//! The Digest response: the parameter list a client sends, and the hash the
//! node expects in it.
//!
//! RFC 7616 section 3.4: `username`, `realm`, `nonce`, `uri`, `response`,
//! `algorithm`, `cnonce`, `qop`, `nc`, as a comma-separated list whose
//! values may be quoted, and a quoted value may hold a comma. With
//! `qop=auth` the response is
//! `H(HA1:nonce:nc:cnonce:auth:H(method:uri))`, where `HA1` is
//! `H(username:realm:password)` — or, for a `-sess` algorithm,
//! `H(that:nonce:cnonce)`.

use authenticate::AuthenticateError;
use authenticate::store::{MD5, SHA_256, hex, sha256};

/// The hash a response was computed with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// RFC 2617's, still what most clients send.
    Md5,
    /// MD5 with a session key.
    Md5Sess,
    /// RFC 7616's preferred.
    Sha256,
    /// SHA-256 with a session key.
    Sha256Sess,
}

impl Algorithm {
    /// The algorithm a response names; none named is MD5, as RFC 7616 says.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "" | "MD5" => Some(Self::Md5),
            "MD5-SESS" => Some(Self::Md5Sess),
            "SHA-256" => Some(Self::Sha256),
            "SHA-256-SESS" => Some(Self::Sha256Sess),
            _ => None,
        }
    }

    /// The name the credential store keeps this algorithm's `HA1` under.
    #[must_use]
    pub const fn store_name(self) -> &'static str {
        match self {
            Self::Md5 | Self::Md5Sess => MD5,
            Self::Sha256 | Self::Sha256Sess => SHA_256,
        }
    }

    /// Whether `HA1` is rehashed with the nonce and the client's nonce.
    #[must_use]
    pub const fn session(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }

    /// The hash of `text`, in lower-case hexadecimal.
    #[must_use]
    pub fn hash(self, text: &str) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => format!("{:x}", md5::compute(text.as_bytes())),
            Self::Sha256 | Self::Sha256Sess => hex(&sha256(text.as_bytes())),
        }
    }

    /// `HA1` for a password: `H(username:realm:password)`, what an operator
    /// enrolls in the credential store for this algorithm.
    #[must_use]
    pub fn ha1(self, username: &str, realm: &str, password: &str) -> String {
        self.hash(&format!("{username}:{realm}:{password}"))
    }
}

/// A Digest response with `qop=auth`, read and not yet believed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    /// Who the client says it is.
    pub username: String,
    /// The protection space the client answered for.
    pub realm: String,
    /// The nonce the client answered.
    pub nonce: String,
    /// The request target the client hashed.
    pub uri: String,
    /// The hash the client sent, lower-cased.
    pub response: String,
    /// The hash it was computed with.
    pub algorithm: Algorithm,
    /// The client's own nonce.
    pub cnonce: String,
    /// The nonce count as it was sent: eight hexadecimal digits.
    pub nc: String,
    /// The nonce count as a number.
    pub count: u32,
}

/// Split a parameter list at the commas outside quotes, and each parameter
/// at its first `=`, unquoting and unescaping the value.
fn parameters(list: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in list.chars().chain(std::iter::once(',')) {
        if escaped {
            current.push(character);
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ',' && !quoted {
            if let Some((name, value)) = current.split_once('=') {
                pairs.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
            current.clear();
        } else {
            current.push(character);
        }
    }
    pairs
}

impl Response {
    /// Read the parameter list, with or without the `Digest ` it followed.
    ///
    /// # Errors
    ///
    /// A required parameter is missing, the algorithm is not one the node
    /// verifies, `qop` is not `auth`, the username is hashed, or `nc` is not
    /// hexadecimal.
    pub fn parse(list: &str) -> Result<Self, AuthenticateError> {
        let list = list.trim();
        let list = match list.get(..7) {
            Some(scheme) if scheme.eq_ignore_ascii_case("digest ") => &list[7..],
            _ => list,
        };
        let pairs = parameters(list);
        let find = |name: &str| {
            pairs
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.as_str())
        };
        let required = |name: &str| {
            find(name).map(str::to_string).ok_or_else(|| {
                AuthenticateError::new(format!("the Digest response has no '{name}'"))
            })
        };

        if find("userhash").is_some_and(|value| value.eq_ignore_ascii_case("true")) {
            return Err(AuthenticateError::new(
                "the Digest response hashes its username and this node does not read that",
            ));
        }
        let named = find("algorithm").unwrap_or_default();
        let algorithm = Algorithm::named(named).ok_or_else(|| {
            AuthenticateError::new(format!(
                "the Digest algorithm '{named}' is not one this node verifies"
            ))
        })?;
        match find("qop") {
            Some(qop) if qop.eq_ignore_ascii_case("auth") => {}
            Some(qop) => {
                return Err(AuthenticateError::new(format!(
                    "the Digest qop is '{qop}' and this node verifies 'auth'"
                )));
            }
            None => {
                return Err(AuthenticateError::new(
                    "the Digest response has no 'qop' and this node verifies 'auth'",
                ));
            }
        }
        let nc = required("nc")?;
        let count = u32::from_str_radix(&nc, 16).map_err(|_| {
            AuthenticateError::new(format!("the Digest nonce count '{nc}' is not hexadecimal"))
        })?;

        Ok(Self {
            username: required("username")?,
            realm: required("realm")?,
            nonce: required("nonce")?,
            uri: required("uri")?,
            response: required("response")?.to_ascii_lowercase(),
            algorithm,
            cnonce: required("cnonce")?,
            nc,
            count,
        })
    }

    /// The response a client holding the password behind `ha1` sends for
    /// `method`.
    #[must_use]
    pub fn expected(&self, ha1: &str, method: &str) -> String {
        let algorithm = self.algorithm;
        let ha1 = if algorithm.session() {
            algorithm.hash(&format!("{ha1}:{}:{}", self.nonce, self.cnonce))
        } else {
            ha1.to_string()
        };
        let ha2 = algorithm.hash(&format!("{method}:{}", self.uri));
        algorithm.hash(&format!(
            "{ha1}:{}:{}:{}:auth:{ha2}",
            self.nonce, self.nc, self.cnonce
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7616 section 3.9.1.
    const NONCE: &str = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
    const CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

    fn published(algorithm: &str, response: &str) -> String {
        format!(
            "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", \
             uri=\"/dir/index.html\", algorithm={algorithm}, nonce=\"{NONCE}\", \
             nc=00000001, cnonce=\"{CNONCE}\", qop=auth, response=\"{response}\", \
             opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        )
    }

    #[test]
    fn the_response_is_rfc_7616s_by_its_published_examples() {
        let md5 = "8ca523f5e9506fed4657c9700eebdbec";
        let read = Response::parse(&published("MD5", md5)).expect("read");
        let ha1 = Algorithm::Md5.ha1("Mufasa", "http-auth@example.org", "Circle of Life");
        assert_eq!(read.expected(&ha1, "GET"), md5);

        let sha = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1";
        let read = Response::parse(&published("SHA-256", sha)).expect("read");
        let ha1 = Algorithm::Sha256.ha1("Mufasa", "http-auth@example.org", "Circle of Life");
        assert_eq!(read.expected(&ha1, "GET"), sha);
        assert_ne!(read.expected(&ha1, "POST"), sha);
    }

    #[test]
    fn a_quoted_value_keeps_its_commas_and_its_escaped_quotes() {
        let read = Response::parse(
            r#"username="a\"b", realm="x, y", nonce="n", uri="/q?a=1,2", response="AB",
               qop="auth", nc=0000000a, cnonce="c""#,
        )
        .expect("read");
        assert_eq!(read.username, "a\"b");
        assert_eq!(read.realm, "x, y");
        assert_eq!(read.uri, "/q?a=1,2");
        assert_eq!(read.response, "ab");
        assert_eq!(read.algorithm, Algorithm::Md5);
        assert_eq!(read.count, 10);
    }

    #[test]
    fn what_this_node_does_not_verify_is_refused_by_name() {
        let refused = |list: &str| Response::parse(list).expect_err("refused").message;
        let rest = r#"username="u", realm="r", nonce="n", uri="/", response="0", cnonce="c""#;
        assert!(refused(&format!("{rest}, nc=00000001")).contains("no 'qop'"));
        assert!(refused(&format!("{rest}, nc=00000001, qop=auth-int")).contains("'auth-int'"));
        assert!(refused(&format!("{rest}, qop=auth")).contains("no 'nc'"));
        assert!(refused(&format!("{rest}, qop=auth, nc=xyz")).contains("not hexadecimal"));
        assert!(
            refused(&format!("{rest}, qop=auth, nc=1, algorithm=SHA-512-256"))
                .contains("'SHA-512-256'")
        );
        assert!(refused(&format!("{rest}, qop=auth, nc=1, userhash=true")).contains("hashes"));
        assert!(refused("realm=\"r\", qop=auth, nc=1").contains("no 'username'"));
    }

    #[test]
    fn a_session_algorithm_rehashes_ha1_with_both_nonces() {
        let list = r#"username="u", realm="r", nonce="n", uri="/", response="0",
                      cnonce="c", nc=00000001, qop=auth, algorithm=SHA-256-sess"#;
        let read = Response::parse(list).expect("read");
        let ha1 = Algorithm::Sha256Sess.ha1("u", "r", "p");
        let session = Algorithm::Sha256.hash(&format!("{ha1}:n:c"));
        let ha2 = Algorithm::Sha256.hash("GET:/");
        assert_eq!(
            read.expected(&ha1, "GET"),
            Algorithm::Sha256.hash(&format!("{session}:n:00000001:c:auth:{ha2}"))
        );
        assert_eq!(Algorithm::Sha256Sess.store_name(), SHA_256);
    }
}
