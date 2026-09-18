#![forbid(unsafe_code)]

//! Authenticate by HTTP Digest: a response against the stored `HA1` for the
//! realm and a nonce this node issued.
//!
//! RFC 7616. The node challenges with a realm and a nonce; the client
//! answers with a hash over its password's `HA1`, the nonce, a count, its
//! own nonce, the method and the request target, and the password never
//! travels. The first gate reads the `username` parameter and calls it a
//! `username` claim, with the whole parameter list riding on
//! `Presented::proof` under `digest.response`. This gate reads the list,
//! takes `HA1` for that user, realm and algorithm from the capability's
//! `CredentialStore` — the store `password`, `basic` and `scram` verify
//! against — recomputes the response and compares in constant time, and
//! only then spends the nonce count, so a replayed response is refused as a
//! replay and a wrong one spends nothing.
//!
//! MD5 and SHA-256, each plain or `-sess`, with `qop=auth`. The method is
//! read from the claim's `http.method` evidence, or is the one configured;
//! where the claim carries `http.uri` evidence the response must have hashed
//! that target. `auth-int`, a hashed username and RFC 2069's response
//! without `qop` are refused by name.

pub mod nonce;
pub mod response;

pub use nonce::Nonces;
pub use response::{Algorithm, Response};

use authenticate::store::{CredentialStore, constant_time_eq};
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof name this verifier reads off a `Presented`: the whole Digest
/// parameter list.
pub const PROOF: &str = "digest.response";
/// The evidence name the request's method is read from.
pub const METHOD: &str = "http.method";
/// The evidence name the request's target is read from, where there is one.
pub const URI: &str = "http.uri";

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Verifies a `username` claim with a `digest.response` proof, for one realm.
pub struct DigestAuthenticator {
    store: CredentialStore,
    realm: String,
    method: Option<String>,
    nonces: Nonces,
    clock: Clock,
}

impl DigestAuthenticator {
    /// Verifies responses for `realm` against the `HA1`s `store` keeps.
    #[must_use]
    pub fn new(store: CredentialStore, realm: impl Into<String>) -> Self {
        Self {
            store,
            realm: realm.into(),
            method: None,
            nonces: Nonces::default(),
            clock: Box::new(now),
        }
    }

    /// The method to hash where a claim carries no `http.method` evidence:
    /// a Location that only ever takes `POST` can say so.
    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// How long an issued nonce is good for, in seconds.
    #[must_use]
    pub fn with_nonce_lifetime(mut self, seconds: i64) -> Self {
        self.nonces = Nonces::lasting(seconds);
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The realm this verifies for.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The enrollments this verifies against.
    #[must_use]
    pub fn store(&self) -> &CredentialStore {
        &self.store
    }

    /// Issue a nonce, for a challenge the caller words itself.
    #[must_use]
    pub fn issue_nonce(&self) -> String {
        self.nonces.issue((self.clock)())
    }

    /// A `WWW-Authenticate` value challenging for this realm with a fresh
    /// nonce, `qop="auth"` and `algorithm`.
    #[must_use]
    pub fn challenge(&self, algorithm: Algorithm) -> String {
        let name = match algorithm {
            Algorithm::Md5 => "MD5",
            Algorithm::Md5Sess => "MD5-sess",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha256Sess => "SHA-256-sess",
        };
        format!(
            "Digest realm=\"{}\", qop=\"auth\", algorithm={name}, nonce=\"{}\"",
            self.realm,
            self.issue_nonce()
        )
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `digest`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "digest"
}

fn evidence<'a>(presented: &'a Presented, name: &str) -> Option<&'a str> {
    presented
        .evidence
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

impl Authenticator for DigestAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::digest()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the Digest verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let list = presented.proof(PROOF).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PROOF}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        let response = Response::parse(list)?;
        if response.username != presented.value {
            return Err(AuthenticateError::new(format!(
                "the claim names '{}' and the Digest response names '{}'",
                presented.value, response.username
            )));
        }
        if response.realm != self.realm {
            return Err(AuthenticateError::new(format!(
                "the Digest response is for the realm '{}' and this node challenges for '{}'",
                response.realm, self.realm
            )));
        }
        let method = evidence(presented, METHOD)
            .or(self.method.as_deref())
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "the claim carries no '{METHOD}' evidence and no method is configured"
                ))
            })?;
        if let Some(target) = evidence(presented, URI)
            && target != response.uri
        {
            return Err(AuthenticateError::new(format!(
                "the request is for '{target}' and the Digest response hashed '{}'",
                response.uri
            )));
        }

        let store_name = response.algorithm.store_name();
        let Some(ha1) = self.store.ha1(&response.username, &self.realm, store_name) else {
            return Ok(Verified::Refused);
        };
        let expected = response.expected(ha1, method);
        if !constant_time_eq(expected.as_bytes(), response.response.as_bytes()) {
            return Ok(Verified::Refused);
        }
        self.nonces
            .spend(&response.nonce, response.count, (self.clock)())?;
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::store::SHA_256;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    const REALM: &str = "xmip";

    fn verifier() -> DigestAuthenticator {
        let mut store = CredentialStore::with_iterations(1);
        store.insert_sha256_ha1("alice", REALM, "pencil");
        store.insert_ha1(
            "alice",
            REALM,
            authenticate::store::MD5,
            &Algorithm::Md5.ha1("alice", REALM, "pencil"),
        );
        DigestAuthenticator::new(store, REALM)
    }

    /// The client's half: answer a nonce with a password, as a browser does.
    fn answer(algorithm: &str, nonce: &str, nc: &str, password: &str, method: &str) -> String {
        let hash = Algorithm::named(algorithm).expect("known");
        let blank = format!(
            "username=\"alice\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"/in/orders\", \
             algorithm={algorithm}, qop=auth, nc={nc}, cnonce=\"0a4f113b\""
        );
        let read = Response::parse(&format!("{blank}, response=\"\"")).expect("read");
        let response = read.expected(&hash.ha1("alice", REALM, password), method);
        format!("{blank}, response=\"{response}\"")
    }

    fn claim(list: &str) -> Presented {
        Presented::passed(mechanism::username(), "alice")
            .with_evidence(METHOD, "POST")
            .with_proof(PROOF, list)
    }

    #[test]
    fn a_response_over_an_issued_nonce_proves_the_username_under_either_hash() {
        let verifier = verifier();
        for algorithm in ["SHA-256", "MD5", "SHA-256-sess"] {
            let nonce = verifier.issue_nonce();
            let list = answer(algorithm, &nonce, "00000001", "pencil", "POST");
            assert_eq!(
                verifier.verify(&claim(&list)).expect("verified"),
                Verified::Proven,
                "{algorithm}"
            );
        }
        assert_eq!(verifier.mechanism().name(), "digest");
        assert!(verifier.store().ha1("alice", REALM, SHA_256).is_some());
    }

    #[test]
    fn a_wrong_password_an_unknown_user_and_another_method_are_refused_alike() {
        let verifier = verifier();
        let nonce = verifier.issue_nonce();
        let wrong = answer("SHA-256", &nonce, "00000001", "pen", "POST");
        assert_eq!(
            verifier.verify(&claim(&wrong)).expect("verified"),
            Verified::Refused
        );
        // The response was hashed for GET and the request is a POST.
        let get = answer("SHA-256", &nonce, "00000001", "pencil", "GET");
        assert_eq!(
            verifier.verify(&claim(&get)).expect("verified"),
            Verified::Refused
        );
        let unknown = Presented::passed(mechanism::username(), "mallory")
            .with_evidence(METHOD, "POST")
            .with_proof(PROOF, wrong.replace("alice", "mallory"));
        assert_eq!(
            verifier.verify(&unknown).expect("verified"),
            Verified::Refused
        );
        // A refused response spent nothing: the right one still counts as 1.
        let right = answer("SHA-256", &nonce, "00000001", "pencil", "POST");
        assert_eq!(
            verifier.verify(&claim(&right)).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn a_replayed_response_and_a_stale_nonce_are_refused_saying_so() {
        let time = Arc::new(AtomicI64::new(1_800_000_000));
        let clock = Arc::clone(&time);
        let verifier = verifier()
            .with_nonce_lifetime(60)
            .with_clock(move || clock.load(Ordering::SeqCst));
        let nonce = verifier.issue_nonce();
        let first = answer("SHA-256", &nonce, "00000001", "pencil", "POST");
        assert_eq!(
            verifier.verify(&claim(&first)).expect("verified"),
            Verified::Proven
        );
        let replay = verifier.verify(&claim(&first)).expect_err("replay");
        assert!(replay.message.contains("a replay"), "{}", replay.message);

        time.fetch_add(61, Ordering::SeqCst);
        let late = answer("SHA-256", &nonce, "00000002", "pencil", "POST");
        let stale = verifier.verify(&claim(&late)).expect_err("stale");
        assert!(stale.message.contains("stale"), "{}", stale.message);
    }

    #[test]
    fn a_nonce_this_node_did_not_issue_is_refused() {
        let list = answer("SHA-256", "5ccc069c403ebaf9", "00000001", "pencil", "POST");
        let failure = verifier().verify(&claim(&list)).expect_err("refused");
        assert!(
            failure.message.contains("not one this node issued"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn the_realm_the_target_and_the_claimed_name_must_be_the_responses() {
        let verifier = verifier();
        let nonce = verifier.issue_nonce();
        let list = answer("SHA-256", &nonce, "00000001", "pencil", "POST");

        let elsewhere = claim(&list).with_evidence(URI, "/in/invoices");
        let failure = verifier.verify(&elsewhere).expect_err("refused");
        assert!(
            failure.message.contains("'/in/invoices'"),
            "{}",
            failure.message
        );

        let bob = Presented::passed(mechanism::username(), "bob")
            .with_evidence(METHOD, "POST")
            .with_proof(PROOF, list.as_str());
        let failure = verifier.verify(&bob).expect_err("refused");
        assert!(
            failure.message.contains("names 'bob'"),
            "{}",
            failure.message
        );

        let other = list.replace("realm=\"xmip\"", "realm=\"other\"");
        let failure = verifier.verify(&claim(&other)).expect_err("refused");
        assert!(failure.message.contains("'other'"), "{}", failure.message);

        // Nothing above spent the count; with the right target it proves.
        let here = claim(&list).with_evidence(URI, "/in/orders");
        assert_eq!(verifier.verify(&here).expect("verified"), Verified::Proven);
    }

    #[test]
    fn the_method_comes_from_evidence_or_configuration_and_is_asked_for_by_name() {
        let bare =
            |list: &str| Presented::passed(mechanism::username(), "alice").with_proof(PROOF, list);
        let verifier = verifier();
        let nonce = verifier.issue_nonce();
        let list = answer("MD5", &nonce, "00000001", "pencil", "PUT");
        let failure = verifier.verify(&bare(&list)).expect_err("refused");
        assert!(
            failure.message.contains("'http.method'"),
            "{}",
            failure.message
        );

        let configured = self::verifier().with_method("PUT");
        let nonce = configured.issue_nonce();
        let list = answer("MD5", &nonce, "00000001", "pencil", "PUT");
        assert_eq!(
            configured.verify(&bare(&list)).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn a_missing_proof_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::username(), "alice");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'digest.response' proof"),
            "{}",
            failure.message
        );
        let key = Presented::passed(mechanism::api_key(), "k-1").with_proof("api-key", "s");
        let failure = verifier().verify(&key).expect_err("refused");
        assert!(failure.message.contains("'api-key'"), "{}", failure.message);
    }

    #[test]
    fn a_challenge_names_the_realm_the_hash_and_a_nonce_that_then_verifies() {
        let verifier = verifier();
        let challenge = verifier.challenge(Algorithm::Sha256);
        assert!(challenge.starts_with("Digest realm=\"xmip\", qop=\"auth\", algorithm=SHA-256"));
        let nonce = challenge
            .rsplit_once("nonce=\"")
            .map(|(_, rest)| rest.trim_end_matches('"'))
            .expect("a nonce");
        let list = answer("SHA-256", nonce, "00000001", "pencil", "POST");
        assert_eq!(
            verifier.verify(&claim(&list)).expect("verified"),
            Verified::Proven
        );
        assert_eq!(verifier.realm(), REALM);
    }
}
