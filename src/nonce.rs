//! The nonces this node issued, and how far each has been counted.
//!
//! A Digest response is only worth what its nonce is worth: the node must
//! have issued it, recently, and the client's nonce count must climb with
//! every request that uses it (RFC 7616 section 3.3, `nc`). A response whose
//! count does not climb is a replay. What is kept per nonce is when it was
//! issued and the highest count spent on it; a nonce past its lifetime is
//! forgotten the next time one is issued.

use authenticate::AuthenticateError;
use authenticate::store::{fresh_salt, hex};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// How long a nonce is good for unless configured otherwise, in seconds.
pub const DEFAULT_LIFETIME: i64 = 300;

/// The nonces a node has issued and not yet forgotten.
#[derive(Debug)]
pub struct Nonces {
    lifetime: i64,
    issued: Mutex<HashMap<String, (i64, u32)>>,
}

impl Default for Nonces {
    fn default() -> Self {
        Self::lasting(DEFAULT_LIFETIME)
    }
}

impl Nonces {
    /// Nonces good for `lifetime` seconds each.
    #[must_use]
    pub fn lasting(lifetime: i64) -> Self {
        Self {
            lifetime,
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// How long a nonce is good for, in seconds.
    #[must_use]
    pub const fn lifetime(&self) -> i64 {
        self.lifetime
    }

    fn book(&self) -> MutexGuard<'_, HashMap<String, (i64, u32)>> {
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issue a nonce at `now`, for the `WWW-Authenticate` challenge, and
    /// forget the ones that have gone stale.
    #[must_use]
    pub fn issue(&self, now: i64) -> String {
        let nonce = hex(&fresh_salt("digest.nonce"));
        let mut book = self.book();
        book.retain(|_, (issued, _)| now.saturating_sub(*issued) < self.lifetime);
        book.insert(nonce.clone(), (now, 0));
        nonce
    }

    /// Spend `count` on `nonce` at `now`: the nonce must be one this node
    /// issued, still fresh, and the count higher than any spent before.
    ///
    /// # Errors
    ///
    /// The nonce is unknown, stale, or the count has been used: a replay.
    pub fn spend(&self, nonce: &str, count: u32, now: i64) -> Result<(), AuthenticateError> {
        let mut book = self.book();
        let Some((issued, spent)) = book.get_mut(nonce) else {
            return Err(AuthenticateError::new(
                "the nonce is not one this node issued, or it has been forgotten",
            ));
        };
        if now.saturating_sub(*issued) >= self.lifetime {
            return Err(AuthenticateError::new(format!(
                "the nonce is stale: it was issued at {issued} and it is {now}"
            )));
        }
        if count <= *spent {
            return Err(AuthenticateError::new(format!(
                "the nonce count {count} has been spent already: a replay"
            )));
        }
        *spent = count;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_climbs_and_never_repeats() {
        let nonces = Nonces::default();
        let nonce = nonces.issue(1000);
        nonces.spend(&nonce, 1, 1001).expect("first");
        nonces.spend(&nonce, 2, 1002).expect("second");
        let replay = nonces.spend(&nonce, 2, 1003).expect_err("replay");
        assert!(replay.message.contains("a replay"), "{}", replay.message);
        assert!(nonces.spend(&nonce, 1, 1003).is_err());
        assert!(nonces.spend(&nonce, 0, 1003).is_err());
        nonces
            .spend(&nonce, 7, 1004)
            .expect("a gap is a lost request, not a replay");
    }

    #[test]
    fn a_nonce_goes_stale_and_is_then_forgotten() {
        let nonces = Nonces::lasting(60);
        assert_eq!(nonces.lifetime(), 60);
        let nonce = nonces.issue(1000);
        let stale = nonces.spend(&nonce, 1, 1060).expect_err("stale");
        assert!(stale.message.contains("stale"), "{}", stale.message);

        let next = nonces.issue(1061);
        assert_ne!(nonce, next);
        let forgotten = nonces.spend(&nonce, 1, 1061).expect_err("forgotten");
        assert!(
            forgotten.message.contains("not one this node issued"),
            "{}",
            forgotten.message
        );
        nonces.spend(&next, 1, 1062).expect("fresh");
    }
}
