//! Token generators and related crypto functions.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{CryptoRng, Error, Fill, RngCore};

/// Used to generate CSRF tokens.
///
/// This trait is used to generate a token that can be used as a CSRF token. It
/// is implemented for all CSRNG (Cryptographically Secure RNG) types. This
/// should not be implemented directly; instead, implement [`CryptoRng`] and
/// [`RngCore`] instead.
///
/// Implementors of this trait should generate a token that's difficult to
/// guess and is safe to store as a cookie. For blanket implementations, this
/// is 32 bytes of random data, encoded as base64 without padding.
pub trait TokenRng: CryptoRng {
    /// Generates a CSRF token.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying RNG fails to generate a token.
    fn generate_token(&mut self) -> Result<String, Error>;
}

impl<Rng: CryptoRng + RngCore> TokenRng for Rng {
    fn generate_token(&mut self) -> Result<String, Error> {
        let mut buf = [0; 32];
        buf.try_fill(self)?;
        Ok(URL_SAFE_NO_PAD.encode(buf))
    }
}
