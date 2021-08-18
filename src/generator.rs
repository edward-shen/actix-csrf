//! Generators will generate a token to send back to the client
//!
//! It's a trait to implement so you can create your own.

use base64::URL_SAFE_NO_PAD;
use rand::{CryptoRng, Error, Fill, RngCore};

/// Used to generate CSRF tokens.
///
/// This trait is used to generate a token that can be used as a CSRF token. It
/// is implemented for all CSRNG (Cryptographically Secure RNG) types, so in
/// general, you don't need to implement this yourself. In fact, you should
/// avoid implementing this trait unless you're aware of the security
/// implications.
///
/// Implementors of this trait should generate a token that's difficult to
/// guess. For blanket implementations, this is 32 bytes of random data.
pub trait TokenRng: CryptoRng {
    /// Generates a CSRF token.
    fn generate_token(&mut self) -> Result<String, Error>;
}

impl<Rng: CryptoRng + RngCore> TokenRng for Rng {
    fn generate_token(&mut self) -> Result<String, Error> {
        let mut buf = [0; 32];
        buf.try_fill(self)?;
        Ok(base64::encode_config(buf, URL_SAFE_NO_PAD))
    }
}
