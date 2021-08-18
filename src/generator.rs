//! Generators will generate a token to send back to the client
//!
//! It's a trait to implement so you can create your own.
use rand::distributions::Alphanumeric;
use rand::{CryptoRng, Rng, RngCore};

pub trait TokenRng {
    fn generate_token(&mut self) -> String;
}

impl<Rng: CryptoRng + RngCore> TokenRng for Rng {
    fn generate_token(&mut self) -> String {
        let chars = (0..32).map(|_| self.sample(Alphanumeric)).collect();
        // SAFETY: self.sample(Alphanumeric) will return valid ASCII, so the vec
        // will always be valid UTF-8.
        unsafe { String::from_utf8_unchecked(chars) }
    }
}
