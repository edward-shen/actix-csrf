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
        let mut chars = String::with_capacity(32);
        for _ in 0..32 {
            chars.push(self.sample(Alphanumeric) as char);
        }
        chars
    }
}
