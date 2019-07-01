//! Generators will generate a token to send back to the client
//!
//! It's a trait to implement so you can create your own.
use rand::distributions::Alphanumeric;
use rand::{rngs::ThreadRng, thread_rng, Rng};

pub trait Generator {
    fn generate_token(&mut self) -> String;
}

pub struct RandGenerator(ThreadRng);

impl RandGenerator {
    pub fn new() -> Self {
        Self(thread_rng())
    }
}

impl Generator for RandGenerator {
    fn generate_token(&mut self) -> String {
        std::iter::repeat(())
            .map(|()| self.0.sample(Alphanumeric))
            .take(32)
            .collect()
    }
}
