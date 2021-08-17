//! Generators will generate a token to send back to the client
//!
//! It's a trait to implement so you can create your own.
use rand::distributions::Alphanumeric;
use rand::{rngs::ThreadRng, thread_rng, Rng};

pub trait Generator: GeneratorClone {
    fn generate_token(&mut self) -> String;
}

// https://stackoverflow.com/questions/30353462/how-to-clone-a-struct-storing-a-boxed-trait-object/30353928#30353928
pub trait GeneratorClone {
    fn clone_box(&self) -> Box<Generator>;
}

impl<T> GeneratorClone for T
where
    T: 'static + Generator + Clone,
{
    fn clone_box(&self) -> Box<Generator> {
        Box::new(self.clone())
    }
}

impl Clone for Box<Generator> {
    fn clone(&self) -> Box<Generator> {
        self.clone_box()
    }
}

#[derive(Clone)]
pub struct RandGenerator(ThreadRng);

impl RandGenerator {
    pub fn new() -> Self {
        Self(thread_rng())
    }
}

impl Generator for RandGenerator {
    fn generate_token(&mut self) -> String {
        todo!()
        // std::iter::repeat(())
        //     .map(|()| self.0.sample(Alphanumeric))
        //     .take(32)
        //     .collect()
    }
}
