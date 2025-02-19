mod errors;
mod hasher;
mod node;
mod proof;
mod tree;

pub use errors::*;
pub use hasher::*;
pub use node::*;
pub use proof::*;
pub use tree::*;

pub fn hello() -> &'static str {
    "Hello, world!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "Hello, world!");
    }
}
