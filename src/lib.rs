mod errors;
mod node;
mod tree;

pub use errors::*;
pub use node::*;
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
