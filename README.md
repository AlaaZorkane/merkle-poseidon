# Merkle Poseidon
A sparse merkle tree implementation using Poseidon hash function and arkworks ff primitives.

## Usage

```rust
use merkle_poseidon::SparseMerkleTree;

let tree = SparseMerkleTree::new(16).unwrap();

let path = Fr::from_bigint(BigInt::from_bits_le(&[false, false, false])).unwrap();
let value = Fr::from(100u64);

tree.insert_at_path(&path, &value).unwrap();

let proof = tree.generate_proof(&path).unwrap();

let verified = proof.verify_proof(&mut hasher).unwrap();

assert!(verified);
```

## Structure
- `src/`: Home to our source code
  - `lib.rs`: Program entrypoint and module declarations
  - `tree.rs`: Core implementation of SparseMerkleTree with key operations:
    - Tree creation and management
    - Node insertion and deletion
    - Path operations and proof generation
  - `node.rs`: Node implementation with:
    - Leaf and Inner node types
    - Hash computation and validation
    - Node relationship management (left/right children)
  - `proof.rs`: Merkle proof implementation:
    - Proof structure and verification
    - Bottom-up verification process
  - `iterator.rs`: Tree traversal implementations:
    - DFS iterators (owned and borrowed)
    - Node value and hash collection
  - `hasher.rs`: Poseidon hasher type definitions
  - `errors.rs`: Custom error types for:
    - Tree operations
    - Proof verification
    - Hash computation


### Compile from source

1. Make sure you have `rust` installed, if not run this:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Compile the project

```bash
cargo build --release
```

3. (optional) Compile for wasm

```bash
cargo build --release --target wasm32-unknown-unknown
```

### Running tests

```bash
cargo test
```

