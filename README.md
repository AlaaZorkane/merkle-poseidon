# Merkle Poseidon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A WASM-compatible sparse Merkle tree implementation using the Poseidon hash function and Arkworks FF primitives for zero-knowledge applications.

## Features

- **Sparse Implementation**: Only allocates nodes as needed, making it memory-efficient
- **WASM Compatible**: Works in browser environments
- **Arkworks Integration**: Uses `ark-bn254` and `ark-ff` for field operations
- **Poseidon Hash Function**: Optimized for zero-knowledge proofs
- **BN254 Field Elements**: Compatible with widely-used zkSNARK systems
- **Lazy Hash Calculation**: Computes hashes only when needed
- **Memory Efficient**: Uses Rc/RefCell for shared node ownership without deep cloning
- **Visualization**: Optional tree visualization feature
- **Comprehensive Error Handling**: Detailed error types for easier debugging
- **DFS Tree Traversal**: Efficient depth-first search iterators

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
merkle-poseidon = { git = "https://github.com/yourusername/merkle-poseidon2" }
```

To enable the visualization feature:

```toml
[dependencies]
merkle-poseidon = { git = "https://github.com/yourusername/merkle-poseidon2", features = ["visualize"] }
```

## Basic Usage

```rust
use merkle_poseidon::SparseMerkleTree;
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a tree with 10 levels
    let mut tree = SparseMerkleTree::new(10)?;
    
    // Create a path
    let path_bits = vec![true, false, true, false]; // Binary path representation
    let path_bigint = BigInt::from_bits_le(&path_bits);
    let path = Fr::from_bigint(path_bigint).unwrap();
    
    // Create a value
    let value = Fr::from(42u64);
    
    // Insert value at path
    tree.insert_at_path(&path, &value)?;
    
    // Generate Merkle proof
    let proof = tree.generate_proof(&path)?;
    
    // Verify the proof
    let mut hasher = tree.hasher.clone();
    assert!(proof.verify_proof(&mut hasher)?);
    
    // Get value at path
    let retrieved_value = tree.get_value(&path)?;
    assert_eq!(retrieved_value, value);
    
    // Delete value (sets it to zero)
    tree.delete_at_path(&path)?;
    
    Ok(())
}
```

## Working with Paths

Paths in the tree are represented as BN254 field elements (`ark_bn254::Fr`). The bits of the field element's binary representation determine the left/right choices at each tree level:

- `0` bit = go left
- `1` bit = go right

### Creating Paths from Bits

```rust
use merkle_poseidon::SparseMerkleTree;
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};

// Create a path from bits
let bits = vec![true, false, true, true, false]; // 10110 binary
let tree = SparseMerkleTree::new(5).unwrap();
let path = tree.get_merkle_path(&bits).unwrap();

// Or directly from a field element
let path = Fr::from(22u64); // Binary 10110 in decimal
```

## Merkle Proofs

Generate and verify Merkle proofs for data in the tree:

```rust
// Generate a proof for a value
let proof = tree.generate_proof(&path)?;

// Verify a proof
let mut hasher = tree.hasher.clone();
let is_valid = proof.verify_proof(&mut hasher)?;
assert!(is_valid);

// Access proof components
let root_hash = proof.root_hash;
let siblings = proof.siblings;
let value = proof.value;
```

## Tree Visualization

When compiled with the `visualize` feature, you can visualize the tree structure:

```rust
// Enable the feature in Cargo.toml:
// merkle-poseidon = { git = "...", features = ["visualize"] }

use merkle_poseidon::{SparseMerkleTree, Visualizer};

let mut tree = SparseMerkleTree::new(3)?;
tree.insert_at_path(&Fr::from(3u64), &Fr::from(100u64))?;
tree.insert_at_path(&Fr::from(5u64), &Fr::from(200u64))?;

// Print the tree structure
tree.visualize();
```

Output example:
```
Sparse Merkle Tree Visualization (Depth: 3)
=======================================
└── 0 (Root Node: 17480..35312)
    ├── 1 (Inner Node: 11293..43256)
    │   ├── 2 (Leaf Value: 100)
    │   └── 2 (Leaf Value: 0)
    └── 1 (Inner Node: 06721..12904)
        ├── 2 (Leaf Value: 200)
        └── 2 (Leaf Value: 0)
```

## Tree Structure

```
                     [I0]                    Level 0 (Root)
                    /   \
                 [I1]     [I2]               Level 1
                /  \    /   \
              [L1]  [L2] [L3]   [L4]          Level 2 (leaf nodes)

I1 = hash(L1, L2)
I2 = hash(L3, L4)

where L1 = RAW FIELD ELEMENT VALUE, NOT ITS HASHED VALUE
```

## Advanced Usage

### Working with Different Depths

```rust
// Create a tree with custom depth
let tree = SparseMerkleTree::new(20)?; // 20 levels deep

// Or use the default depth (20 levels)
let tree = SparseMerkleTree::default();
```

### Tree Operations

```rust
// Check if tree is empty
let is_empty = tree.is_empty();

// Get root hash
let root_hash = tree.get_root_hash()?;

// Clear the tree (remove all nodes)
tree.clear();

// Access inner nodes
let inner_node = tree.get_inner_node(&path, level)?;
```

### Tree Traversal

```rust
use merkle_poseidon::{SparseMerkleTree, DFSIterator};

let tree = SparseMerkleTree::new(10)?;
// ... populate the tree ...

// Create an iterator
let iterator = DFSIterator::new(tree.root.clone());

// Traverse the tree
for node in iterator {
    match node.borrow().node_type {
        NodeType::Leaf(value) => {
            println!("Found leaf with value: {}", value);
        },
        NodeType::Inner(hash) => {
            println!("Found inner node with hash: {}", hash);
        }
    }
}
```

## Architecture

The crate is organized into several core modules:

- `tree.rs`: Core implementation of the sparse Merkle tree
- `node.rs`: Node types (Inner/Leaf) and hash management
- `proof.rs`: Merkle proof generation and verification
- `hasher.rs`: Poseidon hash function implementation
- `iterator.rs`: Tree traversal with DFS iterators
- `errors.rs`: Custom error types
- `visualizer.rs`: Optional tree visualization
- `constants.rs`: Common constants and empty hash values

## Compile from Source

1. Make sure you have `rust` installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone the repository:

```bash
git clone https://github.com/yourusername/merkle-poseidon2.git
cd merkle-poseidon2
```

3. Compile the project:

```bash
cargo build --release
```

4. (optional) Compile for WebAssembly:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

## Running Tests

```bash
cargo test
```

With visualization feature:

```bash
cargo test --features visualize
```

## Implementation Details

### Sparse Tree Structure

This implementation uses a sparse tree structure, meaning that nodes are only created when needed. This makes it memory-efficient for applications where most paths are empty.

### Hash Computation

Inner node hashes are calculated as:
```
inner_node_hash = poseidon_hash(left_child_hash, right_child_hash)
```

Empty inner nodes use a pre-calculated empty hash value.

### Memory Management

The tree uses `Rc<RefCell<Node>>` for efficient memory sharing and mutability:
- `Rc`: Allows multiple ownership of nodes
- `RefCell`: Provides interior mutability

This approach avoids deep cloning of subtrees when manipulating the tree.

## Common Use Cases

### Zero-Knowledge Proofs

Merkle trees are essential in many zero-knowledge proof systems. This library's use of the Poseidon hash function makes it particularly suitable for zkSNARKs and other ZK systems.

### Compact Inclusion Proofs

Merkle proofs provide a compact way to prove inclusion of data without revealing the entire dataset.

### Data Integrity Verification

Verify that data has not been tampered with by comparing Merkle roots after operations.

## License

This project is licensed under the MIT License - see the LICENSE file for details.