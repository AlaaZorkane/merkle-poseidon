use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::{get_empty_inner_hash, PoseidonMerkleError, SparseMerkleTree, Visualizer};

const DEPTH: usize = 2;
const TEST_PATH: [bool; DEPTH] = [true, false];

/// Setup a new tree with a depth of 2 (for testing purposes)
fn setup_tree() -> SparseMerkleTree<Poseidon<Fr>> {
    SparseMerkleTree::new(DEPTH).unwrap()
}

#[test]
fn test_hasher() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let computed_hash = hasher.hash(&[Fr::ZERO, Fr::from(200u64)]).unwrap();
    println!("computed_hash: {:?}", computed_hash);
}

#[test]
fn test_new_tree() {
    let tree = setup_tree();
    assert_eq!(tree.depth, 2);
    assert!(tree.is_empty());
}

#[test]
fn test_invalid_depth() {
    let result = SparseMerkleTree::new(0);
    assert!(matches!(result, Err(PoseidonMerkleError::InvalidDepth)));
}

#[test]
fn test_insert_and_get() {
    let mut tree = setup_tree();
    let merkle_path = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
    let value = Fr::from(123u64);

    // Insert value
    tree.insert_at_path(&merkle_path, &value).unwrap();

    // Get and verify value
    let retrieved_value = tree.get_value(&merkle_path).unwrap();
    assert_eq!(retrieved_value, value);
    assert!(!tree.is_empty());
}

#[test]
fn test_insert_hash() {
    let mut tree = setup_tree();
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let merkle_path = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
    let value = Fr::from(100u64);

    // Insert value
    tree.insert_at_path(&merkle_path, &value).unwrap();

    let parent = tree.get_inner_node(&merkle_path, 1).unwrap();
    let parent_ref = parent.borrow();
    let parent_hash = parent_ref.node_type.hash().unwrap();

    let computed_hash = hasher.hash(&[value, Fr::ZERO]).unwrap();
    assert_eq!(*parent_hash, computed_hash);
}

#[test]
fn test_delete() {
    let mut tree = setup_tree();
    let merkle_path = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
    let value = Fr::from(123u64);

    // Insert and then delete
    tree.insert_at_path(&merkle_path, &value).unwrap();
    tree.delete_at_path(&merkle_path).unwrap();

    // Verify value is zero
    let retrieved_value = tree.get_value(&merkle_path).unwrap();
    assert_eq!(retrieved_value, Fr::ZERO);
}

#[test]
fn test_clear() {
    let mut tree = setup_tree();
    let merkle_path = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
    let value = Fr::from(123u64);

    tree.insert_at_path(&merkle_path, &value).unwrap();
    tree.clear();
    assert!(tree.is_empty());
}

#[test]
fn test_path_bit_extraction() {
    let bi = BigInt::from_bits_le(&TEST_PATH);
    let merkle_path = Fr::from_bigint(bi).unwrap();

    assert!(SparseMerkleTree::get_path_bit(&merkle_path, 0)); // Should be 1
    assert!(!SparseMerkleTree::get_path_bit(&merkle_path, 1)); // Should be 0
}

#[test]
fn test_get_merkle_path() {
    let tree = setup_tree();
    let path = TEST_PATH;
    let merkle_path = tree.get_merkle_path(&path).unwrap();

    // Verify bits can be extracted back
    assert_eq!(SparseMerkleTree::get_path_bit(&merkle_path, 0), path[0]);
    assert_eq!(SparseMerkleTree::get_path_bit(&merkle_path, 1), path[1]);
}

#[test]
fn test_proof_generation_and_verification() {
    let mut tree = setup_tree();
    let merkle_path = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
    let value = Fr::from(100u64);

    // Insert a value
    tree.insert_at_path(&merkle_path, &value).unwrap();

    tree.visualize();

    // Generate proof
    let proof = tree.generate_proof(&merkle_path).unwrap();

    // Verify proof matches inserted data
    assert_eq!(proof.merkle_path, merkle_path);
    assert_eq!(proof.leaf_value, value);

    // Verify siblings are correct
    assert_eq!(proof.siblings[0], *get_empty_inner_hash());
    assert_eq!(proof.siblings[1], Fr::ZERO);

    // Verify proof cryptographically
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

    // Debug info
    println!("Root hash: {:?}", proof.root_hash);
    println!(
        "Merkle path: {:?}",
        proof.merkle_path.into_bigint().to_bytes_le()
    );
    println!("Leaf value: {:?}", proof.leaf_value);
    println!("Siblings: {:?}", proof.siblings);

    let verification_result = proof.verify_proof(&mut hasher);
    println!("Verification result: {:?}", verification_result);

    assert!(verification_result.unwrap());
}

#[test]
fn test_iterator() {
    let mut tree = setup_tree();

    // Insert some values
    let entries = [
        (
            Fr::from_bigint(BigInt::from_bits_le(&[false, false])).unwrap(),
            Fr::from(100u64),
        ),
        (
            Fr::from_bigint(BigInt::from_bits_le(&[false, true])).unwrap(),
            Fr::from(200u64),
        ),
    ];

    for (path, value) in entries.iter() {
        tree.insert_at_path(path, value).unwrap();
    }

    // Collect all entries from iterator
    let tree_iter = tree.iter();
    let found_entries: Vec<Fr> = tree_iter.collect();

    // Verify all inserted entries are found in DFS order
    for (i, value) in found_entries.iter().enumerate() {
        assert_eq!(value, &entries[i].1);
    }
}

#[test]
fn test_default() {
    let tree = SparseMerkleTree::default();
    assert_eq!(tree.depth, 20);
    assert!(tree.is_empty());
}
