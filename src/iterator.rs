use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use light_poseidon::PoseidonHasher;

use crate::{Node, NodeType, SparseMerkleTree};

// Owned iterator struct
#[derive(Debug, Clone)]
pub struct SparseTreeIterator<H: PoseidonHasher<Fr>> {
    // Stack for DFS traversal
    stack: Vec<Rc<RefCell<Node<H>>>>,
    _phantom: std::marker::PhantomData<H>,
}

// Borrowed iterator struct
#[derive(Debug, Clone)]
pub struct SparseTreeRefIterator<H: PoseidonHasher<Fr>> {
    stack: Vec<Rc<RefCell<Node<H>>>>,
    _phantom: std::marker::PhantomData<H>,
}

/// DFS Iterator implementation for borrowed tree
impl<H: PoseidonHasher<Fr>> Iterator for SparseTreeRefIterator<H> {
    type Item = Fr;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            let node_ref = node.borrow();
            if let NodeType::Leaf(value) = node_ref.node_type {
                return Some(value);
            }

            if let Some(right) = node_ref.right.as_ref() {
                self.stack.push(right.clone());
            }
            if let Some(left) = node_ref.left.as_ref() {
                self.stack.push(left.clone());
            }
        }
        None
    }
}

/// DFS Iterator implementation for owned tree
impl<H: PoseidonHasher<Fr>> Iterator for SparseTreeIterator<H> {
    type Item = Fr;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            let node_ref = node.borrow();
            if let NodeType::Leaf(value) = node_ref.node_type {
                return Some(value);
            }

            if let Some(right) = node_ref.right.as_ref() {
                self.stack.push(right.clone());
            }
            if let Some(left) = node_ref.left.as_ref() {
                self.stack.push(left.clone());
            }
        }
        None
    }
}

// owned iteration implementation
impl<H: PoseidonHasher<Fr>> IntoIterator for SparseMerkleTree<H> {
    type Item = Fr;
    type IntoIter = SparseTreeIterator<H>;

    fn into_iter(self) -> Self::IntoIter {
        SparseTreeIterator {
            stack: vec![self.root.clone()],
            _phantom: std::marker::PhantomData,
        }
    }
}

// reference-based iteration implementation
impl<H: PoseidonHasher<Fr>> SparseMerkleTree<H> {
    pub fn iter(&self) -> SparseTreeRefIterator<H> {
        SparseTreeRefIterator {
            stack: vec![self.root.clone()],
            _phantom: std::marker::PhantomData,
        }
    }
}
