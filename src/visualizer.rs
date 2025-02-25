use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use light_poseidon::Poseidon;

use crate::{Node, NodeType, SparseMerkleTree};

/// Trait for tree visualization
#[cfg(feature = "visualize")]
pub trait Visualizer {
    /// Visualize the tree structure to the console
    fn visualize(&self);
}

#[cfg(feature = "visualize")]
impl Visualizer for SparseMerkleTree<Poseidon<Fr>> {
    fn visualize(&self) {
        println!("Sparse Merkle Tree Visualization (Depth: {})", self.depth);
        println!("=======================================");

        if self.is_empty() {
            println!("Empty tree");
            return;
        }

        // Recursively visualize from root
        visualize_node(&self.root, self.depth, 0, "".to_string(), true);
    }
}

/// Shorten the Fr to a string like 12314..12314 (first 5 digits and last 5 digits)
#[cfg(feature = "visualize")]
fn short_fr(fr: &Fr) -> String {
    let str = fr.to_string();
    if str.len() > 10 {
        format!("{}..{}", &str[..5], &str[str.len() - 5..])
    } else {
        str
    }
}

#[cfg(feature = "visualize")]
fn visualize_node(
    node: &Rc<RefCell<Node<Poseidon<Fr>>>>,
    depth: usize,
    level: usize,
    prefix: String,
    is_right: bool,
) {
    let node_ref = node.borrow();
    let indent = prefix.clone() + if is_right { "└── " } else { "├── " };
    // If leaf level, instead of empty, we should print the value 0
    let is_leaf_level = level == depth - 1;
    let is_root = level == 0;

    match &node_ref.node_type {
        NodeType::Inner(hash) => {
            if is_root {
                println!("{}{} (Root Node: {})", indent, level, short_fr(hash));
            } else {
                println!("{}{} (Inner Node: {})", indent, level, short_fr(hash));
            }

            // Child prefix
            let child_prefix = prefix + if is_right { "    " } else { "│   " };

            // Visualize left child
            if let Some(left) = &node_ref.left {
                visualize_node(left, depth, level + 1, child_prefix.clone(), false);
            } else if is_leaf_level {
                println!("{}├── {} (Leaf Value: 0)", child_prefix, level + 1);
            } else {
                println!("{}├── {} (Empty)", child_prefix, level + 1);
            }

            // Visualize right child
            if let Some(right) = &node_ref.right {
                visualize_node(right, depth, level + 1, child_prefix, true);
            } else if is_leaf_level {
                println!("{}└── {} (Leaf Value: 0)", child_prefix, level + 1);
            } else {
                println!("{}└── {} (Empty)", child_prefix, level + 1);
            }
        }
        NodeType::Leaf(value) => {
            println!("{}{} (Leaf Value: {})", indent, level, short_fr(value));
        }
    }
}

#[cfg(all(test, feature = "visualize"))]
mod tests {
    use super::*;
    use crate::SparseMerkleTree;

    #[test]
    fn test_visualization() {
        // Create a simple tree for visualization testing
        let mut tree = SparseMerkleTree::new(2).unwrap();

        // Insert a few values
        let path1 = Fr::from(1u64); // Binary 001
        let path2 = Fr::from(6u64); // Binary 110
        let path3 = Fr::from(3u64); // Binary 011

        let value1 = Fr::from(100u64);
        let value2 = Fr::from(200u64);
        let value3 = Fr::from(300u64);

        tree.insert_at_path(&path1, &value1).unwrap();
        tree.insert_at_path(&path2, &value2).unwrap();
        tree.insert_at_path(&path3, &value3).unwrap();

        // Visualize the tree - this is mostly for manual inspection
        // during development with the feature enabled
        tree.visualize();

        // No assertions needed as this is just a visual test
        // The test passes if it compiles and runs without errors
    }
}
