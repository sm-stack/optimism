//! Prints what the class pins: the class key's digest (`CLASS_KEY_DIGEST`) and its size, and the
//! signature-member guest's verifying key digest. Run after changing the class or leanVM:
//!
//! ```sh
//! cargo run --release -p op-leanvm-tree --example pins
//! ```

use leanvm::aggregate::Tree;
use op_leanvm_tree::{class_tree, signature_program_digest};

fn main() {
    let tree = class_tree().expect("the tree class builds");
    let roots = tree.seal_prover().expect("the class's fixed polynomials commit").roots();
    let key = tree.mixed_verifier_bytes(&roots).expect("a mixed tree's class key");
    let digest = Tree::mixed_class_key_digest(&key);
    println!("class key: {} bytes", key.len());
    println!(
        "CLASS_KEY_DIGEST: 0x{}",
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("signature program digest: {}", signature_program_digest());
}
