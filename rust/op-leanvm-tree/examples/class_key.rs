//! Writes the class key to the given path, checking it against the pinned digest: what op-node and
//! op-supernode embed to verify proof aggregates (`op-core/types/leanvm_class_key.bin`, which
//! `just leanvm-class-key` writes). Building the class takes a fraction of a second natively; the
//! key is about 1 KB.
//!
//! ```sh
//! cargo run --release -p op-leanvm-tree --example class_key -- <path>
//! ```

use leanvm::aggregate::Tree;
use op_leanvm_tree::{CLASS_KEY_DIGEST, class_tree};

fn main() {
    let path = std::env::args().nth(1).expect("usage: class_key <path>");
    let tree = class_tree().expect("the tree class builds");
    let roots = tree.seal_prover().expect("the class's fixed polynomials commit").roots();
    let key = tree.mixed_verifier_bytes(&roots).expect("a mixed tree's class key");
    assert_eq!(
        Tree::mixed_class_key_digest(&key),
        CLASS_KEY_DIGEST,
        "the class key differs from the pinned CLASS_KEY_DIGEST: leanVM or the class changed"
    );
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir).expect("the key's directory is creatable");
    }
    // Replace the key atomically: a reader never sees a partial one.
    let partial = format!("{path}.{}.tmp", std::process::id());
    std::fs::write(&partial, key).expect("the key's directory is writable");
    std::fs::rename(&partial, &path).expect("the key replaces its path");
}
