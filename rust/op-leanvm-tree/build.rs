//! With `embedded-class-key`, builds the tree class natively and writes its class key to
//! `OUT_DIR/class-key.bin`, for the library to embed. The fault proof program runs from scratch
//! every time; building the class there would cost billions of steps, loading it far fewer.

fn main() {
    println!("cargo:rerun-if-changed=src/class.rs");
    #[cfg(feature = "embedded-class-key")]
    embed::write_class_key();
}

#[cfg(feature = "embedded-class-key")]
#[allow(unreachable_pub, dead_code, reason = "the class's items are the library's public items")]
mod embed {
    include!("src/class.rs");

    pub(super) fn write_class_key() {
        let tree = class_tree().expect("the tree class builds");
        let roots = tree.seal_prover().expect("the class's fixed polynomials commit").roots();
        let key = tree.mixed_verifier_bytes(&roots).expect("a mixed tree's class key");
        assert_eq!(
            Tree::mixed_class_key_digest(&key),
            CLASS_KEY_DIGEST,
            "the class key differs from the pinned CLASS_KEY_DIGEST: leanVM or the class changed"
        );
        let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("set by cargo"))
            .join("class-key.bin");
        std::fs::write(out, key).expect("OUT_DIR is writable");
    }
}
