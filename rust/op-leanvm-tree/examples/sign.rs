//! Signs a 32-byte message with a leanSPHINCS key from a seed and prints the signature as
//! `optimism_sendRawTransactionWithStatementProofs` takes it: a JSON object of the public key, the
//! message, the signature and the member it proves. Acceptance tests use it to authorize a
//! transaction by a STATEMENT actor.
//!
//! ```sh
//! cargo run -p op-leanvm-tree --features sequencer --example sign -- <seed byte> <message hex>
//! ```

use alloy_primitives::{B256, hex};
use op_leanvm_tree::Signed;

fn main() {
    let mut args = std::env::args().skip(1);
    let seed: u8 = args.next().expect("a seed byte").parse().expect("a seed byte");
    let message: B256 = args.next().expect("a message").parse().expect("a 32-byte message");
    let (secret, public) = leansphincs::key_gen([seed; 32]);
    let words: [u64; 4] =
        core::array::from_fn(|i| u64::from_le_bytes(message[i * 8..i * 8 + 8].try_into().unwrap()));
    let signature = secret.sign(&words).expect("the message words are field elements");
    let key: Vec<u8> =
        public.root.iter().chain(&public.public_param).flat_map(|w| w.to_le_bytes()).collect();
    // SAFETY: `Signature` is `repr(C)` words with no padding.
    let signature: Vec<u8> = unsafe { leanvm_guest::as_words_unchecked(&signature) }
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let member = Signed::decode(&key, message, &signature).unwrap().verify().unwrap();
    println!(
        r#"{{"publicKey":"{}","message":"{message}","signature":"{}","member":"{member}"}}"#,
        hex::encode_prefixed(&key),
        hex::encode_prefixed(&signature),
    );
}
