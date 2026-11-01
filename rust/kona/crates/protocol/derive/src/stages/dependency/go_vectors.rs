//! Writes the vectors that pin Go derivation's reading of dependent EIP-8430 transactions and proof
//! aggregates to this crate's (`op-core/types/testdata/dependency_vectors.json`).
//!
//! The gate and the scanner decode batcher-supplied bytes, so a byte string one client
//! reads differently from the other splits derivation. The vectors are well-formed EIP-8430
//! transactions and proof aggregate payloads
//! and structural variants of them (field widths, non-canonical encodings, missing and extra
//! fields, trailing bytes, truncations and byte flips), each with what the functions the gate and
//! the scanner call make of it. Regenerate with:
//!
//! ```sh
//! cargo test -p kona-derive --lib -- --ignored write_go_dependency_vectors
//! ```

// The crate is `no_std` without the `metrics` feature; writing the file needs `std`.
#[allow(unused_extern_crates)]
extern crate std;

use super::gate::dependent_txs;
use alloc::{string::ToString, vec, vec::Vec};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Bytes, hex};
use alloy_rlp::Header;
use kona_protocol::SingleBatch;
use op_alloy_consensus::{
    LEANVM_TREE_CLASS_KEY_DIGEST, LeanVmTreeProof, MAX_PROOF_AGGREGATE_PROOF_BYTES,
    MAX_PROOF_AGGREGATE_STATEMENTS, PROOF_AGGREGATE_PAYLOAD_VERSION, PROOF_STATEMENT_SCHEME,
    ProofAggregatePayload, ProofStatement, TxEip8430, keystore,
};
use serde_json::{Value, json};

/// An RLP item, or bytes written as they are.
#[derive(Clone, Debug)]
enum Item {
    Str(Vec<u8>),
    List(Vec<Self>),
    Raw(Vec<u8>),
}

impl Item {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Str(bytes) if bytes.len() == 1 && bytes[0] < 0x80 => out.push(bytes[0]),
            Self::Str(bytes) => {
                Header { list: false, payload_length: bytes.len() }.encode(out);
                out.extend_from_slice(bytes);
            }
            Self::List(items) => {
                let mut body = Vec::new();
                for item in items {
                    item.encode(&mut body);
                }
                Header { list: true, payload_length: body.len() }.encode(out);
                out.extend_from_slice(&body);
            }
            Self::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }

    fn list_mut(&mut self) -> &mut Vec<Self> {
        match self {
            Self::List(items) => items,
            _ => panic!("not a list"),
        }
    }

    /// The item at `path`, list indices from the root.
    fn at(&mut self, path: &[usize]) -> &mut Self {
        path.iter().fold(self, |item, &i| &mut item.list_mut()[i])
    }
}

fn uint(x: u128) -> Item {
    let bytes = x.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    Item::Str(bytes[first..].to_vec())
}

fn typed(ty: u8, item: &Item) -> Vec<u8> {
    let mut out = vec![ty];
    item.encode(&mut out);
    out
}

/// Deterministic test randomness (xorshift64*).
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Truncations, byte flips and trailing bytes of each encoding.
fn mangle(encodings: &[(&str, Vec<u8>)], rng: &mut Rng) -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    for (_, encoding) in encodings {
        for tail in [&[0x00][..], &[0xc0], &[0x80, 0x80]] {
            out.push(("trailing bytes", [encoding.as_slice(), tail].concat()));
        }
        for _ in 0..4 {
            out.push((
                "truncated",
                encoding[..1 + rng.next() as usize % (encoding.len() - 1)].to_vec(),
            ));
        }
        for _ in 0..12 {
            let mut flipped = encoding.clone();
            let at = 1 + rng.next() as usize % (encoding.len() - 1);
            flipped[at] ^= 1 << (rng.next() % 8);
            out.push(("a flipped bit", flipped));
        }
    }
    out
}

/// Field indices of the encodings, so that variant paths name the field they replace.
mod field {
    // A proof aggregate payload.
    pub(super) const VERSION: usize = 0;
    pub(super) const THROUGH: usize = 1;
    pub(super) const VKEY: usize = 2;
    pub(super) const STATEMENTS: usize = 3;
    pub(super) const PROOF: usize = 4;
}

/// A well-formed encoding with the field at `path` replaced.
struct Variant {
    what: &'static str,
    base: usize,
    path: &'static [usize],
    replacement: Item,
}

impl Variant {
    const fn new(
        what: &'static str,
        base: usize,
        path: &'static [usize],
        replacement: Item,
    ) -> Self {
        Self { what, base, path, replacement }
    }

    fn apply(self, bases: &[Item]) -> Item {
        let mut item = bases[self.base].clone();
        *item.at(self.path) = self.replacement;
        item
    }
}

/// Field indices of an EIP-8430 transaction and its parts.
mod aa_field {
    pub(super) const CHAIN_ID: usize = 0;
    pub(super) const SENDER: usize = 1;
    pub(super) const NONCE_KEY: usize = 2;
    pub(super) const NONCE: usize = 3;
    pub(super) const MAX_FEE: usize = 7;
    pub(super) const ACCOUNT_CHANGES: usize = 9;
    pub(super) const CALLS: usize = 10;
    pub(super) const PAYER: usize = 12;
    // A call.
    pub(super) const TO: usize = 0;
    pub(super) const VALUE: usize = 1;
    // An account change: its type, then its target or its dependency list.
    pub(super) const TYPE: usize = 0;
    pub(super) const BODY: usize = 1;
    // A dependency.
    pub(super) const SCHEME: usize = 0;
    pub(super) const DATA_HASH: usize = 1;
}

fn dependency(scheme: u8, data_hash: B256, vkey: B256) -> Item {
    Item::List(vec![uint(scheme.into()), Item::Str(data_hash.to_vec()), Item::Str(vkey.to_vec())])
}

fn dependencies_entry(dependencies: Vec<Item>) -> Item {
    Item::List(vec![uint(0x04), Item::List(dependencies)])
}

fn aa_call(to: u8, value: u128, data: &[u8]) -> Item {
    Item::List(vec![Item::Str(vec![to; 20]), uint(value), Item::Str(data.to_vec())])
}

fn aa_tx(
    sender: &[u8],
    changes: Vec<Item>,
    calls: Vec<Item>,
    payer: &[u8],
    payer_auth: &[u8],
) -> Item {
    let sender_auth =
        if sender.is_empty() { vec![0x5e; 65] } else { [&[0; 19][..], &[1], &[0x5e; 65]].concat() };
    aa_tx_authorized(sender, &sender_auth, changes, calls, payer, payer_auth)
}

fn aa_tx_authorized(
    sender: &[u8],
    sender_auth: &[u8],
    changes: Vec<Item>,
    calls: Vec<Item>,
    payer: &[u8],
    payer_auth: &[u8],
) -> Item {
    let sender_auth = sender_auth.to_vec();
    Item::List(vec![
        uint(10),
        Item::Str(sender.to_vec()),
        uint(0),
        uint(7),
        uint(0),
        uint(0),
        uint(1),
        uint(10),
        uint(500_000),
        Item::List(changes),
        Item::List(calls),
        Item::Str(vec![]),
        Item::Str(payer.to_vec()),
        Item::Str(sender_auth),
        Item::Str(payer_auth.to_vec()),
    ])
}

fn aa_vectors(rng: &mut Rng) -> Vec<Value> {
    let a = B256::repeat_byte(0xa1);
    let b = B256::repeat_byte(0xb2);
    let vk = B256::repeat_byte(0x77);
    let two = || {
        dependencies_entry(vec![
            dependency(PROOF_STATEMENT_SCHEME, a, vk),
            dependency(PROOF_STATEMENT_SCHEME, b, vk),
        ])
    };
    let one_call = || vec![Item::List(vec![aa_call(0x42, 0, &[])])];
    let named_auth = [&[0; 19][..], &[1], &[0xee; 65]].concat();
    // STATEMENT authorizations: the authenticator, a verifying key, a tag and a key.
    let statement = |key: u8| {
        [keystore::STATEMENT_AUTHENTICATOR.as_slice(), &[0x77; 32], b"sphmem01", &[key; 32]]
            .concat()
    };
    let mut bases = vec![
        // Two proof statements, self-paid, the sender recovered.
        aa_tx(&[], vec![two()], one_call(), &[], &[]),
        // A delegation, then a zero data hash, a duplicate and another scheme; a named sender, an
        // open payer and two phases.
        aa_tx(
            &[0x5e; 20],
            vec![
                Item::List(vec![uint(0x01), Item::Str(vec![0xde; 20])]),
                dependencies_entry(vec![
                    dependency(PROOF_STATEMENT_SCHEME, B256::ZERO, vk),
                    dependency(PROOF_STATEMENT_SCHEME, a, vk),
                    dependency(PROOF_STATEMENT_SCHEME, a, vk),
                    dependency(0x10, b, vk),
                ]),
            ],
            vec![
                Item::List(vec![aa_call(0x42, 5, &[1, 2])]),
                Item::List(vec![aa_call(0x43, 0, &[]), aa_call(0x44, 0, &[3])]),
            ],
            &[0],
            &[0xee; 65],
        ),
        // No account change.
        aa_tx(&[], vec![], one_call(), &[], &[]),
        // An empty dependency entry declares nothing.
        aa_tx(&[], vec![dependencies_entry(vec![])], one_call(), &[], &[]),
        // Two dependency entries: only the first counts; a named payer.
        aa_tx(
            &[],
            vec![
                dependencies_entry(vec![dependency(PROOF_STATEMENT_SCHEME, a, vk)]),
                dependencies_entry(vec![dependency(PROOF_STATEMENT_SCHEME, b, vk)]),
            ],
            one_call(),
            &[0x55; 20],
            &named_auth,
        ),
    ];
    bases.extend([
        // A STATEMENT sender: its statement over the sender hash is the only dependency.
        aa_tx_authorized(&[0x5e; 20], &statement(0x4b), vec![], one_call(), &[], &[]),
        // A STATEMENT sender and a STATEMENT named payer, besides a declared dependency.
        aa_tx_authorized(
            &[0x5e; 20],
            &statement(0x4b),
            vec![dependencies_entry(vec![dependency(PROOF_STATEMENT_SCHEME, a, vk)])],
            one_call(),
            &[0x55; 20],
            &statement(0x4c),
        ),
        // A STATEMENT payer of a recovered sender, and a STATEMENT-shaped blob of a recovered
        // sender: neither adds a dependency.
        aa_tx(&[], vec![], one_call(), &[0x55; 20], &statement(0x4c)),
        aa_tx_authorized(&[], &statement(0x4b), vec![], one_call(), &[], &[]),
        // A STATEMENT sender beside a declared zero data hash: two dependencies over the same
        // sender hash, the declared one and the statement. (A declared dependency cannot equal the
        // statement: the sender hash covers the declaration.)
        aa_tx_authorized(
            &[0x5e; 20],
            &statement(0x4b),
            vec![dependencies_entry(vec![dependency(PROOF_STATEMENT_SCHEME, B256::ZERO, vk)])],
            one_call(),
            &[],
            &[],
        ),
        // STATEMENT-prefixed blobs one byte short and long, and a STATEMENT blob of a self-paid
        // transaction's payer.
        aa_tx_authorized(&[0x5e; 20], &statement(0x4b)[..91], vec![], one_call(), &[], &[]),
        aa_tx_authorized(
            &[0x5e; 20],
            &[&statement(0x4b)[..], &[0]].concat(),
            vec![],
            one_call(),
            &[],
            &[],
        ),
        aa_tx_authorized(&[0x5e; 20], &statement(0x4b), vec![], one_call(), &[], &statement(0x4c)),
        // A STATEMENT-length blob of another authenticator, and a statement of an open payer.
        aa_tx_authorized(
            &[0x5e; 20],
            &[&[0; 19][..], &[1], &[0x5e; 72]].concat(),
            vec![],
            one_call(),
            &[0],
            &statement(0x4c),
        ),
    ]);

    let mut encodings: Vec<(&str, Vec<u8>)> =
        bases.iter().map(|base| ("well-formed", typed(0x79, base))).collect();
    encodings.push(("another transaction type", typed(0x02, &bases[0])));

    use aa_field::*;
    let deps0 = || -> Vec<Item> {
        vec![dependency(PROOF_STATEMENT_SCHEME, a, vk), dependency(PROOF_STATEMENT_SCHEME, b, vk)]
    };
    let variants = [
        Variant::new("32-byte nonce key", 0, &[NONCE_KEY], Item::Str(vec![0xff; 32])),
        Variant::new("33-byte nonce key", 0, &[NONCE_KEY], Item::Str(vec![0x01; 33])),
        Variant::new("nonce key with a leading zero", 0, &[NONCE_KEY], Item::Str(vec![0, 1])),
        Variant::new("16-byte fee", 0, &[MAX_FEE], Item::Str(vec![0xff; 16])),
        Variant::new("17-byte fee", 0, &[MAX_FEE], Item::Str(vec![0x01; 17])),
        Variant::new("fee encoded as 0x00", 0, &[MAX_FEE], Item::Str(vec![0])),
        Variant::new("8-byte chain id", 0, &[CHAIN_ID], Item::Str(vec![0x01; 8])),
        Variant::new("9-byte chain id", 0, &[CHAIN_ID], Item::Str(vec![0x01; 9])),
        Variant::new("nonce encoded as 0x00", 0, &[NONCE], Item::Str(vec![0])),
        Variant::new("19-byte sender", 0, &[SENDER], Item::Str(vec![0x5e; 19])),
        Variant::new("21-byte sender", 0, &[SENDER], Item::Str(vec![0x5e; 21])),
        Variant::new("sender as a list", 0, &[SENDER], Item::List(vec![])),
        Variant::new("one-byte payer 0x01", 0, &[PAYER], Item::Str(vec![1])),
        Variant::new("two-byte payer", 0, &[PAYER], Item::Str(vec![0, 0])),
        Variant::new("21-byte payer", 0, &[PAYER], Item::Str(vec![0x55; 21])),
        Variant::new("payer as a list", 0, &[PAYER], Item::List(vec![])),
        Variant::new("32-byte call value", 0, &[CALLS, 0, 0, VALUE], Item::Str(vec![0xff; 32])),
        Variant::new("33-byte call value", 0, &[CALLS, 0, 0, VALUE], Item::Str(vec![0x01; 33])),
        Variant::new(
            "call value with a leading zero",
            0,
            &[CALLS, 0, 0, VALUE],
            Item::Str(vec![0, 1]),
        ),
        Variant::new("19-byte callee", 0, &[CALLS, 0, 0, TO], Item::Str(vec![0x42; 19])),
        Variant::new(
            "call with four fields",
            0,
            &[CALLS, 0, 0],
            Item::List(vec![Item::Str(vec![0x42; 20]), uint(0), Item::Str(vec![]), uint(0)]),
        ),
        Variant::new(
            "call with two fields",
            0,
            &[CALLS, 0, 0],
            Item::List(vec![Item::Str(vec![0x42; 20]), uint(0)]),
        ),
        Variant::new("a phase as a string", 0, &[CALLS, 0], Item::Str(vec![1])),
        Variant::new("account changes as a string", 0, &[ACCOUNT_CHANGES], Item::Str(vec![1])),
        Variant::new("an unknown account change type", 0, &[ACCOUNT_CHANGES, 0, TYPE], uint(0x02)),
        Variant::new(
            "account change type as a list",
            0,
            &[ACCOUNT_CHANGES, 0, TYPE],
            Item::List(vec![]),
        ),
        Variant::new(
            "account change type as a non-canonical single byte",
            0,
            &[ACCOUNT_CHANGES, 0, TYPE],
            Item::Raw(vec![0x81, 0x04]),
        ),
        Variant::new(
            "dependency list as a string",
            0,
            &[ACCOUNT_CHANGES, 0, BODY],
            Item::Str(vec![1, 2]),
        ),
        Variant::new(
            "scheme as a non-canonical single byte",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0, SCHEME],
            Item::Raw(vec![0x81, 0x20]),
        ),
        Variant::new(
            "scheme encoded as 0x00",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0, SCHEME],
            Item::Str(vec![0]),
        ),
        Variant::new(
            "two-byte scheme",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0, SCHEME],
            Item::Str(vec![0x01, 0x20]),
        ),
        Variant::new(
            "31-byte data hash",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0, DATA_HASH],
            Item::Str(vec![0xa1; 31]),
        ),
        Variant::new(
            "dependency with two fields",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0],
            Item::List(vec![uint(PROOF_STATEMENT_SCHEME.into()), Item::Str(a.to_vec())]),
        ),
        Variant::new(
            "dependency with four fields",
            0,
            &[ACCOUNT_CHANGES, 0, BODY, 0],
            Item::List(vec![
                uint(PROOF_STATEMENT_SCHEME.into()),
                Item::Str(a.to_vec()),
                Item::Str(vk.to_vec()),
                uint(0),
            ]),
        ),
        Variant::new(
            "dependency entry with an extra field",
            0,
            &[ACCOUNT_CHANGES, 0],
            Item::List(vec![uint(0x04), Item::List(deps0()), uint(0)]),
        ),
        Variant::new(
            "delegation with an extra field",
            1,
            &[ACCOUNT_CHANGES, 0],
            Item::List(vec![uint(0x01), Item::Str(vec![0xde; 20]), uint(0)]),
        ),
        Variant::new(
            "delegation to 19 bytes",
            1,
            &[ACCOUNT_CHANGES, 0, BODY],
            Item::Str(vec![0xde; 19]),
        ),
    ];
    for variant in variants {
        encodings.push((variant.what, typed(0x79, &variant.apply(&bases))));
    }
    // A short entry must be an error, not the end of `account_changes` with the transaction's later
    // fields read from inside it.
    for (what, short) in [
        ("a short entry ending account changes", vec![0xc0]),
        ("a delegation without target ending account changes", vec![0xc1, 0x01]),
        ("a dependency entry without list ending account changes", vec![0xc1, 0x04]),
    ] {
        let mut tx = bases[0].clone();
        let tail: Vec<Item> = tx.list_mut().drain(CALLS..).collect();
        let changes = tx.at(&[ACCOUNT_CHANGES]).list_mut();
        changes.push(Item::Raw(short));
        changes.extend(tail);
        encodings.push((what, typed(0x79, &tx)));
    }
    let mut extra = bases[0].clone();
    extra.list_mut().push(uint(0));
    encodings.push(("an extra field", typed(0x79, &extra)));
    let mut missing = bases[0].clone();
    missing.list_mut().pop();
    encodings.push(("a missing field", typed(0x79, &missing)));
    let canonical = typed(0x79, &bases[2]);
    let mut body = &canonical[1..];
    let header = Header::decode(&mut body).unwrap();
    assert!(header.payload_length < 256);
    encodings.push((
        "list length with a leading zero",
        [&[0x79, 0xf9, 0x00, header.payload_length as u8][..], body].concat(),
    ));
    encodings.push(("type byte only", vec![0x79]));

    let mangled = mangle(&encodings[..bases.len()], rng);
    encodings.extend(mangled);

    encodings
        .into_iter()
        .map(|(what, raw)| {
            let tx = Bytes::from(raw);
            let decoded = TxEip8430::decode_2718(&mut tx.as_ref()).ok();
            let batch = SingleBatch { transactions: vec![tx.clone()], ..Default::default() };
            let dependent = !dependent_txs(&batch).is_empty();
            let deps = decoded.as_ref().map(|aa| {
                aa.dependencies()
                    .iter()
                    .map(|d| {
                        json!([
                            d.scheme,
                            d.data_hash.to_string(),
                            d.verification_key_hash.to_string()
                        ])
                    })
                    .collect::<Vec<_>>()
            });
            json!({
                "what": what,
                "tx": hex::encode_prefixed(&tx),
                "decodes": decoded.is_some(),
                "count": decoded
                    .as_ref()
                    .map(|aa| aa.declared_dependencies().map_or(0, |d| d.declared)),
                "dependent": dependent,
                "deps": deps,
            })
        })
        .collect()
}

fn aggregate_vectors(rng: &mut Rng) -> Vec<Value> {
    let statement =
        |byte: u8| Item::List(vec![Item::Str(vec![byte; 32]), Item::Str(vec![byte ^ 0xff; 32])]);
    let payload = |statements: Vec<Item>| {
        Item::List(vec![
            uint(PROOF_AGGREGATE_PAYLOAD_VERSION.into()),
            uint(41),
            Item::Str(LEANVM_TREE_CLASS_KEY_DIGEST.to_vec()),
            Item::List(statements),
            Item::Str(b"proof".to_vec()),
        ])
    };
    let encode = |item: &Item| {
        let mut out = Vec::new();
        item.encode(&mut out);
        out
    };
    let base = payload(vec![statement(1), statement(2)]);
    let mut encodings = vec![("well-formed", encode(&base))];
    use field::*;
    let variants = [
        Variant::new("version 3", 0, &[VERSION], uint(3)),
        Variant::new("version 5", 0, &[VERSION], uint(5)),
        Variant::new(
            "version as a non-canonical single byte",
            0,
            &[VERSION],
            Item::Raw(vec![0x81, 0x04]),
        ),
        Variant::new("version with a leading zero", 0, &[VERSION], Item::Str(vec![0, 4])),
        Variant::new("9-byte through", 0, &[THROUGH], Item::Str(vec![0x01; 9])),
        Variant::new("through zero", 0, &[THROUGH], uint(0)),
        Variant::new("through with a leading zero", 0, &[THROUGH], Item::Str(vec![0, 0x29])),
        Variant::new("through of u64::MAX", 0, &[THROUGH], uint(u64::MAX.into())),
        Variant::new("31-byte class", 0, &[VKEY], Item::Str(vec![0x71; 31])),
        Variant::new("another class", 0, &[VKEY], Item::Str(vec![0x71; 32])),
        Variant::new("no statements", 0, &[STATEMENTS], Item::List(vec![])),
        Variant::new(
            "a statement with one field",
            0,
            &[STATEMENTS],
            Item::List(vec![Item::List(vec![Item::Str(vec![1; 32])])]),
        ),
        Variant::new(
            "a statement with three fields",
            0,
            &[STATEMENTS],
            Item::List(vec![Item::List(vec![
                Item::Str(vec![1; 32]),
                Item::Str(vec![1; 32]),
                Item::Str(vec![]),
            ])]),
        ),
        Variant::new("a statement as a string", 0, &[STATEMENTS, 0], Item::Str(vec![1; 64])),
        Variant::new("an empty proof", 0, &[PROOF], Item::Str(vec![])),
        Variant::new("proof as a list", 0, &[PROOF], Item::List(vec![])),
        Variant::new(
            "proof with a long-form string header",
            0,
            &[PROOF],
            Item::Raw(vec![0xb8, 0x02, 0x01, 0x02]),
        ),
    ];
    let bases = [base];
    for variant in variants {
        encodings.push((variant.what, encode(&variant.apply(&bases))));
    }
    let [base] = bases;
    // The tree proof inside the payload's proof field, which verification decodes.
    let with_tree_proof = |what, proof: Item| {
        let mut payload = payload(vec![statement(1)]);
        payload.list_mut()[field::PROOF] = Item::Str(encode(&proof));
        (what, encode(&payload))
    };
    let tree_proof = |root: &[u8], seal: &[u8]| {
        Item::List(vec![Item::Str(root.to_vec()), Item::Str(seal.to_vec())])
    };
    encodings.push(with_tree_proof("a tree proof", tree_proof(b"root", b"seal")));
    encodings.push(with_tree_proof("a tree proof with an empty seal", tree_proof(b"root", b"")));
    let mut third = tree_proof(b"root", b"seal");
    third.list_mut().push(Item::Str(vec![]));
    encodings.push(with_tree_proof("a tree proof with a third field", third));
    let mut one = tree_proof(b"root", b"seal");
    one.list_mut().pop();
    encodings.push(with_tree_proof("a tree proof with one field", one));
    let mut trailing = encode(&tree_proof(b"root", b"seal"));
    trailing.push(0);
    encodings.push(with_tree_proof("a tree proof with a trailing byte", Item::Raw(trailing)));
    encodings.push(with_tree_proof(
        "a tree proof with a long-form root header",
        Item::List(vec![Item::Raw(vec![0xb8, 0x02, 0x01, 0x02]), Item::Str(b"seal".to_vec())]),
    ));
    encodings.push(with_tree_proof("a tree proof as a string", Item::Str(b"root".to_vec())));
    let mut extra = base.clone();
    extra.list_mut().push(uint(0));
    encodings.push(("an extra field", encode(&extra)));
    let mut missing = base;
    missing.list_mut().pop();
    encodings.push(("a missing field", encode(&missing)));
    encodings.push(("empty", vec![]));
    let mangled = mangle(&encodings[..1], rng);
    encodings.extend(mangled);

    encodings
        .into_iter()
        .map(|(what, raw)| match ProofAggregatePayload::from_rlp_bytes(&raw) {
            Ok(p) => json!({
                "what": what,
                "payload": hex::encode_prefixed(&raw),
                "decodes": true,
                "through": p.through,
                "vkey": p.aggregation_vkey_hash.to_string(),
                // Long lists only by count and hash, to keep the file small.
                "statementCount": p.statements.len(),
                "statementsHash": alloy_primitives::keccak256(
                    p.statements
                        .iter()
                        .flat_map(|s| [s.vkey_hash.0, s.public_values_digest.0].concat())
                        .collect::<Vec<u8>>()
                ).to_string(),
                "statements": (p.statements.len() <= 16).then(|| {
                    p.statements
                        .iter()
                        .map(|s| json!([s.vkey_hash.to_string(), s.public_values_digest.to_string()]))
                        .collect::<Vec<_>>()
                }),
                "proof": hex::encode_prefixed(&p.proof),
                "treeProof": LeanVmTreeProof::from_rlp_bytes(&p.proof).ok().map(|proof| {
                    json!([hex::encode_prefixed(&proof.root), hex::encode_prefixed(&proof.seal)])
                }),
                "limitsOk": p.check_limits().is_ok(),
            }),
            Err(_) => {
                json!({ "what": what, "payload": hex::encode_prefixed(&raw), "decodes": false })
            }
        })
        .collect()
}

/// Whether a payload of `statements` zero statements and a `proof_bytes` byte proof is within the
/// limits: the payloads at and past them are megabytes, so only their verdicts are written, and Go
/// rebuilds them.
fn within_limits(statements: usize, proof_bytes: usize) -> bool {
    ProofAggregatePayload {
        version: PROOF_AGGREGATE_PAYLOAD_VERSION,
        through: 1,
        aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
        statements: vec![
            ProofStatement { vkey_hash: B256::ZERO, public_values_digest: B256::ZERO };
            statements
        ],
        proof: Bytes::from(vec![0; proof_bytes]),
    }
    .check_limits()
    .is_ok()
}

/// The vectors, each corpus with randomness of its own so that one changing does not shift the
/// other.
fn vectors() -> Value {
    json!({
        "aaTxs": aa_vectors(&mut Rng(0x8430_8288_5eed_0079)),
        "aggregates": aggregate_vectors(&mut Rng(0xa665_eed0_fca1_1000)),
        // The limits and the verdicts at them, not payloads at them: those would be megabytes.
        "limits": {
            "maxStatements": MAX_PROOF_AGGREGATE_STATEMENTS,
            "maxProofBytes": MAX_PROOF_AGGREGATE_PROOF_BYTES,
            "atLimitsOk": within_limits(MAX_PROOF_AGGREGATE_STATEMENTS, MAX_PROOF_AGGREGATE_PROOF_BYTES),
            "pastStatementsOk": within_limits(MAX_PROOF_AGGREGATE_STATEMENTS + 1, MAX_PROOF_AGGREGATE_PROOF_BYTES),
            "pastProofOk": within_limits(MAX_PROOF_AGGREGATE_STATEMENTS, MAX_PROOF_AGGREGATE_PROOF_BYTES + 1),
        },
    })
}

/// The committed vectors, relative to this crate.
fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../../op-core/types/testdata/dependency_vectors.json")
}

#[test]
#[ignore = "writes the Go parity vectors; run by hand after changing the decoders"]
fn write_go_dependency_vectors() {
    std::fs::write(vectors_path(), serde_json::to_string_pretty(&vectors()).unwrap() + "\n")
        .unwrap();
}

/// The committed vectors are what this crate makes of the encodings, so a decoder change fails
/// here until the Go suite is checked against the regenerated file.
#[test]
fn go_dependency_vectors_are_current() {
    let committed: Value = serde_json::from_slice(&std::fs::read(vectors_path()).unwrap()).unwrap();
    assert!(
        committed == vectors(),
        "op-core/types/testdata/dependency_vectors.json is stale: run write_go_dependency_vectors"
    );
}
