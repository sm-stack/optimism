//! Proof aggregate types.
//!
//! A proof aggregate proves every statement it lists: the OP Stack's carrier for the recursive
//! proof [EIP-8288] puts in the block header. It is a checkpoint: it answers for the dependencies
//! that transactions declared in L2 blocks up to its `through` block. The batcher posts it
//! in a channel as a proof aggregate batch, and derivation replaces a block with its deposits
//! unless the aggregate responsible for it proves all its dependencies.
//!
//! An aggregate is one root of a leanVM aggregation tree over the statements' proofs, whatever
//! their programs, and the seal that settles the root's claims on the tree's fixed polynomials
//! ([`LeanVmTreeProof`]). The tree's class, its circuits fixed for every program, is the
//! `AGGREGATED_VK` of [EIP-8288] ([`LEANVM_TREE_CLASS_KEY_DIGEST`]).
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use alloc::{string::String, sync::Arc, vec::Vec};
use alloy_primitives::{B256, Bytes, b256, keccak256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use core::fmt::Debug;

/// Verifies the leanVM tree roots proof aggregates carry.
///
/// Each environment supplies its own implementation: native verification in the nodes, and the
/// same software verifier, with an embedded class key, inside the Cannon fault proof program.
pub trait ProofAggregateVerifier: Debug + Send + Sync {
    /// Checks that `root`, a root of the leanVM tree class [`LEANVM_TREE_CLASS_KEY_DIGEST`], and
    /// `seal` prove exactly `statements`: each statement a program's verifying key digest and a
    /// member its leaf published.
    fn verify(&self, statements: &[ProofStatement], root: &[u8], seal: &[u8])
    -> Result<(), String>;
}

/// Shared handle to a [`ProofAggregateVerifier`].
pub type SharedProofAggregateVerifier = Arc<dyn ProofAggregateVerifier>;

/// Format version of a [`ProofAggregatePayload`]: its `proof` is a [`LeanVmTreeProof`] and its
/// `aggregation_vkey_hash` is [`LEANVM_TREE_CLASS_KEY_DIGEST`].
pub const PROOF_AGGREGATE_PAYLOAD_VERSION: u8 = 4;

/// Digest of the leanVM tree class every proof aggregate is a root of: the pinned class key of
/// `op-leanvm-tree` (the circuits, fixed polynomials and seal commitments of one class of leaf
/// programs and tree shapes). An aggregate of any other class proves nothing.
pub const LEANVM_TREE_CLASS_KEY_DIGEST: B256 =
    b256!("0x2afe0b2e99fec38e3d385e9b8cfe2de92669fb55deef74c61e63f6a73e91eadd");

/// Upper bound on the statements a proof aggregate lists: the class's claim capacity.
pub const MAX_PROOF_AGGREGATE_STATEMENTS: usize = 4096;

/// Upper bound on the programs a proof aggregate's statements are of: the class's group capacity,
/// each program's statements one group of the root's claim set.
pub const MAX_PROOF_AGGREGATE_PROGRAMS: usize = 64;

/// The most statements a sequencer puts in one proof aggregate, and so in the blocks it answers
/// for: what keeps the batch carrying it within three blobs (3 x 130,044 bytes) once its channel
/// is zlib-compressed, with about 6 KB to spare for framing and compressors. Its root and seal are
/// about 347 KiB and compress to about 315 KiB; each statement adds about 34 bytes, its member
/// being a digest that does not compress. A policy of the sequencer, not a validity rule: an
/// aggregate of up to [`MAX_PROOF_AGGREGATE_STATEMENTS`] is valid, in more blobs.
pub const TARGET_PROOF_AGGREGATE_STATEMENTS: usize = 1700;

/// Upper bound on a proof aggregate's proof: a root of about 157 KiB and a seal of about 190 KiB,
/// whatever the statements, plus the RLP framing. Anything larger is
/// invalid without being decoded, which bounds the verification work an aggregate can demand of
/// every node and of the proof programs.
pub const MAX_PROOF_AGGREGATE_PROOF_BYTES: usize = 1024 * 1024;

/// Upper bound on one statement's leanVM proof. A zero-knowledge proof of the small program class
/// (rate 1/4) is about 415 KiB, one of the large program class (rate 1/8) about 430 KiB.
pub const MAX_STATEMENT_PROOF_BYTES: usize = 512 * 1024;

/// Upper bound on a verifying key of the leanVM tree class's program classes: its root, five words
/// and the class's image, at most the large program class's 128 words (1,096 bytes).
pub const MAX_STATEMENT_VERIFYING_KEY_BYTES: usize = 32 + 5 * 8 + 8 * 128;

/// A statement that a program's run published a member: what an [EIP-8288] dependency of scheme
/// [`crate::PROOF_STATEMENT_SCHEME`] asks to be proven.
///
/// Every leaf of the tree class publishes a list of members, and each member is a statement of
/// its program: an arbitrary program's list is its own, and the leanSPHINCS signature-member
/// guest publishes one member per signature it verified, `BLAKE2s("sphmem01" || public key ||
/// message)`.
///
/// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProofStatement {
    /// The digest of the verifying key of the guest normalized to its leaf class.
    pub vkey_hash: B256,
    /// The member: four little-endian words.
    pub public_values_digest: B256,
}

impl ProofStatement {
    /// Returns the id the sequencer keys the statement by:
    /// `keccak256(vkey_hash || public_values_digest)`.
    pub fn id(&self) -> B256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.vkey_hash.as_slice());
        buf[32..].copy_from_slice(self.public_values_digest.as_slice());
        keccak256(buf)
    }
}

/// An aggregate proof over a list of statements, as the sequencer queues it for op-batcher to post
/// as a proof aggregate batch (`admin_pendingProofAggregates`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PendingAggregate {
    /// The payload version the aggregate posts as: [`PROOF_AGGREGATE_PAYLOAD_VERSION`].
    pub version: u8,
    /// The class key digest of the tree the aggregate is a root of.
    pub aggregation_vkey_hash: B256,
    /// The last L2 block whose dependencies the aggregate answers for: the `through` of the batch
    /// it was proven over.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub through: u64,
    /// The statements the aggregate covers, in the canonical order of the root's claims.
    pub statements: Vec<ProofStatement>,
    /// The RLP encoding of a [`LeanVmTreeProof`].
    pub proof: Bytes,
}

impl From<PendingAggregate> for ProofAggregatePayload {
    fn from(aggregate: PendingAggregate) -> Self {
        Self {
            version: aggregate.version,
            through: aggregate.through,
            aggregation_vkey_hash: aggregate.aggregation_vkey_hash,
            statements: aggregate.statements,
            proof: aggregate.proof,
        }
    }
}

/// The proof a proof aggregate carries: a root of a tree of the class
/// [`LEANVM_TREE_CLASS_KEY_DIGEST`] whose claims are exactly the payload's statements, and the
/// seal that opens the root's claims on the class's fixed polynomials.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
pub struct LeanVmTreeProof {
    /// The tree root's bytes.
    pub root: Bytes,
    /// The seal's bytes.
    pub seal: Bytes,
}

impl LeanVmTreeProof {
    /// RLP-encode the proof into bytes.
    pub fn to_rlp_bytes(&self) -> Bytes {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.into()
    }

    /// Decode a proof from RLP bytes, rejecting trailing bytes.
    pub fn from_rlp_bytes(data: &[u8]) -> alloy_rlp::Result<Self> {
        let mut buf = data;
        let proof = Self::decode(&mut buf)?;
        if !buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(proof)
    }
}

/// A proof aggregate, as the batcher posts it in a proof aggregate batch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProofAggregatePayload {
    /// Format version: [`PROOF_AGGREGATE_PAYLOAD_VERSION`].
    pub version: u8,
    /// The last L2 block whose transactions' dependencies this aggregate answers for.
    pub through: u64,
    /// The class key digest of the tree the aggregate is a root of: only
    /// [`LEANVM_TREE_CLASS_KEY_DIGEST`] proves anything.
    pub aggregation_vkey_hash: B256,
    /// The statements the aggregate proves, in the canonical order of the tree root's claims.
    pub statements: Vec<ProofStatement>,
    /// The RLP encoding of a [`LeanVmTreeProof`].
    pub proof: Bytes,
}

// `version` is pinned rather than left arbitrary because `from_rlp_bytes` rejects any other value,
// which would break encode/decode roundtrip property tests.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ProofAggregatePayload {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            through: u64::arbitrary(u)?,
            aggregation_vkey_hash: B256::arbitrary(u)?,
            statements: <Vec<ProofStatement>>::arbitrary(u)?,
            proof: Bytes::arbitrary(u)?,
        })
    }
}

impl ProofAggregatePayload {
    /// Checks what can be checked without verifying the proof: the version, the tree class, and
    /// the limits on statements and proof size.
    pub fn check_limits(&self) -> Result<(), String> {
        if self.version != PROOF_AGGREGATE_PAYLOAD_VERSION {
            return Err(alloc::format!("unknown payload version {}", self.version));
        }
        if self.aggregation_vkey_hash != LEANVM_TREE_CLASS_KEY_DIGEST {
            return Err(alloc::format!("proven in untrusted class {}", self.aggregation_vkey_hash));
        }
        if self.statements.is_empty() {
            return Err(String::from("lists no statements"));
        }
        if self.statements.len() > MAX_PROOF_AGGREGATE_STATEMENTS {
            return Err(alloc::format!(
                "lists {} statements, above the {MAX_PROOF_AGGREGATE_STATEMENTS} statement limit",
                self.statements.len()
            ));
        }
        if self.proof.len() > MAX_PROOF_AGGREGATE_PROOF_BYTES {
            return Err(alloc::format!(
                "carries a {} byte proof, above the {MAX_PROOF_AGGREGATE_PROOF_BYTES} byte limit",
                self.proof.len()
            ));
        }
        Ok(())
    }

    /// Checks the limits, then verifies the aggregate's tree root and seal with `verifier`: the
    /// statements are proven iff this returns `Ok`.
    pub fn verify(&self, verifier: &dyn ProofAggregateVerifier) -> Result<(), String> {
        self.check_limits()?;
        let proof = LeanVmTreeProof::from_rlp_bytes(&self.proof)
            .map_err(|err| alloc::format!("malformed leanVM tree proof: {err}"))?;
        verifier.verify(&self.statements, &proof.root, &proof.seal)
    }

    /// RLP-encode the payload into bytes.
    pub fn to_rlp_bytes(&self) -> Bytes {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.into()
    }

    /// Decode a payload from RLP bytes, rejecting unknown versions and trailing bytes.
    pub fn from_rlp_bytes(data: &[u8]) -> alloy_rlp::Result<Self> {
        let mut buf = data;
        let payload = Self::decode(&mut buf)?;
        if payload.version != PROOF_AGGREGATE_PAYLOAD_VERSION {
            return Err(alloy_rlp::Error::Custom("unsupported proof aggregate payload version"));
        }
        if !buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::bytes;

    fn sample() -> ProofAggregatePayload {
        ProofAggregatePayload {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            through: 6,
            aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
            statements: vec![
                ProofStatement {
                    vkey_hash: B256::repeat_byte(0x11),
                    public_values_digest: B256::ZERO,
                },
                ProofStatement {
                    vkey_hash: B256::repeat_byte(0x22),
                    public_values_digest: B256::repeat_byte(0x33),
                },
            ],
            proof: bytes!("deadbeef"),
        }
    }

    #[test]
    fn roundtrip() {
        let payload = sample();
        assert_eq!(
            ProofAggregatePayload::from_rlp_bytes(&payload.to_rlp_bytes()).unwrap(),
            payload
        );
    }

    #[test]
    fn rejects_other_versions() {
        for version in [3, 5] {
            let payload = ProofAggregatePayload { version, ..sample() };
            assert!(ProofAggregatePayload::from_rlp_bytes(&payload.to_rlp_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut raw = sample().to_rlp_bytes().to_vec();
        raw.push(0);
        assert!(ProofAggregatePayload::from_rlp_bytes(&raw).is_err());
    }

    /// Golden vector shared with op-core's `TestProofAggregatePayloadGoldenVector` (Go).
    #[test]
    fn payload_golden_vector() {
        let payload = ProofAggregatePayload {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            through: 41,
            aggregation_vkey_hash: B256::repeat_byte(0xaa),
            statements: vec![ProofStatement {
                vkey_hash: B256::repeat_byte(0x11),
                public_values_digest: B256::repeat_byte(0x22),
            }],
            proof: bytes!("deadbeef"),
        };
        assert_eq!(
            alloy_primitives::hex::encode(payload.to_rlp_bytes()),
            "f86e0429a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a011\
             11111111111111111111111111111111111111111111111111111111111111a02222222222222222222222\
             22222222222222222222222222222222222222222284deadbeef"
        );
    }

    /// Golden vector pinning the statement id: the key a dependency is looked up by.
    #[test]
    fn statement_id_golden_vector() {
        let statement = sample().statements[1];
        assert_eq!(
            statement.id(),
            b256!("0xf3357627f4934d47fe409005b05c900777a6d97ec3788304e2d9c7b4d322cd4d")
        );
    }

    /// Accepts a tree proof iff its root is `b"root"` followed by the statements' bytes and its
    /// seal is `b"seal"`.
    #[derive(Debug)]
    struct FakeLeanVmTree;

    impl ProofAggregateVerifier for FakeLeanVmTree {
        fn verify(
            &self,
            statements: &[ProofStatement],
            root: &[u8],
            seal: &[u8],
        ) -> Result<(), String> {
            (root == fake_root(statements).as_ref() && seal == b"seal")
                .then_some(())
                .ok_or_else(|| String::from("bad tree proof"))
        }
    }

    fn fake_root(statements: &[ProofStatement]) -> Bytes {
        let mut root = b"root".to_vec();
        for statement in statements {
            root.extend_from_slice(statement.vkey_hash.as_slice());
            root.extend_from_slice(statement.public_values_digest.as_slice());
        }
        root.into()
    }

    fn tree_payload() -> ProofAggregatePayload {
        let statements = vec![
            ProofStatement {
                vkey_hash: B256::repeat_byte(0xaa),
                public_values_digest: B256::repeat_byte(1),
            },
            ProofStatement {
                vkey_hash: B256::repeat_byte(0xbb),
                public_values_digest: B256::repeat_byte(2),
            },
        ];
        let proof =
            LeanVmTreeProof { root: fake_root(&statements), seal: Bytes::from_static(b"seal") };
        ProofAggregatePayload {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            through: 9,
            aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
            statements,
            proof: proof.to_rlp_bytes(),
        }
    }

    /// Golden vector shared with op-core's `TestLeanVmTreeProofGoldenVector` (Go).
    #[test]
    fn leanvm_tree_proof_golden_vector() {
        let proof = LeanVmTreeProof {
            root: Bytes::from_static(b"root"),
            seal: Bytes::from_static(b"seal"),
        };
        assert_eq!(alloy_primitives::hex::encode(proof.to_rlp_bytes()), "ca84726f6f74847365616c");
        assert_eq!(LeanVmTreeProof::from_rlp_bytes(&proof.to_rlp_bytes()).unwrap(), proof);
    }

    #[test]
    fn verifies_a_leanvm_tree() {
        let payload = tree_payload();
        assert_eq!(
            ProofAggregatePayload::from_rlp_bytes(&payload.to_rlp_bytes()).unwrap(),
            payload
        );
        payload.verify(&FakeLeanVmTree).unwrap();
    }

    #[test]
    fn rejects_a_malformed_leanvm_tree() {
        let reject = |payload: ProofAggregatePayload, why: &str| {
            assert!(payload.verify(&FakeLeanVmTree).is_err(), "{why}");
        };
        reject(
            ProofAggregatePayload { aggregation_vkey_hash: B256::ZERO, ..tree_payload() },
            "another class",
        );
        let mut statements = tree_payload().statements;
        statements[1].public_values_digest = B256::repeat_byte(9);
        reject(ProofAggregatePayload { statements, ..tree_payload() }, "another output");
        reject(
            ProofAggregatePayload {
                statements: vec![tree_payload().statements[0]; MAX_PROOF_AGGREGATE_STATEMENTS + 1],
                ..tree_payload()
            },
            "too many statements",
        );
        reject(ProofAggregatePayload { statements: vec![], ..tree_payload() }, "no statements");
        reject(
            ProofAggregatePayload {
                proof: vec![0; MAX_PROOF_AGGREGATE_PROOF_BYTES + 1].into(),
                ..tree_payload()
            },
            "an oversized proof",
        );
        let mut raw = tree_payload().proof.to_vec();
        raw.push(0);
        reject(ProofAggregatePayload { proof: raw.into(), ..tree_payload() }, "trailing bytes");
        reject(
            ProofAggregatePayload { proof: Bytes::from_static(b"seal"), ..tree_payload() },
            "no tree proof",
        );
        reject(ProofAggregatePayload { version: 3, ..tree_payload() }, "an unknown version");
    }
}
