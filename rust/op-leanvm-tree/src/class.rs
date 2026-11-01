// The tree class: the library and its build script both include this file, each with its own copy
// of leanVM.

use leanvm::{
    PerTable, Rate, TableId,
    aggregate::{
        Capacity, ClaimShape, LeafClass, LeafShape, ProgramClass, Tree, TreeError, TreeShape,
        ZkPlacement,
    },
};

/// The leaf class of small arbitrary programs, which users prove in zero knowledge so that their
/// advice stays with them. Programs whose proofs need not hide anything are proven the same way:
/// a plain class would cost every aggregate a fourth first-level circuit.
pub const PROGRAM_CLASS: usize = 0;

/// The leaf class of the leanSPHINCS signature-member guest, which op-aggregator proves.
pub const SIGNATURE_CLASS: usize = 1;

/// The leaf class of large arbitrary programs, up to 2^20 ALU rows and 2^16 multiplications, 2^8 of
/// them high halves (such as a privacy pool's epoch of 64 transfers, or of one transfer authorized
/// by a lattice signature), which users prove in zero knowledge at rate 1/8. At rate 1/4 verifying
/// such a leaf would take more hash rows than the tree's tier holds, doubling every fold; the
/// queries rate 1/8 saves bring its first level within the tier, at the cost of a slower leaf
/// proof.
pub const LARGE_PROGRAM_CLASS: usize = 2;

/// The number of leaf classes.
pub const CLASSES: usize = 3;

/// The classes of the program leaves users submit, each in zero knowledge: a leaf's shape names its
/// class.
pub const PROGRAM_CLASSES: [usize; 2] = [PROGRAM_CLASS, LARGE_PROGRAM_CLASS];

/// Each leaf class's program bounds, in class order: the padded bytecode, the RAM and the advice
/// as base-two logarithms of words, the padded image's words, and the most members one leaf
/// publishes.
pub const CLASS_BOUNDS: [[usize; 5]; CLASSES] =
    [[12, 17, 13, 64, 128], [13, 17, 16, 64, 128], [14, 17, 16, 128, 128]];

/// Each leaf class's table heights, as base-two logarithms of rows, in leanVM's table order: ALU,
/// LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT.
///
/// The program class fits small general programs, up to 2^16 cycles; the signature class fits
/// the signature-member guest over [`SIGNATURES_PER_LEAF`] signatures; the large program class
/// fits a privacy pool's epoch of 64 transfers with a keccak member (ALU 625k, SD 281k, SHIFT
/// 174k rows), or of one transfer authorized by a Falcon-512 or ML-DSA-44 signature (MUL 2^16,
/// MULH 2^8). Its multiplication tables cost every leaf of the class proving memory (about 1 GB of
/// its 15 GB for these), so it holds no 2^17-row multiplication or division table. Every class's
/// first level is a circuit of the tree's one tier, at its heights ([`ZK_PLACEMENT`]).
pub const CLASS_LEAF_HEIGHTS: [[usize; 11]; CLASSES] = [
    [16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6],
    [20, 4, 15, 18, 18, 16, 4, 4, 4, 16, 3],
    [20, 9, 15, 18, 19, 18, 16, 8, 4, 16, 3],
];

/// Each leaf class's commitment rate, as a base-two logarithm of its inverse. A program leaf at
/// rate 1/4 is about 415 KiB; the large program class's at rate 1/8 about 430 KiB, within the
/// 512 KiB a statement proof may take.
pub const CLASS_LEAF_LOG_INV_RATES: [u8; CLASSES] = [2, 1, 3];

/// Whether each leaf class's proofs are zero knowledge.
pub const CLASS_ZERO_KNOWLEDGE: [bool; CLASSES] = [true, false, true];

/// Every tree proof's commitment rate, as a base-two logarithm of its inverse. At 1/8 a root is
/// about 157 KiB against 281 KiB at 1/2, which with its seal keeps an aggregate within three blobs,
/// and folding a leaf costs about the same.
pub const LOG_INV_RATE: u8 = 3;

/// The leaves a first-level node verifies.
pub const ARITY_0: usize = 1;

/// The most children a node above the first level verifies.
pub const ARITY: usize = 2;

/// A root declares fewer claims than this. The tree has one tier, so every node's circuits are
/// this capacity's: a seal opens the one tier whatever a root holds. At this capacity the first
/// levels' circuits set the tier's heights: 2049 claims fold no faster and prove no smaller.
pub const CLAIM_CAPACITY: usize = 4097;

/// A root declares at most this many groups: distinct programs.
pub const GROUP_CAPACITY: usize = 64;

/// Where the zero-knowledge classes' first levels sit: in the tree's one tier, with the others. A
/// seal opens each tier a root used, so a tier of its own would add about 175 KB to the seal of
/// every root holding a zero-knowledge leaf, and isolating them only pays where they would
/// otherwise raise the tier's heights.
pub const ZK_PLACEMENT: ZkPlacement = ZkPlacement::Shared;

/// The most signatures one signature leaf verifies: the guest's advice holds about 104.
pub const SIGNATURES_PER_LEAF: usize = 100;

/// The class key's digest, `BLAKE2s-256(b"leanvm/mixed-class-key/v4" || class key)`: what the
/// class's circuits and the commitments to their fixed polynomials, which seals open, are pinned
/// to. The key, format v4, carries those commitments and the circuits' dimensions, not their rows.
pub const CLASS_KEY_DIGEST: [u8; 32] = [
    0x2a, 0xfe, 0x0b, 0x2e, 0x99, 0xfe, 0xc3, 0x8e, 0x3d, 0x38, 0x5e, 0x9b, 0x8c, 0xfe, 0x2d, 0xe9,
    0x26, 0x69, 0xfb, 0x55, 0xde, 0xef, 0x74, 0xc6, 0x1e, 0x63, 0xf6, 0xa7, 0x3e, 0x91, 0xea, 0xdd,
];

/// The leaf classes, in class order.
pub fn classes() -> [LeafClass; CLASSES] {
    core::array::from_fn(|i| {
        let [log_bytecode, log_ram, log_advice, image_words, max_members] = CLASS_BOUNDS[i];
        let rate = Rate::new(CLASS_LEAF_LOG_INV_RATES[i]).expect("a supported rate");
        let shape = LeafShape::plain(
            PerTable::from_fn(|t: TableId| CLASS_LEAF_HEIGHTS[i][t.index()]),
            rate,
        )
        .expect("the classes' leaf heights are valid");
        LeafClass {
            program: ProgramClass { log_bytecode, log_ram, log_advice, image_words, max_members },
            shape: if CLASS_ZERO_KNOWLEDGE[i] { shape.zero_knowledge() } else { shape },
        }
    })
}

/// The tree shape: the program class's leaf shape, the arities, the rate and the one tier's
/// capacity.
pub fn shape() -> TreeShape {
    TreeShape {
        leaf: classes()[PROGRAM_CLASS].shape,
        arity_0: ARITY_0,
        arity: ARITY,
        rate: rate(),
        claims: Some(ClaimShape {
            capacity: Capacity { claims: CLAIM_CAPACITY, groups: GROUP_CAPACITY },
            small: None,
        }),
    }
}

/// The class's tree: its leaf classes, shape and zero-knowledge placement.
pub fn class_tree() -> Result<Tree<'static>, TreeError> {
    Tree::mixed_classes_with(&classes(), shape(), ZK_PLACEMENT)
}

/// The class's tree, verifier only, loaded from its class key `key` against `digest`.
pub fn class_tree_from_bytes(key: &[u8], digest: &[u8; 32]) -> Result<Tree<'static>, TreeError> {
    Tree::mixed_classes_from_bytes_with(&classes(), shape(), ZK_PLACEMENT, key, digest)
}

fn rate() -> Rate {
    Rate::new(LOG_INV_RATE).expect("a supported rate")
}
