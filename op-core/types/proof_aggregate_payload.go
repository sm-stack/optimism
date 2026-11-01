package types

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// LeanVmTreeClassKeyDigest is the digest of the leanVM tree class every proof aggregate is a root
// of: the AggregationVkeyHash of every payload, the OP Stack's AGGREGATED_VK (EIP-8288). It must
// equal op-alloy's LEANVM_TREE_CLASS_KEY_DIGEST.
var LeanVmTreeClassKeyDigest = common.HexToHash("0x2afe0b2e99fec38e3d385e9b8cfe2de92669fb55deef74c61e63f6a73e91eadd")

const (
	// ProofAggregatePayloadVersion is the format version of a proof aggregate: its Proof is a
	// LeanVmTreeProof and its AggregationVkeyHash is LeanVmTreeClassKeyDigest.
	ProofAggregatePayloadVersion = 4
	// MaxProofAggregateStatements bounds the statements a proof aggregate lists: the tree class's
	// claim capacity.
	MaxProofAggregateStatements = 4096
	// MaxProofAggregateProofBytes bounds a proof aggregate's proof: a root, a seal and the RLP
	// framing.
	MaxProofAggregateProofBytes = 1024 * 1024
)

// ProofStatement states that a program's run published a member: VkeyHash is the digest of the
// verifying key of the guest normalized to its leaf class, and PublicValuesDigest the member, four
// little-endian words. A leanSPHINCS signature's member is BLAKE2s("sphmem01" || public key ||
// message) under the signature-member guest's key.
type ProofStatement struct {
	VkeyHash           common.Hash `json:"vkeyHash"`
	PublicValuesDigest common.Hash `json:"publicValuesDigest"`
}

// ProofAggregatePayload is a proof aggregate as the batcher posts it in a proof aggregate batch,
// op-alloy's ProofAggregatePayload.
type ProofAggregatePayload struct {
	Version uint8
	// Through is the last L2 block whose transactions' dependencies the aggregate answers
	// for.
	Through             uint64
	AggregationVkeyHash common.Hash
	Statements          []ProofStatement
	// Proof is the RLP encoding of a LeanVmTreeProof.
	Proof []byte
}

// LeanVmTreeProof is the proof a proof aggregate carries, op-alloy's LeanVmTreeProof: a root of a
// tree of the class LeanVmTreeClassKeyDigest whose claims are the payload's statements, and the
// seal that opens the root's claims on the class's fixed polynomials.
type LeanVmTreeProof struct {
	Root []byte
	Seal []byte
}

// DecodeLeanVmTreeProof decodes a leanVM tree proof as op-alloy's LeanVmTreeProof::from_rlp_bytes
// does, rejecting trailing bytes.
func DecodeLeanVmTreeProof(data []byte) (*LeanVmTreeProof, error) {
	var p LeanVmTreeProof
	if err := rlp.DecodeBytes(data, &p); err != nil {
		return nil, fmt.Errorf("malformed leanVM tree proof: %w", err)
	}
	return &p, nil
}

// DecodeProofAggregatePayload decodes a proof aggregate payload as op-alloy's
// ProofAggregatePayload::from_rlp_bytes does: a version 4 payload and no trailing bytes.
func DecodeProofAggregatePayload(data []byte) (*ProofAggregatePayload, error) {
	var p ProofAggregatePayload
	if err := rlp.DecodeBytes(data, &p); err != nil {
		return nil, fmt.Errorf("invalid proof aggregate payload: %w", err)
	}
	if p.Version != ProofAggregatePayloadVersion {
		return nil, fmt.Errorf("unsupported proof aggregate payload version %d", p.Version)
	}
	return &p, nil
}

// CheckLimits checks what can be checked without verifying the proof: the version, the tree class,
// and the limits on statements and proof size.
func (p *ProofAggregatePayload) CheckLimits() error {
	if p.Version != ProofAggregatePayloadVersion {
		return fmt.Errorf("unknown payload version %d", p.Version)
	}
	if p.AggregationVkeyHash != LeanVmTreeClassKeyDigest {
		return fmt.Errorf("proven in untrusted class %s", p.AggregationVkeyHash)
	}
	if len(p.Statements) == 0 {
		return errors.New("lists no statements")
	}
	if len(p.Statements) > MaxProofAggregateStatements {
		return fmt.Errorf("lists %d statements, above the %d statement limit", len(p.Statements), MaxProofAggregateStatements)
	}
	if len(p.Proof) > MaxProofAggregateProofBytes {
		return fmt.Errorf("carries a %d byte proof, above the %d byte limit", len(p.Proof), MaxProofAggregateProofBytes)
	}
	return nil
}
