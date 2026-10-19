package types

import (
	"bytes"
	"errors"
	"fmt"
)

// ProofAggregateTxType is the EIP-2718 type byte of OP Stack proof aggregate transactions.
const ProofAggregateTxType = 0x7C

// ProofAggregateTx is a synthetic, unsigned OP Stack transaction carrying one SP1 proof that
// recursively verified the proofs behind a list of ProofRegistry statements. The sequencer
// places it directly after a block's deposits; the execution client verifies the proof and
// marks the statements verified.
//
// Like PostExecTx, its canonical encoding is ProofAggregateTxType || Data with no outer RLP
// envelope, and Data (an RLP-encoded payload) is opaque here. op-alloy's TxProofAggregate parses
// and validates the payload on decode, so malformed payloads are accepted here but rejected by
// the execution client, the same Go-lenient/Rust-strict split as PostExecTx. Neither op-node
// nor op-batcher needs the payload: derivation only carries the bytes.
type ProofAggregateTx struct {
	Data []byte
}

// MarshalBinary returns the canonical EIP-2718 encoding of the proof aggregate transaction.
func (p *ProofAggregateTx) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, 1+len(p.Data))
	out = append(out, ProofAggregateTxType)
	return append(out, p.Data...), nil
}

// UnmarshalProofAggregateTx decodes a proof aggregate transaction from its EIP-2718 encoding.
// It rejects an empty payload.
func UnmarshalProofAggregateTx(raw []byte) (*ProofAggregateTx, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty transaction bytes")
	}
	if raw[0] != ProofAggregateTxType {
		return nil, fmt.Errorf("expected proof aggregate tx type byte %#x, got %#x", ProofAggregateTxType, raw[0])
	}
	if len(raw) == 1 {
		return nil, errors.New("proof aggregate tx payload is empty")
	}
	return &ProofAggregateTx{Data: bytes.Clone(raw[1:])}, nil
}
