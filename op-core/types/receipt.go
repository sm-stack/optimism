package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// Receipt extends go-ethereum's receipt with the OP Stack fields that L2
// endpoints include in eth_getTransactionReceipt responses. The full op-geth
// field set is carried — not just the fields the monorepo services read — so
// receipt JSON round-trips completely. JSON field names match op-geth's
// types.Receipt verbatim for wire compatibility; values are hex-encoded on the
// wire, hence the custom JSON methods.
//
// While the go.mod replace still points at op-geth, the embedded types.Receipt
// carries identically-named fields. UnmarshalJSON populates both copies
// consistently; when marshaling, the outer fields take precedence.
type Receipt struct {
	types.Receipt
	// DepositNonce was introduced in Regolith to store the actual nonce used by
	// deposit transactions.
	DepositNonce *uint64 `json:"depositNonce,omitempty"`
	// DepositReceiptVersion was introduced in Canyon to indicate an update to
	// how receipt hashes should be computed when set; nil when not set.
	DepositReceiptVersion *uint64 `json:"depositReceiptVersion,omitempty"`
	// L1GasPrice is present from pre-bedrock; the L1 base fee after Bedrock.
	L1GasPrice *big.Int `json:"l1GasPrice,omitempty"`
	// L1BlobBaseFee is nil prior to the Ecotone hardfork.
	L1BlobBaseFee *big.Int `json:"l1BlobBaseFee,omitempty"`
	// L1GasUsed is present from pre-bedrock, deprecated as of Fjord.
	L1GasUsed *big.Int `json:"l1GasUsed,omitempty"`
	// L1Fee is present from pre-bedrock.
	L1Fee *big.Int `json:"l1Fee,omitempty"`
	// FeeScalar is present from pre-bedrock to Ecotone; nil after Ecotone.
	FeeScalar *big.Float `json:"l1FeeScalar,omitempty"`
	// L1BaseFeeScalar is nil prior to the Ecotone hardfork.
	L1BaseFeeScalar *uint64 `json:"l1BaseFeeScalar,omitempty"`
	// L1BlobBaseFeeScalar is nil prior to the Ecotone hardfork.
	L1BlobBaseFeeScalar *uint64 `json:"l1BlobBaseFeeScalar,omitempty"`
	// OperatorFeeScalar is nil prior to the Isthmus hardfork.
	OperatorFeeScalar *uint64 `json:"operatorFeeScalar,omitempty"`
	// OperatorFeeConstant is nil prior to the Isthmus hardfork.
	OperatorFeeConstant *uint64 `json:"operatorFeeConstant,omitempty"`
	// DAFootprintGasScalar is nil prior to the Jovian hardfork.
	DAFootprintGasScalar *uint64 `json:"daFootprintGasScalar,omitempty"`
	// CommittedPhases is the number of phases of an EIP-8430 (0x79) transaction that committed;
	// nil for other types.
	CommittedPhases *uint64 `json:"committedPhases,omitempty"`
	// Payer is the resolved payer of an EIP-8430 (0x79) transaction, as op-reth reports it; nil for
	// other types. It is not part of the consensus encoding.
	Payer *common.Address `json:"payer,omitempty"`
}

// receiptOpFields is the wire representation of the OP Stack receipt extensions.
type receiptOpFields struct {
	DepositNonce          *hexutil.Uint64 `json:"depositNonce,omitempty"`
	DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion,omitempty"`
	L1GasPrice            *hexutil.Big    `json:"l1GasPrice,omitempty"`
	L1BlobBaseFee         *hexutil.Big    `json:"l1BlobBaseFee,omitempty"`
	L1GasUsed             *hexutil.Big    `json:"l1GasUsed,omitempty"`
	L1Fee                 *hexutil.Big    `json:"l1Fee,omitempty"`
	FeeScalar             *big.Float      `json:"l1FeeScalar,omitempty"`
	L1BaseFeeScalar       *hexutil.Uint64 `json:"l1BaseFeeScalar,omitempty"`
	L1BlobBaseFeeScalar   *hexutil.Uint64 `json:"l1BlobBaseFeeScalar,omitempty"`
	OperatorFeeScalar     *hexutil.Uint64 `json:"operatorFeeScalar,omitempty"`
	OperatorFeeConstant   *hexutil.Uint64 `json:"operatorFeeConstant,omitempty"`
	DAFootprintGasScalar  *hexutil.Uint64 `json:"daFootprintGasScalar,omitempty"`
	CommittedPhases       *hexutil.Uint64 `json:"committedPhases,omitempty"`
	Payer                 *common.Address `json:"payer,omitempty"`
}

// UnmarshalJSON decodes both the embedded go-ethereum receipt and the OP Stack
// extension fields from the same JSON object.
func (r *Receipt) UnmarshalJSON(input []byte) error {
	if err := json.Unmarshal(input, &r.Receipt); err != nil {
		return err
	}
	var dec receiptOpFields
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	r.DepositNonce = (*uint64)(dec.DepositNonce)
	r.DepositReceiptVersion = (*uint64)(dec.DepositReceiptVersion)
	r.L1GasPrice = (*big.Int)(dec.L1GasPrice)
	r.L1BlobBaseFee = (*big.Int)(dec.L1BlobBaseFee)
	r.L1GasUsed = (*big.Int)(dec.L1GasUsed)
	r.L1Fee = (*big.Int)(dec.L1Fee)
	r.FeeScalar = dec.FeeScalar
	r.L1BaseFeeScalar = (*uint64)(dec.L1BaseFeeScalar)
	r.L1BlobBaseFeeScalar = (*uint64)(dec.L1BlobBaseFeeScalar)
	r.OperatorFeeScalar = (*uint64)(dec.OperatorFeeScalar)
	r.OperatorFeeConstant = (*uint64)(dec.OperatorFeeConstant)
	r.DAFootprintGasScalar = (*uint64)(dec.DAFootprintGasScalar)
	r.CommittedPhases = (*uint64)(dec.CommittedPhases)
	r.Payer = dec.Payer
	if r.Type == AaTxType && r.CommittedPhases == nil {
		return errors.New("EIP-8430 receipt without committedPhases")
	}
	return nil
}

// MarshalJSON encodes the embedded go-ethereum receipt and merges the OP Stack
// extension fields into the same JSON object, so the encoding round-trips.
func (r Receipt) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(&r.Receipt)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		return nil, err
	}
	extra, err := json.Marshal(&receiptOpFields{
		DepositNonce:          (*hexutil.Uint64)(r.DepositNonce),
		DepositReceiptVersion: (*hexutil.Uint64)(r.DepositReceiptVersion),
		L1GasPrice:            (*hexutil.Big)(r.L1GasPrice),
		L1BlobBaseFee:         (*hexutil.Big)(r.L1BlobBaseFee),
		L1GasUsed:             (*hexutil.Big)(r.L1GasUsed),
		L1Fee:                 (*hexutil.Big)(r.L1Fee),
		FeeScalar:             r.FeeScalar,
		L1BaseFeeScalar:       (*hexutil.Uint64)(r.L1BaseFeeScalar),
		L1BlobBaseFeeScalar:   (*hexutil.Uint64)(r.L1BlobBaseFeeScalar),
		OperatorFeeScalar:     (*hexutil.Uint64)(r.OperatorFeeScalar),
		OperatorFeeConstant:   (*hexutil.Uint64)(r.OperatorFeeConstant),
		DAFootprintGasScalar:  (*hexutil.Uint64)(r.DAFootprintGasScalar),
		CommittedPhases:       (*hexutil.Uint64)(r.CommittedPhases),
		Payer:                 r.Payer,
	})
	if err != nil {
		return nil, err
	}
	var extraObj map[string]json.RawMessage
	if err := json.Unmarshal(extra, &extraObj); err != nil {
		return nil, err
	}
	for k, v := range extraObj {
		obj[k] = v
	}
	return json.Marshal(obj)
}
