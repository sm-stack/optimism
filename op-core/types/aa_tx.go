package types

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/blake2s"
)

const (
	// AaTxType is the EIP-2718 type byte of EIP-8430 account abstraction transactions.
	AaTxType = 0x79
	// AaPayerType is the domain byte of an EIP-8430 payer signature hash.
	AaPayerType = 0x7A

	// AccountChangeDelegation is the account_changes type of a delegation entry.
	AccountChangeDelegation = 0x01
	// AccountChangeDependencies is the account_changes type of an EIP-8288 dependency entry.
	AccountChangeDependencies = 0x04
)

// AaTx is an EIP-8430 account abstraction transaction: AaTxType || rlp([chain_id, sender,
// nonce_key, nonce_sequence, valid_after, valid_before, max_priority_fee_per_gas, max_fee_per_gas,
// gas_limit, account_changes, calls, metadata, payer, sender_auth, payer_auth]), the encoding
// op-alloy's TxEip8430 produces (see TestAaTxGoldenVector).
//
// Like the other OP Stack classes, Go only carries this transaction: op-node and op-batcher move
// its bytes and read its dependencies, and the execution client validates and executes it.
type AaTx struct {
	ChainID uint64
	// Sender is the named sender, or nil to recover it from SenderAuth; nil encodes as an empty
	// string.
	Sender               *common.Address `rlp:"nil"`
	NonceKey             *big.Int
	NonceSequence        uint64
	ValidAfter           uint64
	ValidBefore          uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	AccountChanges       []AccountChange
	// Calls are the phases of calls: a phase's calls commit together.
	Calls    [][]AaCall
	Metadata []byte
	// Payer is the payer field as encoded: empty for self-pay, 0x00 for an open payer, or the
	// named payer's address.
	Payer      []byte
	SenderAuth []byte
	PayerAuth  []byte
}

// AaCall is one call of a phase, dispatched from the sender.
type AaCall struct {
	To    common.Address
	Value *big.Int
	Data  []byte
}

// AccountChange is one account_changes entry: a delegation (Target) or an EIP-8288 dependency
// list (Dependencies), as Type says.
type AccountChange struct {
	Type         uint8
	Target       common.Address
	Dependencies []Dependency
}

// EncodeRLP writes rlp([0x01, target]) or rlp([0x04, [[scheme, data_hash, verification_key_hash],
// ...]]).
func (c *AccountChange) EncodeRLP(w io.Writer) error {
	switch c.Type {
	case AccountChangeDelegation:
		return rlp.Encode(w, []any{c.Type, c.Target})
	case AccountChangeDependencies:
		deps := make([]any, len(c.Dependencies))
		for i, d := range c.Dependencies {
			deps[i] = []any{d.Scheme, d.DataHash, d.VerificationKeyHash}
		}
		return rlp.Encode(w, []any{c.Type, deps})
	default:
		return fmt.Errorf("unknown account change type %#x", c.Type)
	}
}

// DecodeRLP reads an entry the way op-alloy's AccountChange decoder does: a known type and
// exactly its fields.
func (c *AccountChange) DecodeRLP(s *rlp.Stream) error {
	// rlp.EOL here is the end of account_changes, which rlp's slice decoder expects to see.
	if _, err := s.List(); err != nil {
		return err
	}
	if err := c.decodeFields(s); err != nil {
		// Inside the entry, a bare rlp.EOL would make the slice decoder end account_changes early
		// and keep decoding the transaction's later fields from inside it.
		return fmt.Errorf("invalid account change: %w", err)
	}
	return nil
}

// decodeFields reads an entry's fields and its end, after its list header.
func (c *AccountChange) decodeFields(s *rlp.Stream) error {
	typ, err := s.Uint8()
	if err != nil {
		return err
	}
	out := AccountChange{Type: typ}
	switch typ {
	case AccountChangeDelegation:
		if err := s.Decode(&out.Target); err != nil {
			return err
		}
	case AccountChangeDependencies:
		if _, err := s.List(); err != nil {
			return err
		}
		for s.MoreDataInList() {
			var d struct {
				Scheme              uint8
				DataHash            common.Hash
				VerificationKeyHash common.Hash
			}
			if err := s.Decode(&d); err != nil {
				return err
			}
			out.Dependencies = append(out.Dependencies, Dependency(d))
		}
		if err := s.ListEnd(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown account change type %#x", typ)
	}
	if err := s.ListEnd(); err != nil {
		return err
	}
	*c = out
	return nil
}

// MarshalBinary returns the canonical EIP-2718 encoding of the transaction.
func (tx *AaTx) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(AaTxType)
	if err := rlp.Encode(&buf, tx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalAaTx decodes a transaction from its EIP-2718 encoding, which must be exactly one RLP
// value after the type byte.
func UnmarshalAaTx(raw []byte) (*AaTx, error) {
	if len(raw) == 0 || raw[0] != AaTxType {
		return nil, errors.New("not an EIP-8430 transaction")
	}
	var tx AaTx
	if err := rlp.DecodeBytes(raw[1:], &tx); err != nil {
		return nil, fmt.Errorf("invalid EIP-8430 tx: %w", err)
	}
	if err := tx.checkFieldRanges(); err != nil {
		return nil, err
	}
	return &tx, nil
}

// DecodeAaTxLenient decodes a transaction the way op-alloy's TxEip8430::decode_2718 does, which
// derivation uses to find dependent transactions: only the first RLP value after the type byte is
// read and any bytes after it are ignored.
func DecodeAaTxLenient(raw []byte) (*AaTx, error) {
	if len(raw) == 0 || raw[0] != AaTxType {
		return nil, errors.New("not an EIP-8430 transaction")
	}
	var tx AaTx
	if err := rlp.NewStream(bytes.NewReader(raw[1:]), 0).Decode(&tx); err != nil {
		return nil, fmt.Errorf("invalid EIP-8430 tx: %w", err)
	}
	if err := tx.checkFieldRanges(); err != nil {
		return nil, err
	}
	return &tx, nil
}

// checkFieldRanges applies the rules op-alloy's decoder enforces through its field types: the
// fee caps fit u128, the nonce key and call values fit U256, and the payer is empty, 0x00 or an
// address.
func (tx *AaTx) checkFieldRanges() error {
	if tx.MaxPriorityFeePerGas.BitLen() > 128 || tx.MaxFeePerGas.BitLen() > 128 {
		return errors.New("invalid EIP-8430 tx: fee cap overflows u128")
	}
	if tx.NonceKey.BitLen() > 256 {
		return errors.New("invalid EIP-8430 tx: nonce key overflows u256")
	}
	for _, phase := range tx.Calls {
		for _, call := range phase {
			if call.Value.BitLen() > 256 {
				return errors.New("invalid EIP-8430 tx: call value overflows u256")
			}
		}
	}
	switch len(tx.Payer) {
	case 0, common.AddressLength:
	case 1:
		if tx.Payer[0] != 0 {
			return errors.New("invalid EIP-8430 tx: payer is neither empty, 0x00 nor an address")
		}
	default:
		return errors.New("invalid EIP-8430 tx: payer is neither empty, 0x00 nor an address")
	}
	return nil
}

// Hash returns the transaction hash: the keccak-256 hash of the canonical encoding, auth blobs
// included. See DepositTx.Hash for the panic rationale.
func (tx *AaTx) Hash() common.Hash {
	raw, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(raw)
}

// aaSignedFields are the fields both signature hashes cover: chain_id through payer.
type aaSignedFields struct {
	ChainID              uint64
	Sender               *common.Address `rlp:"nil"`
	NonceKey             *big.Int
	NonceSequence        uint64
	ValidAfter           uint64
	ValidBefore          uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	AccountChanges       []AccountChange
	Calls                [][]AaCall
	Metadata             []byte
	Payer                []byte
}

func (tx *AaTx) signingHash(domain byte, sender *common.Address) common.Hash {
	fields := aaSignedFields{
		tx.ChainID, sender, tx.NonceKey, tx.NonceSequence, tx.ValidAfter, tx.ValidBefore,
		tx.MaxPriorityFeePerGas, tx.MaxFeePerGas, tx.GasLimit, tx.AccountChanges, tx.Calls,
		tx.Metadata, tx.Payer,
	}
	var buf bytes.Buffer
	buf.WriteByte(domain)
	if err := rlp.Encode(&buf, &fields); err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(buf.Bytes())
}

// SenderSignatureHash returns the sender signature hash: keccak256(0x79 || rlp([chain_id, ...,
// payer])), with the wire sender. A zero dependency data hash stands for it.
func (tx *AaTx) SenderSignatureHash() common.Hash {
	return tx.signingHash(AaTxType, tx.Sender)
}

// PayerSignatureHash returns the payer signature hash of the transaction sent by sender: the
// sender hash's fields under 0x7A, with the resolved sender.
func (tx *AaTx) PayerSignatureHash(sender common.Address) common.Hash {
	return tx.signingHash(AaPayerType, &sender)
}

// declared returns the dependencies of the first dependency entry, as declared.
func (tx *AaTx) declared() []Dependency {
	for _, change := range tx.AccountChanges {
		if change.Type == AccountChangeDependencies {
			return change.Dependencies
		}
	}
	return nil
}

// StatementAuthenticator is the OP Stack STATEMENT authenticator (op-core/eip8130's
// StatementAuthenticatorAddress): a named sender or payer whose authorization is
// StatementAuthenticator || vk(32) || tag(8) || key(32) is authorized by the statement
// (0x20, BLAKE2s(tag || key || hash), vk) over its hash, which the transaction depends on.
var StatementAuthenticator = common.HexToAddress("0xC5EF79AD4605c55B7f65328Fdd5Cc7c485679Bc0")

// statementAuthLen is the length of a STATEMENT authorization.
const statementAuthLen = 92

// LeanSphincsTag is the tag of a leanSPHINCS STATEMENT actor, whose vk is the signature program's
// and whose key is the public key: its statement over a hash is the signature's member.
var LeanSphincsTag = [8]byte{'s', 'p', 'h', 'm', 'e', 'm', '0', '1'}

// StatementAuthorization returns the STATEMENT authorization of the actor (vk, tag, key):
// StatementAuthenticator || vk || tag || key, like op-alloy's StatementActor::encode.
func StatementAuthorization(vk common.Hash, tag [8]byte, key common.Hash) []byte {
	return slices.Concat(StatementAuthenticator.Bytes(), vk[:], tag[:], key[:])
}

// StatementDependency returns the dependency a STATEMENT authorization auth adds for hash, or
// false if auth is not one.
func StatementDependency(auth []byte, hash common.Hash) (Dependency, bool) {
	if !isStatementAuthorization(auth) {
		return Dependency{}, false
	}
	// auth[52:] is tag || key.
	return Dependency{
		Scheme:              ProofStatementScheme,
		DataHash:            blake2s.Sum256(slices.Concat(auth[52:], hash[:])),
		VerificationKeyHash: common.BytesToHash(auth[20:52]),
	}, true
}

func isStatementAuthorization(auth []byte) bool {
	return len(auth) == statementAuthLen && common.BytesToAddress(auth[:20]) == StatementAuthenticator
}

// authorizationDependencies returns the dependencies of the STATEMENT authorizations: a named
// sender's over the sender hash, and a named payer's of a named sender over the payer hash.
func (tx *AaTx) authorizationDependencies() []Dependency {
	if tx.Sender == nil {
		return nil
	}
	var deps []Dependency
	// The signing hashes are only computed for a STATEMENT authorization.
	if isStatementAuthorization(tx.SenderAuth) {
		dep, _ := StatementDependency(tx.SenderAuth, tx.SenderSignatureHash())
		deps = append(deps, dep)
	}
	if len(tx.Payer) == common.AddressLength && isStatementAuthorization(tx.PayerAuth) {
		dep, _ := StatementDependency(tx.PayerAuth, tx.PayerSignatureHash(*tx.Sender))
		deps = append(deps, dep)
	}
	return deps
}

// DependencyDeclarationCount returns the number of dependencies the transaction declares,
// duplicates included, each STATEMENT authorization counting as one.
func (tx *AaTx) DependencyDeclarationCount() int {
	return len(tx.declared()) + len(tx.authorizationDependencies())
}

// Dependencies returns the transaction's EIP-8288 dependencies, deduplicated and sorted: the
// declared ones, with a zero data hash replaced by the sender hash, and those of its STATEMENT
// authorizations, like op-alloy's TxEip8430::dependencies.
func (tx *AaTx) Dependencies() []Dependency {
	declared := tx.declared()
	auth := tx.authorizationDependencies()
	if len(declared) == 0 && len(auth) == 0 {
		return nil
	}
	deps := append(slices.Clone(declared), auth...)
	var senderHash *common.Hash
	for i := range declared {
		if deps[i].DataHash == (common.Hash{}) {
			if senderHash == nil {
				h := tx.SenderSignatureHash()
				senderHash = &h
			}
			deps[i].DataHash = *senderHash
		}
	}
	return sortDependencies(deps)
}

// sortDependencies sorts deps by scheme, data hash and verification key hash, and drops
// duplicates.
func sortDependencies(deps []Dependency) []Dependency {
	slices.SortFunc(deps, func(a, b Dependency) int {
		if a.Scheme != b.Scheme {
			return cmp.Compare(a.Scheme, b.Scheme)
		}
		if c := a.DataHash.Cmp(b.DataHash); c != 0 {
			return c
		}
		return a.VerificationKeyHash.Cmp(b.VerificationKeyHash)
	})
	return slices.Compact(deps)
}

type aaCallJSON struct {
	To    common.Address `json:"to"`
	Value *hexutil.Big   `json:"value"`
	Data  hexutil.Bytes  `json:"data"`
}

type aaDependencyJSON struct {
	Scheme              hexutil.Uint64 `json:"scheme"`
	DataHash            common.Hash    `json:"dataHash"`
	VerificationKeyHash common.Hash    `json:"verificationKeyHash"`
}

type aaAccountChangeJSON struct {
	Type         hexutil.Uint64      `json:"type"`
	Target       *common.Address     `json:"target,omitempty"`
	Dependencies *[]aaDependencyJSON `json:"dependencies,omitempty"`
}

// aaTxJSON is the RPC transaction object op-reth serves for an EIP-8430 transaction.
type aaTxJSON struct {
	Type                 hexutil.Uint64        `json:"type"`
	Hash                 common.Hash           `json:"hash"`
	ChainID              hexutil.Uint64        `json:"chainId"`
	Sender               *common.Address       `json:"sender"`
	NonceKey             *hexutil.Big          `json:"nonceKey"`
	Nonce                hexutil.Uint64        `json:"nonce"`
	ValidAfter           hexutil.Uint64        `json:"validAfter"`
	ValidBefore          hexutil.Uint64        `json:"validBefore"`
	MaxPriorityFeePerGas *hexutil.Big          `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *hexutil.Big          `json:"maxFeePerGas"`
	Gas                  hexutil.Uint64        `json:"gas"`
	AccountChanges       []aaAccountChangeJSON `json:"accountChanges"`
	Calls                [][]aaCallJSON        `json:"calls"`
	Metadata             hexutil.Bytes         `json:"metadata"`
	Payer                hexutil.Bytes         `json:"payer"`
	SenderAuth           hexutil.Bytes         `json:"senderAuth"`
	PayerAuth            hexutil.Bytes         `json:"payerAuth"`
}

// MarshalJSON encodes the transaction in the RPC transaction format op-reth serves, including the
// transaction hash.
func (tx *AaTx) MarshalJSON() ([]byte, error) {
	enc := aaTxJSON{
		Type:                 AaTxType,
		Hash:                 tx.Hash(),
		ChainID:              hexutil.Uint64(tx.ChainID),
		Sender:               tx.Sender,
		NonceKey:             bigOrZero(tx.NonceKey),
		Nonce:                hexutil.Uint64(tx.NonceSequence),
		ValidAfter:           hexutil.Uint64(tx.ValidAfter),
		ValidBefore:          hexutil.Uint64(tx.ValidBefore),
		MaxPriorityFeePerGas: bigOrZero(tx.MaxPriorityFeePerGas),
		MaxFeePerGas:         bigOrZero(tx.MaxFeePerGas),
		Gas:                  hexutil.Uint64(tx.GasLimit),
		AccountChanges:       make([]aaAccountChangeJSON, len(tx.AccountChanges)),
		Calls:                make([][]aaCallJSON, len(tx.Calls)),
		Metadata:             tx.Metadata,
		Payer:                tx.Payer,
		SenderAuth:           tx.SenderAuth,
		PayerAuth:            tx.PayerAuth,
	}
	for i, change := range tx.AccountChanges {
		enc.AccountChanges[i].Type = hexutil.Uint64(change.Type)
		switch change.Type {
		case AccountChangeDelegation:
			target := change.Target
			enc.AccountChanges[i].Target = &target
		case AccountChangeDependencies:
			deps := make([]aaDependencyJSON, len(change.Dependencies))
			for j, d := range change.Dependencies {
				deps[j] = aaDependencyJSON{hexutil.Uint64(d.Scheme), d.DataHash, d.VerificationKeyHash}
			}
			enc.AccountChanges[i].Dependencies = &deps
		default:
			return nil, fmt.Errorf("unknown account change type %#x", change.Type)
		}
	}
	for i, phase := range tx.Calls {
		enc.Calls[i] = make([]aaCallJSON, len(phase))
		for j, call := range phase {
			enc.Calls[i][j] = aaCallJSON{To: call.To, Value: bigOrZero(call.Value), Data: call.Data}
		}
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON decodes a transaction from the RPC transaction format op-reth serves. The hash is
// required and must match the decoded transaction's, so a field the object lacks cannot silently
// decode as its zero value.
func (tx *AaTx) UnmarshalJSON(input []byte) error {
	var dec aaTxJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Hash == (common.Hash{}) {
		return errors.New("missing required field 'hash' in EIP-8430 transaction")
	}
	if dec.Type != AaTxType {
		return fmt.Errorf("EIP-8430 transaction has type %#x", uint64(dec.Type))
	}
	out := AaTx{
		ChainID:        uint64(dec.ChainID),
		Sender:         dec.Sender,
		NonceSequence:  uint64(dec.Nonce),
		ValidAfter:     uint64(dec.ValidAfter),
		ValidBefore:    uint64(dec.ValidBefore),
		GasLimit:       uint64(dec.Gas),
		AccountChanges: make([]AccountChange, len(dec.AccountChanges)),
		Calls:          make([][]AaCall, len(dec.Calls)),
		Metadata:       dec.Metadata,
		Payer:          dec.Payer,
		SenderAuth:     dec.SenderAuth,
		PayerAuth:      dec.PayerAuth,
	}
	var err error
	if out.NonceKey, err = requiredBig(dec.NonceKey, "nonceKey"); err != nil {
		return err
	}
	if out.MaxPriorityFeePerGas, err = requiredBig(dec.MaxPriorityFeePerGas, "maxPriorityFeePerGas"); err != nil {
		return err
	}
	if out.MaxFeePerGas, err = requiredBig(dec.MaxFeePerGas, "maxFeePerGas"); err != nil {
		return err
	}
	for i, change := range dec.AccountChanges {
		typ, err := byteField(change.Type, "account change type")
		if err != nil {
			return err
		}
		switch {
		case typ == AccountChangeDelegation && change.Target != nil && change.Dependencies == nil:
			out.AccountChanges[i] = AccountChange{Type: typ, Target: *change.Target}
		case typ == AccountChangeDependencies && change.Target == nil && change.Dependencies != nil:
			deps := make([]Dependency, len(*change.Dependencies))
			for j, d := range *change.Dependencies {
				scheme, err := byteField(d.Scheme, "dependency scheme")
				if err != nil {
					return err
				}
				deps[j] = Dependency{Scheme: scheme, DataHash: d.DataHash, VerificationKeyHash: d.VerificationKeyHash}
			}
			out.AccountChanges[i] = AccountChange{Type: typ, Dependencies: deps}
		default:
			return fmt.Errorf("unknown or malformed account change %d", i)
		}
	}
	for i, phase := range dec.Calls {
		out.Calls[i] = make([]AaCall, len(phase))
		for j, call := range phase {
			value, err := requiredBig(call.Value, "value")
			if err != nil {
				return err
			}
			out.Calls[i][j] = AaCall{To: call.To, Value: value, Data: call.Data}
		}
	}
	if err := out.checkFieldRanges(); err != nil {
		return err
	}
	if dec.Hash != out.Hash() {
		return fmt.Errorf("EIP-8430 transaction hash %s does not match its fields (%s)", dec.Hash, out.Hash())
	}
	*tx = out
	return nil
}

func bigOrZero(v *big.Int) *hexutil.Big {
	if v == nil {
		return (*hexutil.Big)(new(big.Int))
	}
	return (*hexutil.Big)(v)
}

func requiredBig(v *hexutil.Big, name string) (*big.Int, error) {
	if v == nil {
		return nil, fmt.Errorf("missing required field '%s' in transaction", name)
	}
	return (*big.Int)(v), nil
}

func byteField(v hexutil.Uint64, name string) (uint8, error) {
	if v > 0xff {
		return 0, fmt.Errorf("transaction %s %#x does not fit a byte", name, uint64(v))
	}
	return uint8(v), nil
}
