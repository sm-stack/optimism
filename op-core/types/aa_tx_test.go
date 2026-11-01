package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

// goldenAaTxRaw is op-alloy's golden EIP-8430 transaction (`aa::tests::golden`), the same bytes
// the kona and op-node span batch tests carry.
const goldenAaTxRaw = "0x79f901f38203859411111111111111111111111111111111111111118003846553f10086018bcfee8fc0830f424084773594008303d090f8a6d60194dedededededededededededededededededededef88d04f88af84320a00000000000000000000000000000000000000000000000000000000000000000a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf84320a0dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddda0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf850dcdb9422222222222222222222222222222222222222228203e882deadf2d79433333333333333333333333333333333333333338080d99444444444444444444444444444444444444444448082beef826f70945555555555555555555555555555555555555555b85500000000000000000000000000000000000000016666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666b85500000000000000000000000000000000000000017777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"

// goldenAaTxJSON is the RPC transaction object op-reth serves for goldenAaTxRaw
// (`aa::tests::golden_rpc_json`).
const goldenAaTxJSON = `{"type":"0x79","hash":"0x41e6de04bc5d0e7448d620643c8d9d1f6f9f2a035eb6e841099f32482c243433","chainId":"0x385","sender":"0x1111111111111111111111111111111111111111","nonceKey":"0x0","nonce":"0x3","validAfter":"0x6553f100","validBefore":"0x18bcfee8fc0","maxPriorityFeePerGas":"0xf4240","maxFeePerGas":"0x77359400","gas":"0x3d090","accountChanges":[{"type":"0x1","target":"0xdededededededededededededededededededede"},{"type":"0x4","dependencies":[{"scheme":"0x20","dataHash":"0x0000000000000000000000000000000000000000000000000000000000000000","verificationKeyHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"scheme":"0x20","dataHash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","verificationKeyHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}],"calls":[[{"to":"0x2222222222222222222222222222222222222222","value":"0x3e8","data":"0xdead"}],[{"to":"0x3333333333333333333333333333333333333333","value":"0x0","data":"0x"},{"to":"0x4444444444444444444444444444444444444444","value":"0x0","data":"0xbeef"}]],"metadata":"0x6f70","payer":"0x5555555555555555555555555555555555555555","senderAuth":"0x00000000000000000000000000000000000000016666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666","payerAuth":"0x00000000000000000000000000000000000000017777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"}`

func repeatAddress(b byte) common.Address {
	return common.BytesToAddress(bytes.Repeat([]byte{b}, common.AddressLength))
}

func repeatHash(b byte) common.Hash {
	return common.BytesToHash(bytes.Repeat([]byte{b}, common.HashLength))
}

func goldenAaTx() *AaTx {
	sender := repeatAddress(0x11)
	k1 := common.BytesToAddress([]byte{1}).Bytes()
	return &AaTx{
		ChainID:              901,
		Sender:               &sender,
		NonceKey:             new(big.Int),
		NonceSequence:        3,
		ValidAfter:           1_700_000_000,
		ValidBefore:          1_700_000_600_000,
		MaxPriorityFeePerGas: big.NewInt(1_000_000),
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		GasLimit:             250_000,
		AccountChanges: []AccountChange{
			{Type: AccountChangeDelegation, Target: repeatAddress(0xde)},
			{Type: AccountChangeDependencies, Dependencies: []Dependency{
				{Scheme: ProofStatementScheme, VerificationKeyHash: repeatHash(0xaa)},
				{Scheme: ProofStatementScheme, DataHash: repeatHash(0xdd), VerificationKeyHash: repeatHash(0xaa)},
			}},
		},
		Calls: [][]AaCall{
			{{To: repeatAddress(0x22), Value: big.NewInt(1_000), Data: []byte{0xde, 0xad}}},
			{
				{To: repeatAddress(0x33), Value: new(big.Int)},
				{To: repeatAddress(0x44), Value: new(big.Int), Data: []byte{0xbe, 0xef}},
			},
		},
		Metadata:   []byte("op"),
		Payer:      repeatAddress(0x55).Bytes(),
		SenderAuth: append(append([]byte{}, k1...), bytes.Repeat([]byte{0x66}, 65)...),
		PayerAuth:  append(append([]byte{}, k1...), bytes.Repeat([]byte{0x77}, 65)...),
	}
}

// TestAaTxGoldenVector pins the encoding, hashes and dependencies of op-alloy's golden EIP-8430
// transaction (`aa::tests::golden_vector`).
func TestAaTxGoldenVector(t *testing.T) {
	tx := goldenAaTx()
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, goldenAaTxRaw, hexutil.Encode(raw))
	require.Equal(t, common.HexToHash("0x41e6de04bc5d0e7448d620643c8d9d1f6f9f2a035eb6e841099f32482c243433"), tx.Hash())
	senderHash := common.HexToHash("0x9d9a2c330a234279bf45099bf8283fd2a872c853c69f26040b565340d15472ed")
	require.Equal(t, senderHash, tx.SenderSignatureHash())
	require.Equal(t, common.HexToHash("0x07f9d695fece3c6dad9df587790a2439fd142e82268cbd47cb64cbb98ad6fc45"),
		tx.PayerSignatureHash(repeatAddress(0x11)))

	decoded, err := UnmarshalAaTx(raw)
	require.NoError(t, err)
	reencoded, err := decoded.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, raw, reencoded)

	want := []Dependency{
		{Scheme: ProofStatementScheme, DataHash: senderHash, VerificationKeyHash: repeatHash(0xaa)},
		{Scheme: ProofStatementScheme, DataHash: repeatHash(0xdd), VerificationKeyHash: repeatHash(0xaa)},
	}
	require.Equal(t, want, decoded.Dependencies())
	require.Equal(t, 2, decoded.DependencyDeclarationCount())
	deps, ok := DeclaredDependencies(raw)
	require.True(t, ok)
	require.Equal(t, want, deps)
}

func TestAaTxRPCJSON(t *testing.T) {
	encoded, err := json.Marshal(goldenAaTx())
	require.NoError(t, err)
	require.JSONEq(t, goldenAaTxJSON, string(encoded))

	var decoded AaTx
	require.NoError(t, json.Unmarshal([]byte(goldenAaTxJSON), &decoded))
	raw, err := decoded.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, goldenAaTxRaw, hexutil.Encode(raw))

	tampered := bytes.Replace([]byte(goldenAaTxJSON), []byte(`"nonce":"0x3"`), []byte(`"nonce":"0x4"`), 1)
	require.ErrorContains(t, json.Unmarshal(tampered, &decoded), "does not match its fields")
}

// The lenient decoder reads the first RLP value like op-alloy's decode_2718; the strict one
// requires the input to end there.
func TestAaTxDecodersOnTrailingBytes(t *testing.T) {
	raw := append(hexutil.MustDecode(goldenAaTxRaw), 0x01)
	_, err := UnmarshalAaTx(raw)
	require.Error(t, err)
	tx, err := DecodeAaTxLenient(raw)
	require.NoError(t, err)
	require.Equal(t, goldenAaTx().Hash(), tx.Hash())
}

func TestAaTxRejectsWhatOpAlloyRejects(t *testing.T) {
	encode := func(mutate func(*AaTx)) []byte {
		tx := goldenAaTx()
		mutate(tx)
		raw, err := tx.MarshalBinary()
		require.NoError(t, err)
		return raw
	}
	for name, raw := range map[string][]byte{
		"payer of two bytes":  encode(func(tx *AaTx) { tx.Payer = []byte{0, 1} }),
		"payer byte not zero": encode(func(tx *AaTx) { tx.Payer = []byte{1} }),
		"fee over u128":       encode(func(tx *AaTx) { tx.MaxFeePerGas = new(big.Int).Lsh(big.NewInt(1), 128) }),
	} {
		_, err := UnmarshalAaTx(raw)
		require.Error(t, err, name)
		_, ok := DeclaredDependencies(raw)
		require.False(t, ok, name)
	}

	// No dependency entry: it decodes and declares nothing.
	none := encode(func(tx *AaTx) { tx.AccountChanges = tx.AccountChanges[:1] })
	_, err := UnmarshalAaTx(none)
	require.NoError(t, err)
	_, ok := DeclaredDependencies(none)
	require.False(t, ok, "no dependency entry")

	// Account change entries op-alloy rejects: an unknown type, and a known one with an extra
	// field.
	for name, entry := range map[string][]any{
		"unknown type":            {uint8(0x02), repeatAddress(0xde)},
		"delegation extra field":  {uint8(AccountChangeDelegation), repeatAddress(0xde), uint8(1)},
		"dependency missing hash": {uint8(AccountChangeDependencies), []any{[]any{uint8(0x20), repeatHash(1)}}},
	} {
		entryRaw, err := rlp.EncodeToBytes(entry)
		require.NoError(t, err)
		tx := goldenAaTx()
		fields := []any{tx.ChainID, tx.Sender, tx.NonceKey, tx.NonceSequence, tx.ValidAfter, tx.ValidBefore,
			tx.MaxPriorityFeePerGas, tx.MaxFeePerGas, tx.GasLimit, []rlp.RawValue{entryRaw}, tx.Calls,
			tx.Metadata, tx.Payer, tx.SenderAuth, tx.PayerAuth}
		body, err := rlp.EncodeToBytes(fields)
		require.NoError(t, err)
		_, err = UnmarshalAaTx(append([]byte{AaTxType}, body...))
		require.Error(t, err, name)
	}
}

// TestAaReceiptGoldenVector pins op-alloy's golden EIP-8430 receipt (`receipts::aa::tests::golden_vector`)
// through the consensus codec and the receipts-root encoding.
func TestAaReceiptGoldenVector(t *testing.T) {
	raw := hexutil.MustDecode("0x79f901470183015f90b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000008000000000000000000000000000000002000000000000000000000000000000000000000000000000f83cf83a941111111111111111111111111111111111111111e1a0222222222222222222222222222222222222222222222222222222222222222282dead02")
	var r Receipt
	require.NoError(t, r.UnmarshalBinary(raw))
	require.Equal(t, uint8(AaTxType), r.Type)
	require.Equal(t, types.ReceiptStatusSuccessful, r.Status)
	require.Equal(t, uint64(90_000), r.CumulativeGasUsed)
	require.Equal(t, uint64(2), *r.CommittedPhases)
	require.Len(t, r.Logs, 1)

	encoded, err := r.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, raw, encoded)
	var buf bytes.Buffer
	Receipts{&r}.EncodeIndex(0, &buf)
	require.Equal(t, raw, buf.Bytes())

	payer := repeatAddress(0x55)
	r.Payer = &payer
	obj, err := json.Marshal(r)
	require.NoError(t, err)
	var back Receipt
	require.NoError(t, json.Unmarshal(obj, &back))
	require.Equal(t, uint64(2), *back.CommittedPhases)
	require.Equal(t, payer, *back.Payer)
	// The payer is RPC-only: the consensus encoding is unchanged.
	encoded, err = back.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, raw, encoded)

	// Without its phase count a 0x79 receipt has no encoding.
	r.CommittedPhases = nil
	_, err = r.MarshalBinary()
	require.Error(t, err)
}

// A short account change entry must not end account_changes early: op-alloy rejects the
// transaction, so Go's decoders must too, or op-node's dependency gate would read dependencies
// kona does not see.
func TestAaTxShortAccountChangeDoesNotEndTheList(t *testing.T) {
	tx := goldenAaTx()
	depEntry, err := rlp.EncodeToBytes(&tx.AccountChanges[1])
	require.NoError(t, err)
	for name, short := range map[string][]byte{
		"empty entry":               {0xc0},
		"delegation without target": {0xc1, 0x01},
		"dependencies without list": {0xc1, 0x04},
	} {
		// The transaction's later fields sit inside account_changes, after the short entry.
		inner := []any{rlp.RawValue(depEntry), rlp.RawValue(short), tx.Calls, tx.Metadata, tx.Payer,
			tx.SenderAuth, tx.PayerAuth}
		fields := []any{tx.ChainID, tx.Sender, tx.NonceKey, tx.NonceSequence, tx.ValidAfter,
			tx.ValidBefore, tx.MaxPriorityFeePerGas, tx.MaxFeePerGas, tx.GasLimit, inner}
		body, err := rlp.EncodeToBytes(fields)
		require.NoError(t, err)
		raw := append([]byte{AaTxType}, body...)
		_, err = UnmarshalAaTx(raw)
		require.Error(t, err, name)
		_, err = DecodeAaTxLenient(raw)
		require.Error(t, err, name)
		_, ok := DeclaredDependencies(raw)
		require.False(t, ok, name)
	}
}

// A leanSPHINCS actor's statement over a message is the signature's member (op-leanvm-tree's signature-0 fixture;
// op-alloy: a_statement_is_the_signature_member).
func TestStatementDependencyIsTheSignatureMember(t *testing.T) {
	vk := common.Hash{9}
	auth := StatementAuthorization(vk, LeanSphincsTag,
		common.HexToHash("0xbb9ca6c2f8bc2cb914968c8ecb5a5b3c9d70d9199b842cde14b0726cf4d56991"))
	message := common.HexToHash("0x0000000000000000010000000000000002000000000000000300000000000000")
	dep, ok := StatementDependency(auth, message)
	require.True(t, ok)
	require.Equal(t, Dependency{
		Scheme:              ProofStatementScheme,
		DataHash:            common.HexToHash("0x4142422d4bcba7a3640cbe9ae6f13998a76d99373b946218926ef6299b8534e0"),
		VerificationKeyHash: vk,
	}, dep)
	_, ok = StatementDependency(auth[:91], message)
	require.False(t, ok)
}
