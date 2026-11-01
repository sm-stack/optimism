package types

import "github.com/ethereum/go-ethereum/common"

// ProofStatementScheme is the EIP-8288 dependency scheme of a proof statement: data_hash is a member
// a leanVM leaf published and verification_key_hash the digest of the verifying key of the guest
// that ran, normalized to its leaf class. It must equal op-alloy's PROOF_STATEMENT_SCHEME.
const ProofStatementScheme = 0x20

// Dependency is one EIP-8288 dependency a transaction declares.
type Dependency struct {
	Scheme              uint8
	DataHash            common.Hash
	VerificationKeyHash common.Hash
}

// Statement returns the statement the dependency asks to be proven, or false for another scheme.
func (d Dependency) Statement() (ProofStatement, bool) {
	if d.Scheme != ProofStatementScheme {
		return ProofStatement{}, false
	}
	return ProofStatement{VkeyHash: d.VerificationKeyHash, PublicValuesDigest: d.DataHash}, true
}

// DeclaredDependencies returns the EIP-8288 dependencies the EIP-2718 transaction raw declares,
// deduplicated and sorted, as op-alloy's declared_dependencies reads them, or false if it declares
// none: a type that cannot, one that does not, or bytes that do not decode as such a type.
func DeclaredDependencies(raw []byte) ([]Dependency, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	switch raw[0] {
	case AaTxType:
		tx, err := DecodeAaTxLenient(raw)
		if err != nil {
			return nil, false
		}
		// Dependencies is nil exactly when the transaction declares none.
		deps := tx.Dependencies()
		return deps, deps != nil
	default:
		return nil, false
	}
}
