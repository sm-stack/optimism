package rollup

// This file contains ephemeral feature toggles for the next
// fork while it is in development. They should be removed
// after the fork scope is locked.

// Example:
// func (c *Config) IsMinBaseFee(time uint64) bool {
// 	return c.IsJovian(time) // Replace with return false to disable
// }

// IsL2CM gates the L2 Contracts Manager upgrade transactions at the Karst fork.
// Replace with return false to disable NUT bundle execution during development.
func (c *Config) IsL2CM(time uint64) bool {
	return c.IsKarst(time)
}

// IsL2CMActivationBlock returns true only at the exact activation block.
func (c *Config) IsL2CMActivationBlock(l2BlockTime uint64) bool {
	if !c.IsL2CM(l2BlockTime) {
		return false
	}
	return c.IsKarstActivationBlock(l2BlockTime)
}

// IsSDM gates Sequencer-Defined Metering: when false, batches carrying PostExec
// transactions are rejected during derivation. Defers to the hardfork where SDM is activated.
func (c *Config) IsSDM(time uint64) bool {
	return c.IsLagoon(time)
}

// IsProofAggregation gates proof aggregation: when false, a proof aggregate batch is an unknown
// batch type and ends its channel during derivation. Defers to the hardfork where the feature is
// activated, matching op-reth's `is_proof_aggregation_active_at_timestamp` and kona's
// `is_proof_aggregation_active`.
func (c *Config) IsProofAggregation(time uint64) bool {
	return c.IsLagoon(time)
}

// IsAaTx gates EIP-8430 transactions: when false, batches carrying EIP-8430 (0x79) transactions
// are rejected during derivation. Defers to Lagoon, the fork at which op-reth executes them,
// matching op-reth's `is_aa_tx_active_at_timestamp` and kona's `is_aa_tx_active`.
func (c *Config) IsAaTx(time uint64) bool {
	return c.IsLagoon(time)
}

// IsInterop returns true if the interoperability feature is active at or past the given timestamp.
// The feature defers to the hardfork where interop is activated; this toggle exists so the feature
// can be decoupled from the fork if needed.
func (c *Config) IsInterop(timestamp uint64) bool {
	return c.IsLagoon(timestamp)
}

// IsInteropActivationBlock returns true if the given block timestamp is the first block at which interop is active.
func (c *Config) IsInteropActivationBlock(l2BlockTime uint64) bool {
	if !c.IsInterop(l2BlockTime) {
		return false
	}
	return c.IsLagoonActivationBlock(l2BlockTime)
}
