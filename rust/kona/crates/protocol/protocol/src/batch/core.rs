//! Module containing the core [`Batch`] enum.

use crate::{
    BatchDecodingError, BatchEncodingError, BatchType, RawSpanBatch, SingleBatch, SpanBatch,
};
use alloy_primitives::bytes;
use alloy_rlp::{Buf, Decodable, Encodable};
use kona_genesis::RollupConfig;
use op_alloy_consensus::ProofAggregatePayload;

/// A Batch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Batch {
    /// A single batch
    Single(SingleBatch),
    /// Span Batches
    Span(SpanBatch),
    /// A proof aggregate, from Lagoon. It produces no L2 block: derivation's dependency scanner
    /// reads it, and the rest of the pipeline skips it.
    ProofAggregate(ProofAggregatePayload),
}

impl core::fmt::Display for Batch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Single(_) => write!(f, "single"),
            Self::Span(_) => write!(f, "span"),
            Self::ProofAggregate(_) => write!(f, "proof aggregate"),
        }
    }
}

impl Batch {
    /// Returns the timestamp for the batch: 0 for a proof aggregate, which belongs to no block.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Single(sb) => sb.timestamp,
            Self::Span(sb) => sb.starting_timestamp(),
            Self::ProofAggregate(_) => 0,
        }
    }

    /// Attempts to decode a batch from a reader.
    pub fn decode(r: &mut &[u8], cfg: &RollupConfig) -> Result<Self, BatchDecodingError> {
        if r.is_empty() {
            return Err(BatchDecodingError::EmptyBuffer);
        }

        // Read the batch type
        let batch_type = BatchType::try_from(r[0]).map_err(BatchDecodingError::UnknownBatchType)?;
        r.advance(1);

        match batch_type {
            BatchType::Single => {
                let single_batch =
                    SingleBatch::decode(r).map_err(BatchDecodingError::AlloyRlpError)?;
                Ok(Self::Single(single_batch))
            }
            BatchType::Span => {
                let mut raw_span_batch = RawSpanBatch::decode(r)?;
                let span_batch = raw_span_batch
                    .derive(cfg.block_time, cfg.genesis.l2_time, cfg.l2_chain_id.id())
                    .map_err(BatchDecodingError::SpanBatchError)?;
                Ok(Self::Span(span_batch))
            }
            BatchType::ProofAggregate => {
                // The payload must decode exactly, with no trailing bytes.
                let payload = ProofAggregatePayload::from_rlp_bytes(r)
                    .map_err(BatchDecodingError::AlloyRlpError)?;
                r.advance(r.len());
                Ok(Self::ProofAggregate(payload))
            }
        }
    }

    /// Attempts to encode the batch to a writer.
    pub fn encode(&self, out: &mut dyn bytes::BufMut) -> Result<(), BatchEncodingError> {
        match self {
            Self::Single(sb) => {
                out.put_u8(BatchType::Single as u8);
                sb.encode(out);
            }
            Self::Span(sb) => {
                out.put_u8(BatchType::Span as u8);
                let raw_span_batch =
                    sb.to_raw_span_batch().map_err(BatchEncodingError::SpanBatchError)?;
                raw_span_batch.encode(out).map_err(BatchEncodingError::SpanBatchError)?;
            }
            Self::ProofAggregate(payload) => {
                out.put_u8(BatchType::ProofAggregate as u8);
                payload.encode(out);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpanBatchElement, SpanBatchError, SpanBatchTransactions};
    use alloc::{vec, vec::Vec};
    use alloy_consensus::{Signed, TxEip2930, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Bytes, Signature, TxKind, address, hex};

    /// Golden vector of a proof aggregate batch, shared with op-node's
    /// `TestProofAggregateBatchGoldenVector`: the type byte, then op-alloy's
    /// `payload_golden_vector`. Trailing bytes are rejected.
    #[test]
    fn test_proof_aggregate_batch_golden_vector() {
        let item = hex!(
            "02f86e0429a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0\
             1111111111111111111111111111111111111111111111111111111111111111a0\
             222222222222222222222222222222222222222222222222222222222222222284deadbeef"
        );
        let batch = Batch::ProofAggregate(ProofAggregatePayload {
            version: op_alloy_consensus::PROOF_AGGREGATE_PAYLOAD_VERSION,
            through: 41,
            aggregation_vkey_hash: alloy_primitives::B256::repeat_byte(0xaa),
            statements: vec![op_alloy_consensus::ProofStatement {
                vkey_hash: alloy_primitives::B256::repeat_byte(0x11),
                public_values_digest: alloy_primitives::B256::repeat_byte(0x22),
            }],
            proof: Bytes::from_static(&hex!("deadbeef")),
        });
        let mut out = Vec::new();
        batch.encode(&mut out).unwrap();
        assert_eq!(out, item);
        let cfg = RollupConfig::default();
        let mut reader = item.as_slice();
        assert_eq!(Batch::decode(&mut reader, &cfg).unwrap(), batch);
        assert!(reader.is_empty());

        let mut trailing = item.to_vec();
        trailing.push(0);
        assert!(Batch::decode(&mut trailing.as_slice(), &cfg).is_err());
    }

    #[test]
    fn test_single_batch_encode_decode() {
        let mut out = Vec::new();
        let batch = Batch::Single(SingleBatch::default());
        batch.encode(&mut out).unwrap();
        let decoded = Batch::decode(&mut out.as_slice(), &RollupConfig::default()).unwrap();
        assert_eq!(batch, decoded);
    }

    #[test]
    fn test_span_batch_encode_decode() {
        let sig = Signature::test_signature();
        let to = address!("0123456789012345678901234567890123456789");
        let tx = TxEnvelope::Eip2930(Signed::new_unchecked(
            TxEip2930 { to: TxKind::Call(to), chain_id: 1, ..Default::default() },
            sig,
            Default::default(),
        ));
        let mut span_batch_txs = SpanBatchTransactions::default();
        let mut buf = vec![];
        tx.encode_2718(&mut buf);
        let txs = vec![Bytes::from(buf)];
        let chain_id = 1;
        span_batch_txs.add_txs(txs, chain_id).unwrap();

        let mut out = Vec::new();
        let batch = Batch::Span(SpanBatch {
            block_tx_counts: vec![1],
            batches: vec![SpanBatchElement::default()],
            txs: span_batch_txs,
            ..Default::default()
        });
        batch.encode(&mut out).unwrap();
        let decoded = Batch::decode(&mut out.as_slice(), &RollupConfig::default()).unwrap();
        assert_eq!(Batch::Span(SpanBatch {
            batches: vec![SpanBatchElement {
                transactions: vec![hex!("01f85f808080809401234567890123456789012345678901234567898080c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1").into()],
                ..Default::default()
            }],
            txs: SpanBatchTransactions::default(),
            ..Default::default()
        }), decoded);
    }

    #[test]
    fn test_unknown_batch_type_returns_error() {
        let data = [0xFF, 0x00]; // unknown batch type 0xFF followed by dummy data
        let result = Batch::decode(&mut data.as_slice(), &RollupConfig::default());
        assert_eq!(result, Err(BatchDecodingError::UnknownBatchType(0xFF)));
    }

    #[test]
    fn test_empty_span_batch() {
        let mut out = Vec::new();
        let batch = Batch::Span(SpanBatch::default());
        // Fails to even encode an empty span batch - decoding will do the same
        let err = batch.encode(&mut out).unwrap_err();
        assert_eq!(BatchEncodingError::SpanBatchError(SpanBatchError::EmptySpanBatch), err);
    }
}
