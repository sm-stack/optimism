//! Receipts of [EIP-8430] transactions: `rlp([status, cumulative_gas_used, logs_bloom, logs,
//! committed_phases])`, an [EIP-1559] receipt with the number of phases that committed.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
//! [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559

use alloc::vec::Vec;
use alloy_consensus::{Eip658Value, Receipt, ReceiptWithBloom, TxReceipt};
use alloy_primitives::{Bloom, Log};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// The receipt of an [EIP-8430] transaction.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OpAaReceipt<T = Log> {
    /// Status, cumulative gas and the logs of the committed phases. The status is success exactly
    /// when every phase committed.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Receipt<T>,
    /// The number of phases that committed: phases run in order and stop at the first revert.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub committed_phases: u64,
}

impl<T> OpAaReceipt<T> {
    /// Converts the log type.
    pub fn map_logs<U>(self, f: impl FnMut(T) -> U) -> OpAaReceipt<U> {
        OpAaReceipt { inner: self.inner.map_logs(f), committed_phases: self.committed_phases }
    }
}

impl<T: Encodable> OpAaReceipt<T> {
    /// Length of the receipt's RLP fields with `bloom`, without the outer list header.
    pub fn rlp_encoded_fields_length_with_bloom(&self, bloom: &Bloom) -> usize {
        self.inner.rlp_encoded_fields_length_with_bloom(bloom) + self.committed_phases.length()
    }

    /// RLP-encodes the receipt's fields with `bloom`, without the outer list header.
    pub fn rlp_encode_fields_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        self.inner.rlp_encode_fields_with_bloom(bloom, out);
        self.committed_phases.encode(out);
    }

    /// The outer RLP list header with `bloom`.
    pub fn rlp_header_with_bloom(&self, bloom: &Bloom) -> Header {
        Header { list: true, payload_length: self.rlp_encoded_fields_length_with_bloom(bloom) }
    }
}

impl<T: Decodable> OpAaReceipt<T> {
    /// Decodes the receipt and its bloom, outer list header included.
    pub fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let (mut body, rest) =
            buf.split_at_checked(header.payload_length).ok_or(alloy_rlp::Error::InputTooShort)?;
        let status = Eip658Value::decode(&mut body)?;
        let cumulative_gas_used = u64::decode(&mut body)?;
        let logs_bloom = Bloom::decode(&mut body)?;
        let logs = Vec::<T>::decode(&mut body)?;
        let committed_phases = u64::decode(&mut body)?;
        if !body.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        *buf = rest;
        Ok(ReceiptWithBloom {
            receipt: Self {
                inner: Receipt { status, cumulative_gas_used, logs },
                committed_phases,
            },
            logs_bloom,
        })
    }
}

impl<T> TxReceipt for OpAaReceipt<T>
where
    T: AsRef<Log> + Clone + core::fmt::Debug + PartialEq + Eq + Send + Sync,
{
    type Log = T;

    fn status_or_post_state(&self) -> Eip658Value {
        self.inner.status_or_post_state()
    }

    fn status(&self) -> bool {
        self.inner.status()
    }

    fn bloom(&self) -> Bloom {
        self.inner.bloom_slow()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.inner.cumulative_gas_used()
    }

    fn logs(&self) -> &[Self::Log] {
        self.inner.logs()
    }

    fn into_logs(self) -> Vec<Self::Log> {
        self.inner.logs
    }
}

impl<T: Encodable> alloy_consensus::RlpEncodableReceipt for OpAaReceipt<T> {
    fn rlp_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        self.rlp_header_with_bloom(bloom).length_with_payload()
    }

    fn rlp_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        self.rlp_header_with_bloom(bloom).encode(out);
        self.rlp_encode_fields_with_bloom(bloom, out);
    }
}

impl<T> alloy_consensus::RlpDecodableReceipt for OpAaReceipt<T>
where
    T: Decodable + AsRef<Log>,
{
    fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        Self::rlp_decode_with_bloom(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::RlpEncodableReceipt;
    use alloy_primitives::{Address, Bytes, LogData};

    #[test]
    fn round_trips_with_its_committed_phases() {
        let log = Log {
            address: Address::repeat_byte(1),
            data: LogData::new_unchecked(vec![], Bytes::from_static(&[7])),
        };
        let receipt = OpAaReceipt {
            inner: Receipt { status: false.into(), cumulative_gas_used: 90_000, logs: vec![log] },
            committed_phases: 2,
        };
        let bloom = receipt.inner.bloom_slow();
        let mut buf = Vec::new();
        receipt.rlp_encode_with_bloom(&bloom, &mut buf);
        assert_eq!(buf.len(), receipt.rlp_encoded_length_with_bloom(&bloom));
        let decoded = OpAaReceipt::<Log>::rlp_decode_with_bloom(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, ReceiptWithBloom { receipt, logs_bloom: bloom });
    }

    /// Golden vector shared with op-core (`TestAaReceiptGoldenVector`).
    #[test]
    fn golden_vector() {
        use alloy_eips::{Decodable2718, Encodable2718};
        let log = Log {
            address: Address::repeat_byte(0x11),
            data: LogData::new_unchecked(
                vec![alloy_primitives::B256::repeat_byte(0x22)],
                Bytes::from_static(&[0xde, 0xad]),
            ),
        };
        let receipt = OpAaReceipt {
            inner: Receipt { status: true.into(), cumulative_gas_used: 90_000, logs: vec![log] },
            committed_phases: 2,
        };
        let logs_bloom = receipt.inner.bloom_slow();
        let env = crate::OpReceiptEnvelope::Aa(ReceiptWithBloom { receipt, logs_bloom });
        let raw = env.encoded_2718();
        assert_eq!(alloy_primitives::hex::encode(&raw), GOLDEN_RAW);
        assert_eq!(crate::OpReceiptEnvelope::decode_2718(&mut raw.as_slice()).unwrap(), env);
    }

    /// [EIP-2718] encoding of the golden receipt: status 1, 90,000 gas, one log, two committed
    /// phases.
    ///
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    const GOLDEN_RAW: &str = "79f901470183015f90b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000008000000000000000000000000000000002000000000000000000000000000000000000000000000000f83cf83a941111111111111111111111111111111111111111e1a0222222222222222222222222222222222222222222222222222222222222222282dead02";
}
