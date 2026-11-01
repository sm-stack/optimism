package derive

import (
	"bytes"
	"io"

	"github.com/ethereum/go-ethereum/rlp"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-service/log"
)

// ProofAggregateBatch is a proof aggregate the batcher posts in a channel, as kona's
// Batch::ProofAggregate. Its payload must decode exactly, with no trailing bytes.
type ProofAggregateBatch struct {
	Payload optypes.ProofAggregatePayload
}

var (
	_ Batch          = (*ProofAggregateBatch)(nil)
	_ InnerBatchData = (*ProofAggregateBatch)(nil)
)

func (b *ProofAggregateBatch) GetBatchType() int { return ProofAggregateBatchType }

// GetTimestamp returns 0: a proof aggregate belongs to no L2 block.
func (b *ProofAggregateBatch) GetTimestamp() uint64 { return 0 }

func (b *ProofAggregateBatch) AsSingularBatch() (*SingularBatch, bool) { return nil, false }
func (b *ProofAggregateBatch) AsSpanBatch() (*SpanBatch, bool)         { return nil, false }

func (b *ProofAggregateBatch) LogContext(l log.Logger) log.Logger {
	return l.New("batch_type", "ProofAggregateBatch", "through", b.Payload.Through, "statements", len(b.Payload.Statements))
}

func (b *ProofAggregateBatch) encode(w io.Writer) error {
	return rlp.Encode(w, &b.Payload)
}

func (b *ProofAggregateBatch) decode(r *bytes.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	payload, err := optypes.DecodeProofAggregatePayload(data)
	if err != nil {
		return err
	}
	b.Payload = *payload
	return nil
}

// asProofAggregateBatch returns the proof aggregate a channel reader returned, if it is one.
func asProofAggregateBatch(batch Batch) (*ProofAggregateBatch, bool) {
	if b, ok := batch.(batchWithMetadata); ok {
		batch = b.Batch
	}
	aggregate, ok := batch.(*ProofAggregateBatch)
	return aggregate, ok
}
