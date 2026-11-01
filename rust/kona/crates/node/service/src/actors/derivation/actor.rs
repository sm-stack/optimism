//! [`NodeActor`] implementation for the derivation sub-routine.

use crate::{
    DerivationActorRequest, DerivationEngineClient, DerivationState, DerivationStateMachine,
    DerivationStateTransitionError, DerivationStateUpdate, Metrics, NodeActor,
    actors::derivation::L2Finalizer,
};
use async_trait::async_trait;
use kona_derive::{
    ActivationSignal, Pipeline, PipelineError, PipelineErrorKind, ResetError, Signal,
    SignalReceiver, StepResult,
};
use kona_engine::FinalizeBlockId;
use kona_protocol::{BlockInfo, OpAttributesWithParent};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

/// The [`NodeActor`] for the derivation sub-routine.
///
/// This actor is responsible for receiving messages from [`NodeActor`]s and stepping the
/// derivation pipeline forward to produce new payload attributes. The actor then sends the payload
/// to the [`NodeActor`] responsible for the execution sub-routine.
#[derive(Debug)]
pub struct DerivationActor<DerivationEngineClient_, PipelineSignalReceiver>
where
    DerivationEngineClient_: DerivationEngineClient,
    PipelineSignalReceiver: Pipeline + SignalReceiver,
{
    /// The channel on which all inbound requests are received by the [`DerivationActor`].
    inbound_request_rx: mpsc::Receiver<DerivationActorRequest>,
    /// The Engine client used to interact with the engine.
    engine_client: DerivationEngineClient_,

    /// The derivation pipeline.
    pipeline: PipelineSignalReceiver,
    /// The state machine controlling when derivation can occur.
    derivation_state_machine: DerivationStateMachine,
    /// The [`L2Finalizer`] tracks derived L2 blocks awaiting finalization.
    pub(crate) finalizer: L2Finalizer,
    /// Publishes the pipeline's L1 origin, served as the sync status's `current_l1`. `None`
    /// until the pipeline has an origin, and again from a reset until the pipeline is reset onto
    /// its new origin.
    origin_tx: watch::Sender<Option<BlockInfo>>,
}

impl<DerivationEngineClient_, PipelineSignalReceiver>
    DerivationActor<DerivationEngineClient_, PipelineSignalReceiver>
where
    DerivationEngineClient_: DerivationEngineClient,
    PipelineSignalReceiver: Pipeline + SignalReceiver,
{
    /// Creates a new instance of the [`DerivationActor`].
    pub fn new(
        engine_client: DerivationEngineClient_,
        inbound_request_rx: mpsc::Receiver<DerivationActorRequest>,
        pipeline: PipelineSignalReceiver,
        origin_tx: watch::Sender<Option<BlockInfo>>,
    ) -> Self {
        Self {
            pipeline,
            inbound_request_rx,
            engine_client,
            derivation_state_machine: DerivationStateMachine::default(),
            finalizer: L2Finalizer::default(),
            origin_tx,
        }
    }

    /// Publishes `origin` as the L1 block derivation has reached. The pipeline reports the zero
    /// block before its first reset; that is published as `None`.
    fn publish_origin(&self, origin: Option<BlockInfo>) {
        self.origin_tx.send_replace(origin.filter(|origin| *origin != BlockInfo::default()));
    }

    /// Handles a [`Signal`] received over the derivation signal receiver channel.
    async fn signal(&mut self, signal: Signal) {
        if matches!(signal, Signal::Reset(_)) {
            // Clear the finalization queue on reset.
            self.finalizer.clear();
            // Like op-node, report no L1 progress until the pipeline is reset onto its new origin.
            self.publish_origin(None);
        }

        match self.pipeline.signal(signal).await {
            Ok(_) => {
                info!(target: "derivation", ?signal, "[SIGNAL] Executed Successfully");
                self.publish_origin(self.pipeline.origin());
            }
            Err(e) => {
                error!(target: "derivation", ?e, ?signal, "Failed to signal derivation pipeline")
            }
        }
    }

    /// Attempts to step the derivation pipeline forward as much as possible in order to produce the
    /// next safe payload.
    async fn produce_next_attributes(&mut self) -> Result<OpAttributesWithParent, DerivationError> {
        // As we start the safe head at the disputed block's parent, we step the pipeline until the
        // first attributes are produced. All batches at and before the safe head will be
        // dropped, so the first payload will always be the disputed one.
        loop {
            let result =
                self.pipeline.step(self.derivation_state_machine.last_confirmed_safe_head()).await;
            // Report the origin after every step, including one that idles or holds a batch for
            // later L1 data: the L1 head may run ahead, but derivation has only reached here.
            self.publish_origin(self.pipeline.origin());
            match result {
                StepResult::PreparedAttributes => { /* continue; attributes will be sent off. */ }
                StepResult::AdvancedOrigin => {
                    let origin =
                        self.pipeline.origin().ok_or(PipelineError::MissingOrigin.crit())?.number;

                    kona_macros::set!(counter, Metrics::DERIVATION_L1_ORIGIN, origin);
                    debug!(target: "derivation", l1_block = origin, "Advanced L1 origin");
                }
                StepResult::OriginAdvanceErr(e) | StepResult::StepFailed(e) => {
                    match e {
                        PipelineErrorKind::Temporary(e) => {
                            // NotEnoughData is transient, and doesn't imply we need to wait for
                            // more data. We can continue stepping until we receive an Eof.
                            if matches!(e, PipelineError::NotEnoughData) {
                                continue;
                            }

                            debug!(
                                target: "derivation",
                                "Exhausted data source for now; Yielding until the chain has extended."
                            );
                            return Err(DerivationError::Yield);
                        }
                        PipelineErrorKind::Reset(e) => {
                            warn!(target: "derivation", "Derivation pipeline is being reset: {e}");

                            if matches!(e, ResetError::HoloceneActivation) {
                                self.pipeline
                                    .signal(Signal::Activation(ActivationSignal {
                                        l2_safe_head: self
                                            .derivation_state_machine
                                            .last_confirmed_safe_head(),
                                    }))
                                    .await?;
                            } else {
                                if let ResetError::ReorgDetected(expected, new) = e {
                                    warn!(
                                        target: "derivation",
                                        "L1 reorg detected! Expected: {expected} | New: {new}"
                                    );

                                    kona_macros::inc!(counter, Metrics::L1_REORG_COUNT);
                                }
                                // The reset discards the pipeline's progress, as op-node's
                                // `ResetEvent` clears its `CurrentL1`.
                                self.publish_origin(None);
                                self.engine_client.reset_engine_forkchoice().await.map_err(|e| {
                                    error!(target: "derivation", ?e, "Failed to send reset request");
                                    DerivationError::Sender(Box::new(e))
                                })?;
                                self.derivation_state_machine
                                    .update(&DerivationStateUpdate::SignalNeeded)?;
                                return Err(DerivationError::Yield);
                            }
                        }
                        PipelineErrorKind::Critical(_) => {
                            error!(target: "derivation", "Critical derivation error: {e}");
                            kona_macros::inc!(counter, Metrics::DERIVATION_CRITICAL_ERROR);
                            return Err(e.into());
                        }
                    }
                }
            }

            // If there are any new attributes, send them to the execution actor.
            if let Some(attrs) = self.pipeline.next() {
                return Ok(attrs);
            }
        }
    }

    async fn handle_derivation_actor_request(
        &mut self,
        request_type: DerivationActorRequest,
    ) -> Result<(), DerivationError> {
        match request_type {
            DerivationActorRequest::ProcessEngineSignalRequest(signal) => {
                self.signal(*signal).await;
                self.derivation_state_machine.update(&DerivationStateUpdate::SignalProcessed)?;
            }
            DerivationActorRequest::ProcessFinalizedL1Block(finalized_l1_block) => {
                // Attempt to finalize the block. If successful, notify engine.
                if let Some(l2_block_number) = self.finalizer.try_finalize_next(*finalized_l1_block)
                {
                    // Local L1-finality: the engine's own canonical chain is the authoritative
                    // source at this height, so finalize by number.
                    self.engine_client
                        .send_finalized_l2_block(FinalizeBlockId::ByNumber(l2_block_number))
                        .await
                        .map_err(|e| DerivationError::Sender(Box::new(e)))?;
                }
            }
            DerivationActorRequest::ProcessL1HeadUpdateRequest(l1_head) => {
                info!(target: "derivation", l1_head = ?*l1_head, "Processing l1 head update");

                self.derivation_state_machine.update(&DerivationStateUpdate::L1DataReceived)?;

                self.attempt_derivation().await?;
            }
            DerivationActorRequest::ProcessEngineSafeHeadUpdateRequest(safe_head) => {
                info!(target: "derivation", safe_head = ?*safe_head, "Received safe head from engine.");
                self.derivation_state_machine
                    .update(&DerivationStateUpdate::NewAttributesConfirmed(safe_head))?;

                self.attempt_derivation().await?;
            }
            DerivationActorRequest::ProcessEngineSyncCompletionRequest(safe_head) => {
                info!(target: "derivation", "Engine finished syncing, starting derivation.");
                self.derivation_state_machine
                    .update(&DerivationStateUpdate::ELSyncCompleted(safe_head))?;

                self.attempt_derivation().await?;
            }
        }

        Ok(())
    }

    /// Attempts to process the next payload attributes.
    async fn attempt_derivation(&mut self) -> Result<(), DerivationError> {
        if self.derivation_state_machine.current_state() != DerivationState::Deriving {
            info!(target: "derivation", derivation_state=?self.derivation_state_machine, "Skipping derivation.");
            return Ok(());
        }

        info!(target: "derivation", derivation_state=?self.derivation_state_machine, "Attempting derivation.");

        // Advance the pipeline as much as possible, new data may be available or there still may be
        // payloads in the attributes queue.
        let payload_attributes = match self.produce_next_attributes().await {
            Ok(attrs) => attrs,
            Err(DerivationError::Yield) => {
                info!(target: "derivation", "Yielding derivation until more data is available.");
                self.derivation_state_machine.update(&DerivationStateUpdate::MoreDataNeeded)?;
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        };
        trace!(target: "derivation", ?payload_attributes, "Produced payload attributes.");

        self.derivation_state_machine.update(&DerivationStateUpdate::NewAttributesDerived(
            Box::new(payload_attributes.clone()),
        ))?;

        // Enqueue the payload attributes for finalization tracking.
        self.finalizer.enqueue_for_finalization(&payload_attributes);

        // Send payload attributes out for processing.
        self.engine_client
            .send_safe_l2_signal(payload_attributes.into())
            .await
            .map_err(|e| DerivationError::Sender(Box::new(e)))?;

        Ok(())
    }
}

#[async_trait]
impl<DerivationEngineClient_, PipelineSignalReceiver> NodeActor
    for DerivationActor<DerivationEngineClient_, PipelineSignalReceiver>
where
    DerivationEngineClient_: DerivationEngineClient + 'static,
    PipelineSignalReceiver: Pipeline + SignalReceiver + Send + Sync + 'static,
{
    type Error = DerivationError;

    async fn step(&mut self) -> Result<(), Self::Error> {
        let request = self.inbound_request_rx.recv().await.ok_or_else(|| {
            error!(
                target: "derivation",
                "DerivationActor inbound request receiver closed unexpectedly",
            );
            DerivationError::RequestReceiveFailed
        })?;
        self.handle_derivation_actor_request(request).await
    }
}

/// An error from the [`DerivationActor`].
#[derive(Error, Debug)]
pub enum DerivationError {
    /// An error originating from the derivation pipeline.
    #[error(transparent)]
    Pipeline(#[from] PipelineErrorKind),
    /// Waiting for more data to be available.
    #[error("Waiting for more data to be available")]
    Yield,
    /// An error originating from the broadcast sender.
    #[error("Failed to send event to broadcast sender: {0}")]
    Sender(Box<dyn std::error::Error>),
    /// Failed to receive inbound request
    #[error("Failed to receive inbound request")]
    RequestReceiveFailed,
    /// An invalid state transition occurred.
    #[error(transparent)]
    StateTransitionError(#[from] DerivationStateTransitionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::derivation::engine_client::MockDerivationEngineClient;
    use alloy_primitives::B256;
    use kona_derive::{PipelineResult, ResetSignal};
    use kona_genesis::{HardForkConfig, RollupConfig, SystemConfig};
    use kona_protocol::{BlockInfo, L2BlockInfo};
    use rstest::rstest;
    use std::sync::Arc;

    /// A pipeline stub whose every step returns the same result, and whose origin a reset signal
    /// moves onto `reset_origin`.
    #[derive(Debug)]
    struct StubPipeline {
        rollup_config: Arc<RollupConfig>,
        origin: Option<BlockInfo>,
        reset_origin: Option<BlockInfo>,
        step: fn() -> StepResult,
    }

    impl StubPipeline {
        fn new(rollup_config: Arc<RollupConfig>, step: fn() -> StepResult) -> Self {
            Self { rollup_config, origin: None, reset_origin: None, step }
        }
    }

    impl Iterator for StubPipeline {
        type Item = OpAttributesWithParent;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    impl kona_derive::OriginProvider for StubPipeline {
        fn origin(&self) -> Option<BlockInfo> {
            self.origin
        }
    }

    #[async_trait]
    impl SignalReceiver for StubPipeline {
        async fn signal(&mut self, signal: Signal) -> PipelineResult<()> {
            if matches!(signal, Signal::Reset(_)) {
                self.origin = self.reset_origin;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl Pipeline for StubPipeline {
        fn peek(&self) -> Option<&OpAttributesWithParent> {
            None
        }

        async fn step(&mut self, _: L2BlockInfo) -> StepResult {
            (self.step)()
        }

        fn rollup_config(&self) -> &RollupConfig {
            &self.rollup_config
        }

        async fn system_config_by_l2_hash(
            &mut self,
            _: B256,
        ) -> Result<SystemConfig, PipelineErrorKind> {
            Ok(SystemConfig::default())
        }
    }

    /// Every step reports an L1 reorg, forcing the reset branch of
    /// [`DerivationActor::produce_next_attributes`].
    fn reorg() -> StepResult {
        StepResult::StepFailed(PipelineErrorKind::Reset(ResetError::ReorgDetected(
            B256::ZERO,
            B256::repeat_byte(1),
        )))
    }

    /// Every step finds no more data at the current origin, as when a stage holds a batch for
    /// later L1 data.
    fn hold() -> StepResult {
        StepResult::StepFailed(PipelineError::Eof.temp())
    }

    fn l1(number: u64) -> BlockInfo {
        BlockInfo::new(B256::repeat_byte(number as u8), number, B256::ZERO, number * 12)
    }

    /// Delivers `request` to `actor` and lets it handle it.
    async fn deliver(
        request_tx: &mpsc::Sender<DerivationActorRequest>,
        actor: &mut DerivationActor<MockDerivationEngineClient, StubPipeline>,
        request: DerivationActorRequest,
    ) {
        request_tx.send(request).await.unwrap();
        actor.step().await.unwrap();
    }

    /// A pipeline-driven reset must always reach the engine actor. The engine's reset is what
    /// sends the pipeline its [`Signal`] back; without it the actor parks in
    /// [`DerivationState::AwaitingSignal`] forever.
    #[rstest]
    #[case::interop_inactive(None)]
    #[case::interop_active(Some(0))]
    #[tokio::test]
    async fn test_pipeline_reset_always_resets_engine(#[case] lagoon_time: Option<u64>) {
        let rollup_config = Arc::new(RollupConfig {
            hardforks: HardForkConfig { lagoon_time, ..Default::default() },
            ..Default::default()
        });

        let mut engine_client = MockDerivationEngineClient::new();
        engine_client.expect_reset_engine_forkchoice().times(1).returning(|| Ok(()));

        let (request_tx, request_rx) = mpsc::channel(1);
        let (origin_tx, origin_rx) = watch::channel(None);
        let mut pipeline = StubPipeline::new(rollup_config, reorg);
        pipeline.origin = Some(l1(3));
        let mut actor = DerivationActor::new(engine_client, request_rx, pipeline, origin_tx);

        // Complete EL sync so the actor starts deriving, then let it hit the reorg.
        request_tx
            .send(DerivationActorRequest::ProcessEngineSyncCompletionRequest(Box::default()))
            .await
            .unwrap();
        actor.step().await.unwrap();

        assert_eq!(actor.derivation_state_machine.current_state(), DerivationState::AwaitingSignal);
        // Like op-node's `ResetEvent`, the reset clears the reported L1 progress.
        assert_eq!(*origin_rx.borrow(), None);
    }

    /// The published `current_l1` is the pipeline's origin, as op-node reports it: it stays at
    /// the origin while derivation holds there and the L1 head advances, and follows the
    /// pipeline when its origin moves, including back onto an earlier block on reset.
    #[tokio::test]
    async fn test_published_origin_follows_pipeline_not_l1_head() {
        let (request_tx, request_rx) = mpsc::channel(1);
        let (origin_tx, origin_rx) = watch::channel(None);
        let mut pipeline = StubPipeline::new(Arc::default(), hold);
        // Before its first reset the pipeline reports the zero block as its origin.
        pipeline.origin = Some(BlockInfo::default());
        pipeline.reset_origin = Some(l1(2));
        let mut actor = DerivationActor::new(
            MockDerivationEngineClient::new(),
            request_rx,
            pipeline,
            origin_tx,
        );
        let head =
            |number| DerivationActorRequest::ProcessL1HeadUpdateRequest(Box::new(l1(number)));

        // Nothing is reported before derivation has stepped, nor for the zero origin.
        assert_eq!(*origin_rx.borrow(), None);
        let synced = DerivationActorRequest::ProcessEngineSyncCompletionRequest(Box::default());
        deliver(&request_tx, &mut actor, synced).await;
        assert_eq!(*origin_rx.borrow(), None);

        actor.pipeline.origin = Some(l1(3));
        deliver(&request_tx, &mut actor, head(3)).await;
        assert_eq!(*origin_rx.borrow(), Some(l1(3)));

        // The L1 head moves on while derivation holds its origin.
        for number in 4..=6 {
            deliver(&request_tx, &mut actor, head(number)).await;
            assert_eq!(*origin_rx.borrow(), Some(l1(3)));
        }

        // Derivation advances its origin, still behind the head.
        actor.pipeline.origin = Some(l1(5));
        deliver(&request_tx, &mut actor, head(7)).await;
        assert_eq!(*origin_rx.borrow(), Some(l1(5)));

        // A reset moves the pipeline back onto an earlier origin.
        let reset = DerivationActorRequest::ProcessEngineSignalRequest(Box::new(Signal::Reset(
            ResetSignal::default(),
        )));
        deliver(&request_tx, &mut actor, reset).await;
        assert_eq!(*origin_rx.borrow(), Some(l1(2)));
    }
}
