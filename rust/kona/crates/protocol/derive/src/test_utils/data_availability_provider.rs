//! An implementation of the [`DataAvailabilityProvider`] trait for tests.

use crate::{errors::PipelineError, traits::DataAvailabilityProvider, types::PipelineResult};
use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use core::fmt::Debug;
use kona_protocol::BlockInfo;

/// Mock data availability provider
#[derive(Debug, Default)]
pub struct TestDAP {
    /// Specifies the stage results.
    pub results: Vec<PipelineResult<Bytes>>,
}

/// A clone starts with no results: errors cannot be cloned, and only the dependency scanner's
/// stack takes a clone.
impl Clone for TestDAP {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[async_trait]
impl DataAvailabilityProvider for TestDAP {
    type Item = Bytes;

    async fn next(&mut self, _: &BlockInfo, _: Address) -> PipelineResult<Self::Item> {
        self.results.pop().unwrap_or(Err(PipelineError::Eof.temp()))
    }

    fn clear(&mut self) {
        self.results.clear();
    }
}
