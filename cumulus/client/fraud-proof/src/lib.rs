// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate block builder
//!
//! This crate provides the [`BlockBuilder`] utility and the corresponding runtime api
//! [`BlockBuilder`](sp_block_builder::BlockBuilder).
//!
//! The block builder utility is used in the node as an abstraction over the runtime api to
//! initialize a block, to push extrinsics and to finalize a block.

#![warn(missing_docs)]
#![allow(clippy::all)]

use codec::{Codec, Decode, Encode};
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::{backend, CallExecutor, ExecutorProvider};
use sp_api::{
	ApiExt, ApiRef, Core, ProvideRuntimeApi, StateBackend, StorageChanges, StorageProof,
	TransactionOutcome,
};
use sp_blockchain::{ApplyExtrinsicFailed, Error};
use sp_core::{
	traits::{CodeExecutor, SpawnNamed},
	ExecutionContext,
};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Hash, HashFor, Header as HeaderT, NumberFor, One},
	Digest,
};
use sp_state_machine::{TrieBackend, TrieBackendStorage};
use sp_trie::DBValue;
use std::sync::Arc;

pub fn prove_execution<
	Block: BlockT,
	B: backend::Backend<Block>,
	Exec: CodeExecutor + 'static,
	Spawn: SpawnNamed + Send + 'static,
>(
	backend: &Arc<B>,
	executor: &Exec,
	spawn_handle: Spawn,
	at: &BlockId<Block>,
	method: &str,
	call_data: &[u8],
) -> sp_blockchain::Result<(Vec<u8>, StorageProof)> {
	let state = backend.state_at(*at)?;

	let trie_backend = state.as_trie_backend().ok_or_else(|| {
		Box::new(sp_state_machine::ExecutionError::UnableToGenerateProof)
			as Box<dyn sp_state_machine::Error>
	})?;

	let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
	let runtime_code =
		state_runtime_code.runtime_code().map_err(sp_blockchain::Error::RuntimeCode)?;
	// let runtime_code = self.check_override(runtime_code, at)?;

	sp_state_machine::prove_execution_on_trie_backend(
		&trie_backend,
		&mut Default::default(),
		executor,
		spawn_handle,
		method,
		call_data,
		&runtime_code,
	)
	.map_err(Into::into)
}

/// Create a new trie backend with memory DB delta changes.
///
/// This can be used to verify any extrinsic-specific execution on the combined state of `backend`
/// and `delta`.
pub fn create_delta_backend<
	'a,
	S: 'a + TrieBackendStorage<H>,
	H: 'a + Hasher,
	DB: HashDB<H, DBValue>,
>(
	backend: &'a TrieBackend<S, H>,
	delta: DB,
	post_delta_root: H::Out,
) -> TrieBackend<DeltaBackend<'a, S, H, DB>, H>
where
	H::Out: Codec,
{
	let essence = backend.essence();
	let delta_backend = DeltaBackend {
		backend: essence.backend_storage(),
		delta,
		_phantom: sp_std::marker::PhantomData::<H>,
	};
	TrieBackend::new(delta_backend, post_delta_root)
}

pub struct DeltaBackend<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>> {
	backend: &'a S,
	/// Pending changes to the backend.
	delta: DB,
	_phantom: sp_std::marker::PhantomData<H>,
}

impl<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>>
	TrieBackendStorage<H> for DeltaBackend<'a, S, H, DB>
{
	type Overlay = S::Overlay;

	fn get(&self, key: &H::Out, prefix: Prefix) -> Result<Option<DBValue>, String> {
		match HashDB::get(&self.delta, key, prefix) {
			Some(v) => Ok(Some(v)),
			None => Ok(self.backend.get(key, prefix)?),
		}
	}
}
