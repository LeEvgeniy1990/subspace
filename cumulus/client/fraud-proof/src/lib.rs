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

use codec::Encode;

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

pub use sp_block_builder::BlockBuilder as BlockBuilderApi;

use sc_client_api::{backend, CallExecutor, ExecutorProvider};

fn prove_execution(
	&self,
	at: &BlockId<Block>,
	method: &str,
	call_data: &[u8],
) -> sp_blockchain::Result<(Vec<u8>, StorageProof)> {
	let state = self.backend.state_at(*at)?;

	let trie_backend = state.as_trie_backend().ok_or_else(|| {
		Box::new(sp_state_machine::ExecutionError::UnableToGenerateProof)
			as Box<dyn sp_state_machine::Error>
	})?;

	let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
	let runtime_code =
		state_runtime_code.runtime_code().map_err(sp_blockchain::Error::RuntimeCode)?;
	let runtime_code = self.check_override(runtime_code, at)?;

	sp_state_machine::prove_execution_on_trie_backend(
		&trie_backend,
		&mut Default::default(),
		&self.executor,
		self.spawn_handle.clone(),
		method,
		call_data,
		&runtime_code,
	)
	.map_err(Into::into)
}
