use cirrus_block_builder::{BlockBuilder, RecordProof};
use cirrus_primitives::{Hash, SecondaryApi};
use cirrus_test_service::{
	run_primary_chain_validator_node,
	runtime::Block,
	Keyring::{Alice, Charlie, Dave},
};
use codec::{Decode, Encode};
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, HashFor, Header as HeaderT},
};

#[substrate_test_utils::test]
async fn test_executor_full_node_catching_up() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// start alice
	let alice = run_primary_chain_validator_node(tokio_handle.clone(), Alice, vec![], true);

	// run cirrus charlie (a secondary chain authority node)
	let charlie = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// run cirrus dave (a secondary chain full node)
	let dave = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Dave)
		.connect_to_parachain_node(&charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// dave is able to sync blocks.
	futures::future::join(charlie.wait_for_blocks(10), dave.wait_for_blocks(10)).await;

	let charlie_block_hash = charlie.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();

	let dave_block_hash = dave.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();

	assert_eq!(
		charlie_block_hash, dave_block_hash,
		"Executor authority node and full node must have the same state"
	);
}

#[substrate_test_utils::test]
async fn test_fraud_proof() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// start alice
	let alice = run_primary_chain_validator_node(tokio_handle.clone(), Alice, vec![], true);

	// run cirrus charlie (a secondary chain authority node)
	let charlie = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// run cirrus dave (a secondary chain full node)
	let dave = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Dave)
		.connect_to_parachain_node(&charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// dave is able to sync blocks.
	futures::future::join(charlie.wait_for_blocks(3), dave.wait_for_blocks(3)).await;

	// Ensure the extrinsic included is same with manually constructed one.
	// Alternative: retrieve the extrinsic from the client
	let transfer_to_charlie = cirrus_test_service::construct_extrinsic(
		&charlie.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
			value: 8,
		},
		Alice.into(),
		false,
		0,
	);

	let transfer_to_dave = cirrus_test_service::construct_extrinsic(
		&charlie.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Dave.public().into()),
			value: 8,
		},
		Alice.into(),
		false,
		1,
	);

	let transfer_to_charlie_again = cirrus_test_service::construct_extrinsic(
		&charlie.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
			value: 88,
		},
		Alice.into(),
		false,
		2,
	);

	let test_txs = vec![
		transfer_to_charlie.clone(),
		transfer_to_dave.clone(),
		transfer_to_charlie_again.clone(),
	];

	for tx in test_txs.iter() {
		charlie.send_extrinsic(tx.clone()).await.expect("Failed to send extrinsic");
	}

	// Wait until the transfer tx is included in the next block.
	charlie.wait_for_blocks(1).await;

	let best_hash = charlie.client.info().best_hash;

	let header = charlie.client.header(&BlockId::Hash(best_hash)).unwrap().unwrap();

	let parent_header =
		charlie.client.header(&BlockId::Hash(*header.parent_hash())).unwrap().unwrap();

	let create_block_builder = || {
		let mut block_builder = BlockBuilder::new(
			&*charlie.client,
			parent_header.hash(),
			*parent_header.number(),
			RecordProof::No,
			Default::default(),
			&*charlie.backend,
		)
		.unwrap();
		block_builder.set_extrinsics(test_txs.clone().into_iter().map(Into::into).collect());
		block_builder
	};

	// Index of the extrinsic to proof.
	for (target_extrinsic_index, xt) in test_txs.clone().into_iter().enumerate() {
		let parent_state = charlie
			.client
			.state_at(&BlockId::Hash(parent_header.hash()))
			.expect("Get parent state");

		let mut block_builder = create_block_builder();
		let overlayed_changes = block_builder
			.prepare_overlay_before(target_extrinsic_index)
			.expect("Failed to get overlayed changes");
		let storage_changes = overlayed_changes
			.into_storage_changes(
				&parent_state,
				best_hash, // unused.
				Default::default(),
				sp_core::storage::StateVersion::V1,
			)
			.expect("Failed to convert `OverlayedChanges` to `StorageChanges`");

		let delta = storage_changes.transaction;
		let post_delta_root = storage_changes.transaction_storage_root;

		let storage_proof = cirrus_fraud_proof::prove_execution(
			&charlie.backend,
			&*charlie.code_executor,
			charlie.task_manager.spawn_handle(),
			&BlockId::Hash(parent_header.hash()),
			"BlockBuilder_apply_extrinsic",
			&xt.encode(),
			Some((delta, post_delta_root)),
		)
		.expect("Create extrinsic execution proof");

		let intermediate_roots = charlie
			.client
			.runtime_api()
			.intermediate_roots(&BlockId::Hash(best_hash))
			.expect("Get intermediate roots");

		let target_trace_root: Hash = intermediate_roots[target_extrinsic_index].into();
		println!("  post_delta_root: {:?}", post_delta_root);
		println!("target_trace_root: {:?}", target_trace_root);
		println!(
			"intermediate_roots: {:?}",
			intermediate_roots.clone().into_iter().map(Hash::from).collect::<Vec<_>>()
		);

		assert_eq!(target_trace_root, post_delta_root);

		// FIXME: conver the storage proof to compact proof in fraud proof
		let compact_proof = storage_proof
			.clone()
			.into_compact_proof::<BlakeTwo256>(post_delta_root)
			.expect("Convert storage proof to compact proof");

		let execution_result = cirrus_fraud_proof::check_execution_proof(
			post_delta_root,
			storage_proof,
			&charlie.backend,
			&*charlie.code_executor,
			charlie.task_manager.spawn_handle(),
			&BlockId::Hash(parent_header.hash()),
			"SecondaryApi_apply_extrinsic_with_post_state_root",
			&xt.encode(),
		)
		.expect("Check extrinsic execution proof");

		let post_execution_root = Hash::decode(&mut &execution_result.as_slice()[1..]).unwrap();
		println!("Post execution root: {:?}", post_execution_root);
		assert_eq!(post_execution_root, intermediate_roots[target_extrinsic_index + 1].into());

		/* TODO: https://github.com/paritytech/substrate/issues/11046
		use sp_core::{NativeOrEncoded, NeverNativeValue};
		let proof_ret_value: NativeOrEncoded<sp_core::NeverNativeValue> =
			Decode::decode(&mut execution_result.as_slice()).unwrap();
		let execution_ret_value = proof_ret_value.into_encoded();
		let post_execution_root = Hash::decode(&mut &execution_ret_value.as_slice()).unwrap();
		*/
	}
}
