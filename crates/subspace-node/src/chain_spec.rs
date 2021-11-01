// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

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

use sc_service::{ChainType, Properties};
use sc_telemetry::TelemetryEndpoints;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime::{
    AccountId, Balance, BalancesConfig, BlockNumber, GenesisConfig, Signature, SubspaceConfig,
    SudoConfig, SystemConfig, VestingConfig, SSC, WASM_BINARY,
};

// The URL for the telemetry server.
const POLKADOT_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub fn testnet_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::from_genesis(
        // Name
        "Subspace testnet",
        // ID
        "subspace_test",
        ChainType::Custom("Subspace testnet".to_string()),
        // TODO: Provide a way for farmer to start with these accounts
        || {
            // st6iwqnxNab6JUawtmqUmftG2oSsKoTaWzbg9PxdWrWw5C6Th
            let root_account: AccountId =
                "0x14682f9dea76a4dd47172a118eb29b9cf9976df7ade12f95709a7cd2e3d81d6c"
                    .parse()
                    .expect("Wrong root account ID");
            create_genesis_config(
                WASM_BINARY.expect("Wasm binary must be built for testnet"),
                // Sudo account
                root_account.clone(),
                // Pre-funded accounts
                vec![
                    (root_account, 1_000 * SSC),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Alice"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Bob"),
                        1_000 * SSC,
                    ),
                ],
                vec![],
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        Some(
            TelemetryEndpoints::new(vec![(POLKADOT_TELEMETRY_URL.into(), 0)])
                .map_err(|error| error.to_string())?,
        ),
        // Protocol ID
        Some("subspace"),
        // Properties
        Some(Properties::from_iter([
            (
                "tokenDecimals".to_string(),
                serde_json::to_value(18_u8).expect("u8 is always serializable; qed"),
            ),
            (
                "tokenSymbol".to_string(),
                serde_json::to_value("tSSC").expect("&str is always serializable; qed"),
            ),
        ])),
        // Extensions
        None,
    ))
}

pub fn development_config() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

    Ok(ChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "dev",
        ChainType::Development,
        // TODO: Provide a way for farmer to start with these accounts
        || {
            create_genesis_config(
                wasm_binary,
                // Sudo account
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                // Pre-funded accounts
                vec![
                    (
                        get_account_id_from_seed::<sr25519::Public>("Alice"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Bob"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                        1_000 * SSC,
                    ),
                ],
                vec![],
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        // Properties
        None,
        // Extensions
        None,
    ))
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

    Ok(ChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "local_testnet",
        ChainType::Local,
        || {
            create_genesis_config(
                wasm_binary,
                // Sudo account
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                // Pre-funded accounts
                vec![
                    (
                        get_account_id_from_seed::<sr25519::Public>("Alice"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Bob"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Charlie"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Dave"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Eve"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
                        1_000 * SSC,
                    ),
                    (
                        get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
                        1_000 * SSC,
                    ),
                ],
                vec![],
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        // Properties
        None,
        // Extensions
        None,
    ))
}

/// Configure initial storage state for FRAME modules.
fn create_genesis_config(
    wasm_binary: &[u8],
    root_key: AccountId,
    balances: Vec<(AccountId, Balance)>,
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            // Add Wasm runtime to storage.
            code: wasm_binary.to_vec(),
            changes_trie_config: Default::default(),
        },
        balances: BalancesConfig { balances },
        subspace: SubspaceConfig {
            epoch_config: Some(subspace_runtime::SUBSPACE_GENESIS_EPOCH_CONFIG),
        },
        sudo: SudoConfig {
            // Assign network admin rights.
            key: root_key,
        },
        vesting: VestingConfig { vesting },
    }
}
