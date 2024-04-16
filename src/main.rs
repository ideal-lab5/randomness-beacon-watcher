
/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![allow(missing_docs)]

use subxt::{
    client::OnlineClient,
    config::SubstrateConfig,
    backend::rpc::{RpcClient, RpcParams},
};
use subxt::ext::codec::Encode;
use beefy::{known_payloads, Payload, Commitment, VersionedFinalityProof};
use sp_core::{Bytes, Decode};

use etf_crypto_primitives::{
    ibe::fullident::{IBESecret, Identity},
    encryption::tlock::{Tlock, TLECiphertext}
};

use ark_serialize::CanonicalDeserialize;

use rand_core::OsRng;

use w3f_bls::{EngineBLS, TinyBLS377, SerializableToBytes};


pub enum ETFError {
    EncryptionFailed,
    Other,
}

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./artifacts/metadata.scale")]
pub mod etf {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎲 ETF Randomness Beacon and Timelock Encryption Demo");

    let rpc_client = RpcClient::from_url("ws://localhost:9944").await?;

    println!("🔗 RPC Client: connection established");
    
    let client = OnlineClient::<SubstrateConfig>::from_rpc_client(rpc_client.clone()).await?;

    // fetch the round public key from BEEFY runtime storage
    let round_key_query = subxt::dynamic::storage("Beefy", "RoundPublic", ());
    let result = client
        .storage()
        .at_latest()
        .await?
        .fetch(&round_key_query)
        .await?;
    let round_pubkey_bytes = result.unwrap().as_type::<Vec<u8>>()?;

    let current_block = client.blocks().at_latest().await?;
    let current_block_number = current_block.header().number;
    let target = current_block_number + 1;

    println!("🧊 Current block number: #{:?}", current_block_number);

    let ciphertext = tlock_encrypt::<TinyBLS377>(
        client.clone(), 
        round_pubkey_bytes,
        target,
    ).await?;

    if let Some(decryption_key) = wait_for_justification::<TinyBLS377>(
        rpc_client, client.clone(), target
    ).await? {
        println!(
            "🧾 Extracted decryption key {:?} for block number #{:?}", 
            decryption_key,
            target,
        );
        let m = tlock_decrypt::<TinyBLS377>(
            client.clone(),
            ciphertext, 
            decryption_key,
        ).await?;

        println!("🔓 Message recovered: {:?}", std::str::from_utf8(&m).unwrap());
        println!("👋 Goodbye.");
        return Ok(());
    }

    Ok(())
}

/// construct the encoded commitment for the round in which block_number h
async fn get_validator_set_id(
    client: OnlineClient<SubstrateConfig>,
    _block_number: u32,
) -> Result<u64, Box<dyn std::error::Error>>  {
    // we need to estimate the future epoch index when block_number will happen
    // for now, since we are encrypting for close by blocks, we will just use the current epoch index
    // but this won't work for blocks in different epochs.

    let epoch_index_query = subxt::dynamic::storage("Babe", "EpochIndex", ());
    let result = client.storage()
        .at_latest()
        .await?
        .fetch(&epoch_index_query)
        .await?;
    let epoch_index = result.unwrap().as_type::<u64>()?;
    Ok(epoch_index)
}

/// perform timelock encryption over BLS12-377
async fn tlock_encrypt<E: EngineBLS>(
        client: OnlineClient<SubstrateConfig>,
        rk_bytes: Vec<u8>,
        target: u32,
    ) -> Result<TLECiphertext<E>, Box<dyn std::error::Error>> {
    let round_pubkey = E::PublicKeyGroup::deserialize_compressed(&rk_bytes[..])
        .expect("The network must have a valid round public key.");

    println!("🔑 Successfully retrieved the round public key.");

    println!("🔒 Encrypting the message for target block #{:?}", target);

    let epoch_index = get_validator_set_id(client.clone(), target).await?;
    let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
    let commitment = Commitment { payload, block_number: target, validator_set_id: epoch_index };
    // validators sign the SCALE encoded commitment, so that becomes our identity for TLE as well
    let message = b"This is a test".to_vec();
    let id = Identity::new(&commitment.encode());
    // 2) tlock for encoded commitment (TODO: error handling)
    let ciphertext = Tlock::<E>::encrypt(
        round_pubkey,
        &message,
        vec![id],
        1,
        OsRng,
    ).unwrap();
    Ok(ciphertext)
}

/// perform timelock encryption over BLS12-377
async fn tlock_decrypt<E: EngineBLS>(
        _client: OnlineClient<SubstrateConfig>,
        ciphertext: TLECiphertext<E>,
        signature: E::SignatureGroup,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {    
    let result = Tlock::<E>::decrypt(
        ciphertext,
        vec![IBESecret(signature)],
    ).unwrap();

    Ok(result.message)
}

/// subscribe for justifications until we can decode a finality proof
/// given at a specific block number (in the future)
async fn wait_for_justification<E: EngineBLS>(
    rpc_client: RpcClient, 
    client: OnlineClient<SubstrateConfig>,
    block_number: u32,
) -> Result<Option<E::SignatureGroup>, Box<dyn std::error::Error>> {

    println!("🔍 Subscribing to ETF justifications...");

    let mut justification_subscription = rpc_client.subscribe::<Bytes>(
        "beefy_subscribeJustifications", 
        RpcParams::new(), 
        "beefy_unsubscribeJustifications"
    ).await?;

    while let Some(Ok(justification)) = justification_subscription.next().await {
        let current_block = client.blocks().at_latest().await?;
        let current_block_number = current_block.header().number;
        if current_block_number == block_number {
            let recv_finality_proof: VersionedFinalityProof<u32, sp_application_crypto::bls377::Signature> =
			    Decode::decode(&mut &justification[..]).unwrap();
            match recv_finality_proof {
                VersionedFinalityProof::V1(signed_commitment) => {
                    let sigs = signed_commitment.signatures;
                    let primary = sigs[0].unwrap();
                    match w3f_bls::double::DoubleSignature::<E>::from_bytes(&primary.to_raw()) {
                        Ok(sig) => {
                            return Ok(Some(sig.0))
                        },
                        Err(_) => {
                            panic!("TODO: proper error handling: couldn't recover sig");
                        },
                    };
                }
            }
            
        }
    }
    Ok(None)
}
