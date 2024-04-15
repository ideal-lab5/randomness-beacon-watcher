#![allow(missing_docs)]

use subxt::{
    client::OnlineClient,
    config::SubstrateConfig,
    dynamic::At,
    backend::rpc::{RpcClient, RpcParams},
};
use subxt::ext::codec::Encode;
use subxt_signer::sr25519::dev;

use w3f_bls::EngineBLS;
use beefy::{known_payloads, Payload, Commitment, VersionedFinalityProof};
use sp_core::{Bytes, Decode};

use etf_crypto_primitives::{
    ibe::fullident::{IBESecret, Identity},
    encryption::tlock::{Tlock, TLECiphertext}
};

use ark_ff::UniformRand;
use ark_ec::Group;
use rand_chacha::ChaCha20Rng;

use ark_bls12_377::Bls12_377;
use ark_ec::bls12::Bls12Config;
use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
use ark_ec::pairing::Pairing as PairingEngine;
use ark_serialize::CanonicalDeserialize;

use rand_core::OsRng;

use w3f_bls::{CurveExtraConfig, TinyBLS, UsualBLS};

use ark_std::{test_rng, rand::{RngCore, SeedableRng}};

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
    let target = current_block_number + 2;

    println!("🧊 Current block number: #{:?}", current_block_number);

    let ciphertext = tlock_encrypt::<TinyBLS<Bls12_377, ark_bls12_377::Config>, Bls12_377, ark_bls12_377::Config>(
        client.clone(), 
        round_pubkey_bytes,
        target,
    ).await?;

    if let Some(decryption_key) = wait_for_justification::<TinyBLS<Bls12_377, ark_bls12_377::Config>, Bls12_377, ark_bls12_377::Config>(
        rpc_client, client.clone(), target
    ).await? {
        println!(
            "🧾 Extracted decryption key {:?} for block number #{:?}", 
            decryption_key,
            target,
        );
        let m = tlock_decrypt::<TinyBLS<Bls12_377, ark_bls12_377::Config>, Bls12_377, ark_bls12_377::Config>(
            client.clone(),
            ciphertext, 
            decryption_key,
        ).await?;

        println!("Message recovered: {:?}", m);
        return Ok(());
    }

    Ok(())
}

/// perform timelock encryption over BLS12-377
async fn tlock_encrypt<
    EB: EngineBLS<Engine = E>,
    E: PairingEngine, 
    P: Bls12Config + CurveExtraConfig>(
        client: OnlineClient<SubstrateConfig>,
        mut rk_bytes: Vec<u8>,
        target: u32,
    ) -> Result<TLECiphertext<EB>, Box<dyn std::error::Error>>
where
    <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
{
    let round_pubkey = EB::PublicKeyGroup::deserialize_compressed(&rk_bytes[..])
        .expect("The network must have a valid round public key.");

    println!("🔑 Successfully retrieved the round public key.");

    println!("🔒 Encrypting the message for target block #{:?}", target);

    let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
    let commitment = Commitment { payload, block_number: target, validator_set_id: 6 };

    println!("THE ENCODED COMMITMENT LOOKS LIKE: {:?}", commitment.clone().encode());
    // validators sign the SCALE encoded commitment, so that becomes our identity for TLE as well
    let message = b"This is a test".to_vec();
    let id = Identity::new(&commitment.encode());
    // 2) tlock for encoded commitment (TODO: error handling)
    let ciphertext = Tlock::<EB>::encrypt(
        round_pubkey,
        &message,
        vec![id],
        1,
        &mut OsRng,
    ).unwrap();
    Ok(ciphertext)
}


/// perform timelock encryption over BLS12-377
async fn tlock_decrypt<
    EB: EngineBLS<Engine = E>,
    E: PairingEngine, 
    P: Bls12Config + CurveExtraConfig>(
        client: OnlineClient<SubstrateConfig>,
        ciphertext: TLECiphertext<EB>,
        signature: EB::SignatureGroup,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
{    

    // let ibe_secret = IBESecret(signature);

    let message = Tlock::<EB>::decrypt(
        ciphertext,
        vec![IBESecret(signature)],
    ).unwrap();

    Ok(vec![])
}

/// subscribe for justifications until we can decode a finality proof
/// given at a specific block number (in the future)
async fn wait_for_justification<
    EB: EngineBLS<Engine = E>,
    E: PairingEngine, 
    P: Bls12Config + CurveExtraConfig>(
    rpc_client: RpcClient, 
    client: OnlineClient<SubstrateConfig>,
    block_number: u32,
) -> Result<Option<EB::SignatureGroup>, Box<dyn std::error::Error>>
where
    <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
{

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
                    let sig = sp_core::bls377::Signature::from(primary);
                    let sig_bytes = sig.0;
                    let s = EB::SignatureGroup::deserialize_compressed(&mut &sig_bytes[..]).unwrap();
                    return Ok(Some(s))
                    // println!(
                    //     "🧾 Extracted signatures {:?} for block number #{:?}", 
                    //     sig,
                    //     current_block_number,
                    // );
                }
                _ => {
                    println!("idk");
                }
            }
            
        }
    }
    Ok(None)
}
