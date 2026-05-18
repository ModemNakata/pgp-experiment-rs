use pgp::{
    composed::{ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey},
    crypto::ecc_curve::ECCCurve,
};
use rand::thread_rng;

fn main() {
    // Generate a single, ultra-slim primary key with ZERO subkeys
    let secret_key = keygen_slim("user@example.com").expect("failed during slim keygen");

    let armor_opts = ArmorOptions::default();
    println!("{}", secret_key.to_armored_string(armor_opts).unwrap());
}

fn keygen_slim(uid: &str) -> Result<SignedSecretKey, pgp::composed::SubkeyParamsBuilderError> {
    let mut key_params = SecretKeyParamsBuilder::default();

    // Consolidate all capabilities into the primary master key
    key_params
        .key_type(KeyType::Ed25519Legacy) // Compact, modern Edwards curve
        .can_certify(true) // Must have to be a valid master key
        .can_sign(true) // Handles data signing (e.g., Git commits)
        .can_authenticate(true) // Handles SSH authentication
        .can_encrypt(EncryptionCaps::None) // Ed25519 cannot natively encrypt data
        .primary_user_id(uid.into())
        .subkeys(vec![]); // <--- Completely empty! No subkeys.

    let secret_key_params = key_params.build().expect("Build secret_key_params");
    let signed = secret_key_params
        .generate(thread_rng())
        .expect("Generate key");

    Ok(signed)
}
