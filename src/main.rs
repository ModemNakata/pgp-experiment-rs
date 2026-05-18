use pgp::{
    composed::{
        ArmorOptions,
        EncryptionCaps,
        KeyType,
        SecretKeyParamsBuilder,
        SignedSecretKey,
        // SubkeyParamsBuilder,
    },
    // crypto::ecc_curve::ECCCurve,
};
use rand::thread_rng;

fn main() {
    let secret_key = keygen_with_encryption("user@example.com").expect("failed during keygen");

    let armor_opts = ArmorOptions::default();
    println!("{}", secret_key.to_armored_string(armor_opts).unwrap());
}

fn keygen_with_encryption(
    uid: &str,
) -> Result<SignedSecretKey, pgp::composed::SubkeyParamsBuilderError> {
    // 1. Build the ultra-slim Encryption Subkey using Cv25519 (ECDH)
    // let mut encrypt_subkey = SubkeyParamsBuilder::default();
    // encrypt_subkey
    //     .key_type(KeyType::ECDH(ECCCurve::Curve25519)) // Curve25519 for encryption
    //     .can_sign(false)
    //     .can_encrypt(EncryptionCaps::All) // Enables full encryption/decryption
    //     .can_authenticate(false);

    // 2. Build the primary master key (handles Sign, Certify, Auth)
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_authenticate(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(uid.into());
    // .subkeys(vec![
    // encrypt_subkey.build()?, // Attach the single encryption subkey
    // ]);

    let secret_key_params = key_params.build().expect("Build secret_key_params");
    let signed = secret_key_params
        .generate(thread_rng())
        .expect("Generate key");

    Ok(signed)
}
