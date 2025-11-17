use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use openssl::sign::Signer;
use openssl::symm::{Cipher, encrypt};
use std::process::Command;

pub fn ec_params(nid: Nid, output_file: &str) -> Result<(), anyhow::Error> {
    let curve_name = nid.long_name()?;
    // No available rust bindings, so use the CLI
    Command::new("openssl")
        .args(["ecparam", "-name", curve_name, "-out", output_file])
        .output()?;
    Ok(())
}

pub fn gen_priv_key(param_file: &str, output: &str) -> Result<(), anyhow::Error> {
    // No available rust bindings, so use the CLI
    let output = Command::new("openssl")
        .args(["genpkey", "-paramfile", param_file, "-out", output])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate keypair: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn gen_pub_key(input: &str, output: &str) -> Result<(), anyhow::Error> {
    let output = Command::new("openssl")
        .args(["pkey", "-in", input, "-pubout", "-out", output])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract pub key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn session_key(inkey: &str, peerkey: &str) -> Result<Vec<u8>, anyhow::Error> {
    let output = Command::new("openssl")
        .args(["pkeyutl", "-derive", "-inkey", inkey, "-peerkey", peerkey])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract pub key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Read from stdout (binary data)
    let shared_secret = output.stdout;

    // Hash the shared secret
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_slice());
    let digest = hasher.finish();

    Ok(digest.to_vec())
}

pub fn encryption(key: &[u8], input: &str) -> Result<(), anyhow::Error> {
    if key.len() != 32 {
        anyhow::bail!("Encryption key must be 32 bytes long");
    }
    let enc_key = key[..16].to_vec();
    let hmac_key = key[16..].to_vec();

    // Read the plain text
    let plaintext = std::fs::read(input)?;

    // Generate a random IV
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv)?;

    // Encrypt with AES-128-CBC
    let cipher = Cipher::aes_128_cbc();
    let ciphertext = encrypt(cipher, enc_key.as_slice(), Some(&iv), plaintext.as_slice())?;

    // Prepare data for HMAC
    let mut mac_data = Vec::with_capacity(iv.len() + ciphertext.len());
    mac_data.extend_from_slice(&iv);
    mac_data.extend_from_slice(&ciphertext);

    // Generate SHA256-HMAC
    let hmac = generate_hmac(&mac_data, hmac_key.as_slice())?;

    // Export the ciphertext, IV and tag
    std::fs::write("ciphertext.bin", ciphertext)?;
    std::fs::write("iv.bin", iv)?;
    std::fs::write("tag.bin", hmac)?;

    Ok(())
}

fn generate_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let hmac_key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &hmac_key)?;
    signer.update(data)?;
    let hmac = signer.sign_to_vec()?;
    Ok(hmac)
}
