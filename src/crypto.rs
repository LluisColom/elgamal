use crate::EPH_PUB_FILE;
use anyhow::Context;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use openssl::sign::Signer;
use openssl::symm::{Cipher, decrypt, encrypt};
use openssl::{base64, memcmp};
use std::process::Command;

const AES_KEY_SIZE: usize = 16;
const SESSION_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;

pub fn ec_params(nid: Nid, output_file: &str) -> Result<(), anyhow::Error> {
    let curve_name = nid.long_name()?;
    // No available rust bindings, so use the CLI
    let output = Command::new("openssl")
        .args(["ecparam", "-name", curve_name, "-out", output_file])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate EC parameters: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
    if key.len() != SESSION_KEY_SIZE {
        anyhow::bail!("Encryption key must be {} bytes long", SESSION_KEY_SIZE);
    }
    let enc_key = &key[..AES_KEY_SIZE];
    let hmac_key = &key[AES_KEY_SIZE..];

    // Read the plain text
    let plaintext = std::fs::read(input)?;

    // Generate a random IV
    let mut iv = [0u8; IV_SIZE];
    rand_bytes(&mut iv)?;

    // Encrypt with AES-128-CBC
    let cipher = Cipher::aes_128_cbc();
    let ciphertext = encrypt(cipher, enc_key, Some(&iv), plaintext.as_slice())?;

    // Generate SHA256-HMAC
    let hmac = generate_hmac(iv.as_slice(), ciphertext.as_slice(), hmac_key)?;

    // Export the ephemeral public key, ciphertext, IV and tag
    export(&iv, &ciphertext, &hmac)?;

    Ok(())
}

pub fn decryption(key: &[u8], iv: &[u8], input: &[u8], hmac: &[u8]) -> Result<(), anyhow::Error> {
    if key.len() != SESSION_KEY_SIZE {
        anyhow::bail!("Encryption key must be {} bytes long", SESSION_KEY_SIZE);
    }
    let enc_key = &key[..AES_KEY_SIZE];
    let hmac_key = &key[AES_KEY_SIZE..];

    // HMAC verification
    if !verify_hmac(&hmac_key, &iv, &input, &hmac)? {
        anyhow::bail!("HMAC verification failed");
    }

    // Decrypt with AES-128-CBC
    let cipher = Cipher::aes_128_cbc();
    let plaintext = decrypt(cipher, enc_key, Some(&iv), input)?;

    // Write to the file
    std::fs::write("decoded.txt", plaintext)?;
    Ok(())
}

fn export(iv: &[u8], ciphertext: &[u8], hmac: &[u8]) -> Result<(), anyhow::Error> {
    // Prepare export data
    let eph_pub_key = std::fs::read_to_string(EPH_PUB_FILE)?;
    let iv_b64 = base64::encode_block(iv);
    let ciphertext_b64 = base64::encode_block(ciphertext);
    let hmac_b64 = base64::encode_block(hmac);

    // Create the PEM-style format
    let content = format!(
        "{}\
         -----BEGIN AES-128-CBC IV-----\n\
         {}\n\
         -----END AES-128-CBC IV-----\n\
         -----BEGIN AES-128-CBC CIPHERTEXT-----\n\
         {}\n\
         -----END AES-128-CBC CIPHERTEXT-----\n\
         -----BEGIN SHA256-HMAC TAG-----\n\
         {}\n\
         -----END SHA256-HMAC TAG-----",
        eph_pub_key, iv_b64, ciphertext_b64, hmac_b64
    );

    // Write to file
    std::fs::write("ciphertext.txt", content)?;
    Ok(())
}

pub fn import(ciphertext: &str) -> Result<(String, Vec<u8>, Vec<u8>, Vec<u8>), anyhow::Error> {
    let content = std::fs::read_to_string(ciphertext)?;

    // Extract the ephemeral public key
    let eph_pub_key = content
        .split("-----BEGIN AES-128-CBC IV-----")
        .next()
        .with_context(|| "Failed to extract ephemeral public key")?
        .to_string();

    // Extract IV
    let iv = extract_pem_section(&content, "AES-128-CBC IV")?;

    // Extract ciphertext
    let ciphertext = extract_pem_section(&content, "AES-128-CBC CIPHERTEXT")?;

    // Extract HMAC tag
    let hmac = extract_pem_section(&content, "SHA256-HMAC TAG")?;

    Ok((eph_pub_key, iv, ciphertext, hmac))
}

fn extract_pem_section(content: &str, label: &str) -> Result<Vec<u8>, anyhow::Error> {
    let begin_marker = format!("-----BEGIN {}-----", label);
    let end_marker = format!("-----END {}-----", label);

    let start = content
        .find(&begin_marker)
        .context(format!("Could not find {}", begin_marker))?
        + begin_marker.len();

    let end = content[start..]
        .find(&end_marker)
        .context(format!("Could not find {}", end_marker))?
        + start;

    // Extract and trim the base64 content
    let content = content[start..end]
        .trim()
        .lines()
        .map(|line| line.trim())
        .collect::<String>();

    Ok(base64::decode_block(&content)?)
}

fn generate_hmac(iv: &[u8], ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    // Construct the data to be authenticated
    let mut mac_data = Vec::with_capacity(iv.len() + ciphertext.len());
    mac_data.extend_from_slice(&iv);
    mac_data.extend_from_slice(&ciphertext);

    let hmac_key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &hmac_key)?;
    signer.update(&mac_data)?;
    let hmac = signer.sign_to_vec()?;
    Ok(hmac)
}

fn verify_hmac(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    received_hmac: &[u8],
) -> Result<bool, anyhow::Error> {
    let generated_hmac = generate_hmac(iv, ciphertext, key)?;
    // Use OpenSSL's constant-time comparison
    Ok(memcmp::eq(&generated_hmac, received_hmac))
}
