use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use openssl::sign::Signer;
use openssl::symm::{Cipher, decrypt, encrypt};
use std::process::Command;

const AES_KEY_SIZE: usize = 16;
const SESSION_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CryptoGroup {
    EC(Nid),
    DH, // RFC 5114 Group 3
}

pub fn new_params(group: CryptoGroup, output_file: &str) -> Result<(), anyhow::Error> {
    // No available rust bindings, so use the CLI
    let output = match group {
        CryptoGroup::EC(nid) => {
            let curve_name = nid.long_name()?;
            Command::new("openssl")
                .args(["ecparam", "-name", curve_name, "-out", output_file])
                .output()?
        }
        CryptoGroup::DH => {
            Command::new("openssl")
                .args([
                    "genpkey",
                    "-genparam",
                    "-algorithm",
                    "DHX",
                    "-pkeyopt",
                    "dh_rfc5114:3", // Always use group 3
                    "-out",
                    output_file,
                ])
                .output()?
        }
    };

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate DH parameters: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn new_private(param_file: &str, output: &str) -> Result<(), anyhow::Error> {
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

pub fn new_public(input: &str, output: &str) -> Result<(), anyhow::Error> {
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

pub fn encryption(key: &[u8], input: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), anyhow::Error> {
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

    Ok((iv.to_vec(), ciphertext, hmac))
}

pub fn decryption(
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    hmac: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
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

    Ok(plaintext)
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
