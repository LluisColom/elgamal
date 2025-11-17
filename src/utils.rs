use anyhow::Context;
use openssl::base64;

pub fn export(
    output: &str,
    pub_key: &str,
    iv: &[u8],
    ciphertext: &[u8],
    hmac: &[u8],
) -> Result<(), anyhow::Error> {
    // Prepare export data
    let eph_pub_key = std::fs::read_to_string(pub_key)?;
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
    std::fs::write(output, content)?;
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
