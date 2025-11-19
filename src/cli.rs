use super::Command;
use cliclack::{input, intro, outro, select};
use openssl::nid::Nid;

pub fn introduction() -> Result<(), anyhow::Error> {
    intro("Welcome to the ECDH-based encryption tool!")?;
    Ok(())
}

pub fn closing() -> Result<(), anyhow::Error> {
    outro("Done")?;
    Ok(())
}

pub fn choose_functionality() -> Result<Command, anyhow::Error> {
    let command = select("Select functionality:")
        .item(Command::Param, "EC parameters and key generation", "")
        .item(Command::Encrypt, "Document encryption", "")
        .item(Command::Decrypt, "Document decryption", "")
        .interact()?;

    Ok(command)
}

pub fn choose_group() -> Result<Nid, anyhow::Error> {
    let nid = select("Select EC group:")
        .item(Nid::SECP256K1, "secp256k1", "Bitcoin/Ethereum")
        .item(Nid::X9_62_PRIME256V1, "prime256v1", "NIST P-256")
        .item(Nid::BRAINPOOL_P256R1, "brainpoolP256r1", "Brainpool")
        .interact()?;

    Ok(nid)
}

pub fn choose_file(msg: &str, default: &str) -> Result<String, anyhow::Error> {
    // Prompt user for file name
    let input = if default.is_empty() {
        input(msg).interact()?
    } else {
        input(msg)
            .default_input(default)
            .placeholder(default)
            .interact()?
    };

    Ok(input)
}
