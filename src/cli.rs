use crate::crypto::CryptoGroup;
use clap::{Parser, Subcommand};
use cliclack::{input, intro, select};
use openssl::nid::Nid;

#[derive(Parser, Debug)]
#[command(name = "ec-crypto")]
#[command(about = "ElGamal Encryption Tool")]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Param,
    Encrypt {
        #[arg(short, long)]
        peer_key: String,
        #[arg(short, long)]
        document: String,
        #[arg(short, long)]
        parameters: String,
        #[arg(short, long)]
        output: String,
    },
    Decrypt {
        #[arg(short, long)]
        document: String,
        #[arg(short, long)]
        private_key: String,
        #[arg(short, long)]
        output: String,
    },
}

pub fn introduction() -> Result<(), anyhow::Error> {
    intro("Welcome to the ECDH-based encryption tool!")?;
    Ok(())
}

pub fn choose_group() -> Result<CryptoGroup, anyhow::Error> {
    let group = select("Select EC group:")
        .item(
            CryptoGroup::EC(Nid::SECP256K1),
            "secp256k1",
            "Bitcoin/Ethereum",
        )
        .item(
            CryptoGroup::EC(Nid::X9_62_PRIME256V1),
            "prime256v1",
            "NIST P-256",
        )
        .item(
            CryptoGroup::EC(Nid::BRAINPOOL_P256R1),
            "brainpoolP256r1",
            "Brainpool",
        )
        .item(CryptoGroup::DH, "DH RFC 5114 Group 3", "DH 2048-bit")
        .interact()?;

    Ok(group)
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
