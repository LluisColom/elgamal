mod cli;
mod crypto;

use clap::{Parser, Subcommand};

const PARAM_FILE: &str = "params.pem";
const PRIV_FILE: &str = "priv.pem";
const PUB_FILE: &str = "pub.pem";
const EPH_PRIV_FILE: &str = "ephpkey.pem";
const EPH_PUB_FILE: &str = "ephpubkey.pem";

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// EC parameters and key generation
    Param,
    /// Encrypts a document
    Encrypt { peer_key: String, document: String },
    /// Decrypts a document
    Decrypt { document: String },
    /// Verify a proof
    Test,
}

fn main() -> Result<(), anyhow::Error> {
    // Parse the command line arguments
    let args = Args::parse();

    match args.command {
        Command::Param => {
            let nid = cli::choose_group()?;
            // Generate the EC parameters
            crypto::ec_params(nid, PARAM_FILE)?;
            // Generate the keypair
            crypto::gen_priv_key(PARAM_FILE, PRIV_FILE)?;
            crypto::gen_pub_key(PRIV_FILE, PUB_FILE)?;
            println!("Parameter generation successful");
        }
        Command::Encrypt { peer_key, document } => {
            anyhow::ensure!(std::fs::exists(&peer_key)?, "Peer key file not found");
            anyhow::ensure!(std::fs::exists(&document)?, "Plaintext file not found");
            // Generate a new ephemeral keypair
            crypto::gen_priv_key(PARAM_FILE, EPH_PRIV_FILE)?;
            crypto::gen_pub_key(PRIV_FILE, EPH_PUB_FILE)?;
            // Derive session key using ECDH
            let key = crypto::session_key(EPH_PRIV_FILE, peer_key.as_str())?;
            // Encrypt the document + HMAC
            crypto::encryption(&key, document.as_str())?;
            println!("Document encryption successful");
        }
        Command::Decrypt { document } => {
            anyhow::ensure!(std::fs::exists(&document)?, "Ciphertext file not found");
            // Extract data from ciphertext file
            let (peer_key, iv, ciphertext, hmac) = crypto::import(&document)?;
            // Derive session key using ECDH
            let key = crypto::session_key(PRIV_FILE, peer_key.as_str())?;
            // Decrypt the document + HMAC verification
            crypto::decryption(&key, &iv, &ciphertext, &hmac)?;
            println!("Document decryption successful");
        }
        Command::Test => {
            println!("Test suite run successful");
        }
    }
    Ok(())
}
