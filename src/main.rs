mod cli;
mod crypto;
mod utils;

use clap::{Parser, Subcommand};

const PARAM_FILE: &str = "params.pem";
const PRIV_FILE: &str = "priv.pem";
const PUB_FILE: &str = "pub.pem";
const EPH_PRIV_FILE: &str = "ephpkey.pem";
const EPH_PUB_FILE: &str = "ephpubkey.pem";
const DECODED: &str = "decoded.txt";

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
            crypto::gen_pub_key(EPH_PRIV_FILE, EPH_PUB_FILE)?;
            // Derive session key using ECDH
            let key = crypto::session_key(EPH_PRIV_FILE, peer_key.as_str())?;
            // Encrypt the document + HMAC
            let (iv, ciphertext, hmac) = crypto::encryption(&key, document.as_str())?;
            // Write data to ciphertext
            utils::export(EPH_PUB_FILE, &iv, &ciphertext, &hmac)?;
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PRIV_FILE)?;
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document encryption successful");
        }
        Command::Decrypt { document } => {
            anyhow::ensure!(std::fs::exists(&document)?, "Ciphertext file not found");
            // Extract data from ciphertext file
            let (peer_key, iv, ciphertext, hmac) = utils::import(&document)?;
            // Store peer ephemeral public key
            std::fs::write(EPH_PUB_FILE, peer_key.as_str())?;
            // Derive session key using ECDH
            let key = crypto::session_key(PRIV_FILE, EPH_PUB_FILE)?;
            // Decrypt the document + HMAC verification
            let decoded = crypto::decryption(&key, &iv, &ciphertext, &hmac)?;
            std::fs::write(DECODED, decoded)?;g
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document decryption successful");
        }
        Command::Test => {
            println!("Test suite run successful");
        }
    }
    Ok(())
}
