use crate::cli::{Args, Command};
use clap::Parser;

mod cli;
mod crypto;
mod utils;

// Auxiliary ephemeral keypair filenames
const EPH_PRIV_FILE: &str = "ephpkey.pem";
const EPH_PUB_FILE: &str = "ephpubkey.pem";

fn main() -> Result<(), anyhow::Error> {
    // Read CLI arguments
    let args = Args::parse();
    match args.command {
        Command::Param => {
            cli::introduction()?;
            let group = cli::choose_group()?;
            // Generate the DH parameters
            let params = cli::choose_file("Params file name:", "data/params.pem")?;
            crypto::new_params(group, params.as_str())?;
            // Generate the keypair
            let private = cli::choose_file("Private key file name:", "data/priv.pem")?;
            crypto::new_private(params.as_str(), private.as_str())?;
            let public = cli::choose_file("Public key file name:", "data/pub.pem")?;
            crypto::new_public(private.as_str(), public.as_str())?;
            println!("Parameter generation successful");
        }
        Command::Encrypt {
            peer_key,
            document,
            parameters,
            output,
        } => {
            anyhow::ensure!(std::fs::exists(&peer_key)?, "Peer key file not found");
            anyhow::ensure!(std::fs::exists(&document)?, "Document file not found");
            anyhow::ensure!(std::fs::exists(&parameters)?, "Parameters file not found");
            // Generate a new ephemeral keypair
            crypto::new_private(&parameters, EPH_PRIV_FILE)?;
            crypto::new_public(EPH_PRIV_FILE, EPH_PUB_FILE)?;
            // Derive session key using ECDH
            let key = crypto::session_key(EPH_PRIV_FILE, peer_key.as_str())?;
            // Encrypt the document + HMAC
            let (iv, ciphertext, hmac) = crypto::encryption(&key, document.as_str())?;
            // Write data to ciphertext
            utils::export(&output, EPH_PUB_FILE, &iv, &ciphertext, &hmac)?;
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PRIV_FILE)?;
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document encryption successful");
        }
        Command::Decrypt {
            document,
            private_key,
            output,
        } => {
            anyhow::ensure!(std::fs::exists(&document)?, "Ciphertext file not found");
            anyhow::ensure!(std::fs::exists(&private_key)?, "Ciphertext file not found");
            // Extract data from ciphertext file
            let (peer_key, iv, ciphertext, hmac) = utils::import(&document)?;
            // Store peer ephemeral public key
            std::fs::write(EPH_PUB_FILE, peer_key.as_str())?;
            // Derive session key using ECDH
            let key = crypto::session_key(&private_key, EPH_PUB_FILE)?;
            // Decrypt the document + HMAC verification
            let decrypted = crypto::decryption(&key, &iv, &ciphertext, &hmac)?;
            // Export decrypted message
            std::fs::write(output, decrypted)?;
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document decryption successful");
        }
    }
    Ok(())
}
