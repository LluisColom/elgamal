mod cli;
mod crypto;
mod utils;

// Auxiliary ephemeral keypair filenames
const EPH_PRIV_FILE: &str = "ephpkey.pem";
const EPH_PUB_FILE: &str = "ephpubkey.pem";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Command {
    /// EC parameters and key generation
    Param,
    /// Encrypts a document
    Encrypt,
    /// Decrypts a document
    Decrypt,
}

fn main() -> Result<(), anyhow::Error> {
    match cli::choose_functionality()? {
        Command::Param => {
            let nid = cli::choose_group()?;
            // Generate the EC parameters
            let params = cli::choose_file("Params file name:", "data/params.pem")?;
            crypto::ec_params(nid, params.as_str())?;
            // Generate the keypair
            let private = cli::choose_file("Private key file name:", "data/priv.pem")?;
            crypto::gen_priv_key(params.as_str(), private.as_str())?;
            let public = cli::choose_file("Public key file name:", "data/pub.pem")?;
            crypto::gen_pub_key(private.as_str(), public.as_str())?;
            println!("Parameter generation successful");
        }
        Command::Encrypt => {
            let peer_key = cli::choose_file("Peer key file name:", "")?;
            anyhow::ensure!(std::fs::exists(&peer_key)?, "Peer key file not found");
            let document = cli::choose_file("Document file name:", "")?;
            anyhow::ensure!(std::fs::exists(&document)?, "Plaintext file not found");
            // Generate a new ephemeral keypair
            let params = cli::choose_file("Params file name:", "data/params.pem")?;
            crypto::gen_priv_key(params.as_str(), EPH_PRIV_FILE)?;
            crypto::gen_pub_key(EPH_PRIV_FILE, EPH_PUB_FILE)?;
            // Derive session key using ECDH
            let key = crypto::session_key(EPH_PRIV_FILE, peer_key.as_str())?;
            // Encrypt the document + HMAC
            let (iv, ciphertext, hmac) = crypto::encryption(&key, document.as_str())?;
            // Write data to ciphertext
            let filename = cli::choose_file("Ciphertext file name:", "data/ciphertext.txt")?;
            utils::export(filename.as_str(), EPH_PUB_FILE, &iv, &ciphertext, &hmac)?;
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PRIV_FILE)?;
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document encryption successful");
        }
        Command::Decrypt => {
            let document = cli::choose_file("Document file name:", "")?;
            anyhow::ensure!(std::fs::exists(&document)?, "Ciphertext file not found");
            // Extract data from ciphertext file
            let (peer_key, iv, ciphertext, hmac) = utils::import(&document)?;
            // Store peer ephemeral public key
            std::fs::write(EPH_PUB_FILE, peer_key.as_str())?;
            // Derive session key using ECDH
            let private = cli::choose_file("Private key file name:", "data/priv.pem")?;
            let key = crypto::session_key(private.as_str(), EPH_PUB_FILE)?;
            // Decrypt the document + HMAC verification
            let decrypted = crypto::decryption(&key, &iv, &ciphertext, &hmac)?;
            // Export decrypted message
            let filename = cli::choose_file("Decoded msg file name:", "data/decoded.txt")?;
            std::fs::write(filename, decrypted)?;
            // Remove ephemeral keypair
            std::fs::remove_file(EPH_PUB_FILE)?;
            println!("Document decryption successful");
        }
    }
    Ok(())
}
