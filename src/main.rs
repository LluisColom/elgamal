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
    Encrypt,
    /// Decrypts a document
    Decrypt,
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
        Command::Encrypt => {
            // ensure!();
            // Generate a new ephemeral keypair
            crypto::gen_priv_key(PARAM_FILE, EPH_PRIV_FILE)?;

            println!("Document encryption successful");
        }
        Command::Decrypt => {
            // ensure!();
            println!("Document encryption successful");
        }
        Command::Test => {
            println!("Test suite run successful");
        }
    }
    Ok(())
}
