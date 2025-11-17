use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::process::Command;

pub fn ec_params(nid: Nid, output_file: &str) -> Result<(), anyhow::Error> {
    let curve_name = nid.long_name()?;
    // No available rust bindings, so use the CLI
    Command::new("openssl")
        .args(&["ecparam", "-name", curve_name, "-out", output_file])
        .output()?;
    Ok(())
}

pub fn gen_keypair(nid: Nid, output_priv: &str, output_pub: &str) -> Result<(), anyhow::Error> {
    // Load the EC group
    let group = EcGroup::from_curve_name(nid)?;
    // Generate keypair
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    // Export the private key
    let private_pem = pkey.private_key_to_pem_pkcs8()?;
    std::fs::write(output_priv, private_pem)?;
    // Export the public key
    let public_pem = pkey.public_key_to_pem()?;
    std::fs::write(output_pub, public_pem)?;
    Ok(())
}
