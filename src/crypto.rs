use openssl::nid::Nid;
use std::process::Command;

pub fn ec_params(nid: Nid, output_file: &str) -> Result<(), anyhow::Error> {
    let curve_name = nid.long_name()?;
    // No available rust bindings, so use the CLI
    Command::new("openssl")
        .args(&["ecparam", "-name", curve_name, "-out", output_file])
        .output()?;
    Ok(())
}

pub fn gen_priv_key(param_file: &str, output: &str) -> Result<(), anyhow::Error> {
    // No available rust bindings, so use the CLI
    let output = Command::new("openssl")
        .args(&["genpkey", "-paramfile", param_file, "-out", output])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate keypair: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn gen_pub_key(input: &str, output: &str) -> Result<(), anyhow::Error> {
    let output = Command::new("openssl")
        .args(&["pkey", "-in", input, "-pubout", "-out", output])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract pub key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
