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

pub fn gen_keypair(
    param_file: &str,
    output_priv: &str,
    output_pub: &str,
) -> Result<(), anyhow::Error> {
    // No available rust bindings, so use the CLI
    let output = Command::new("openssl")
        .args(&["genpkey", "-paramfile", param_file, "-out", output_priv])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate keypair: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
