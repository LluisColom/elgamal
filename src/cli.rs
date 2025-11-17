use cliclack::select;
use openssl::nid::Nid;

pub fn choose_group() -> Result<Nid, anyhow::Error> {
    let ec_groups = vec![
        (Nid::SECP256K1, "secp256k1", "Bitcoin/Ethereum"),
        (Nid::X9_62_PRIME256V1, "prime256v1", "NIST P-256"),
        (Nid::BRAINPOOL_P256R1, "brainpoolP256r1", "Brainpool"),
    ];

    let nid = select("Select EC group:")
        .items(&ec_groups)
        .initial_value(Nid::SECP256K1)
        .interact()?;

    Ok(nid)
}
