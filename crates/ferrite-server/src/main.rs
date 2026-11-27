//! Ferrite server binary entrypoint.

use anyhow::{Context, Result};
use ferrite_net::{NetConfig, ServerListener};
use ferrite_protocol::{
    Description, PlayersInfo, ServerStatus, VersionInfo, GAME_VERSION, PROTOCOL_VERSION,
};

#[tokio::main]
async fn main() -> Result<()> {
    let bind_addr = std::env::var("FERRITE_BIND").unwrap_or_else(|_| "0.0.0.0:25565".to_owned());
    let motd = std::env::var("FERRITE_MOTD").unwrap_or_else(|_| "Ferrite Server".to_owned());

    let status = ServerStatus {
        version: VersionInfo {
            name: GAME_VERSION.to_owned(),
            protocol: PROTOCOL_VERSION,
        },
        players: PlayersInfo {
            max: 100,
            online: 0,
            sample: Vec::new(),
        },
        description: Description { text: motd },
        favicon: None,
        enforces_secure_chat: None,
    };

    let capture_dir = std::env::var_os("FERRITE_CAPTURE_DIR").map(std::path::PathBuf::from);
    let net_config = NetConfig {
        capture_dir,
        ..NetConfig::default()
    };

    let listener = ServerListener::bind(&bind_addr, status, net_config)
        .await
        .with_context(|| format!("failed to bind TCP listener on {bind_addr}"))?;

    let local_addr = listener
        .local_addr()
        .context("failed to read bound local address")?;
    println!(
        "Ferrite listening on {local_addr} (version {GAME_VERSION}, protocol {PROTOCOL_VERSION})"
    );

    listener
        .serve(async {
            let _ = tokio::signal::ctrl_c().await;
            println!("Shutting down Ferrite...");
        })
        .await
        .context("server listener terminated with error")?;

    Ok(())
}
