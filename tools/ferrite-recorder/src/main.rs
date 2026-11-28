//! CLI entrypoint for `ferrite-recorder`.
//!
//! Modes:
//! - Proxy mode (default): listens on `127.0.0.1:25566`, forwards to `127.0.0.1:25565`,
//!   and writes Login + Configuration frames into `recordings/session-<ts>-<n>.rec`.
//! - Inspect mode (`--inspect <file.rec>`): prints packet order, IDs, byte lengths,
//!   and `Login` structural metadata without dumping registry/tag contents.
//! - Extract mode (`--extract-config <file.rec> [--out <path.json>] [--overwrite]`):
//!   strictly decodes `Configuration` skeleton (no NBT) into a gitignored JSON file
//!   and prints numeric counts only.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use ferrite_recorder::{
    create_recording_file, ensure_loopback, extract_config_file, inspect_file, proxy_session,
};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_LISTEN: &str = "127.0.0.1:25566";
const DEFAULT_UPSTREAM: &str = "127.0.0.1:25565";
const DEFAULT_OUT_DIR: &str = "recordings";
const DEFAULT_EXTRACT_OUT: &str = "server-data/configuration-26.3.json";

enum CliMode {
    Inspect(PathBuf),
    ExtractConfig {
        rec_path: PathBuf,
        out_path: PathBuf,
        overwrite: bool,
    },
    Proxy {
        listen: SocketAddr,
        upstream: SocketAddr,
        out_dir: PathBuf,
    },
}

fn parse_args() -> Result<CliMode> {
    let mut args = std::env::args().skip(1);
    let mut listen_str = DEFAULT_LISTEN.to_owned();
    let mut upstream_str = DEFAULT_UPSTREAM.to_owned();
    let mut out_dir = PathBuf::from(DEFAULT_OUT_DIR);
    let mut extract_rec: Option<PathBuf> = None;
    let mut extract_out: Option<PathBuf> = None;
    let mut overwrite = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--inspect" => {
                let path = args
                    .next()
                    .context("missing file path after --inspect")?;
                return Ok(CliMode::Inspect(PathBuf::from(path)));
            }
            "--extract-config" => {
                let path = args
                    .next()
                    .context("missing .rec file path after --extract-config")?;
                extract_rec = Some(PathBuf::from(path));
            }
            "--out" => {
                let path = args
                    .next()
                    .context("missing output file path after --out")?;
                extract_out = Some(PathBuf::from(path));
            }
            "--overwrite" => {
                overwrite = true;
            }
            "--listen" => {
                listen_str = args.next().context("missing address after --listen")?;
            }
            "--upstream" => {
                upstream_str = args.next().context("missing address after --upstream")?;
            }
            "--out-dir" => {
                let dir = args.next().context("missing path after --out-dir")?;
                out_dir = PathBuf::from(dir);
            }
            other => bail!(
                "unknown argument `{other}` (supported: --inspect <file.rec>, --extract-config <file.rec> [--out <file.json>] [--overwrite], --listen <addr>, --upstream <addr>, --out-dir <dir>)"
            ),
        }
    }

    if let Some(rec_path) = extract_rec {
        let out_path = extract_out.unwrap_or_else(|| PathBuf::from(DEFAULT_EXTRACT_OUT));
        return Ok(CliMode::ExtractConfig {
            rec_path,
            out_path,
            overwrite,
        });
    }

    let listen: SocketAddr = listen_str
        .parse()
        .with_context(|| format!("invalid --listen socket address `{listen_str}`"))?;
    let upstream: SocketAddr = upstream_str
        .parse()
        .with_context(|| format!("invalid --upstream socket address `{upstream_str}`"))?;

    ensure_loopback(listen)?;
    ensure_loopback(upstream)?;

    Ok(CliMode::Proxy {
        listen,
        upstream,
        out_dir,
    })
}

async fn run_proxy(listen: SocketAddr, upstream: SocketAddr, out_dir: &Path) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind recorder proxy on {listen}"))?;
    println!(
        "ferrite-recorder listening on {listen} -> forwarding to {upstream} (output: {})",
        out_dir.display()
    );

    let session_counter = AtomicU64::new(1);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down ferrite-recorder...");
                break;
            }
            accepted = listener.accept() => {
                let (client_stream, peer_addr) = accepted?;
                if let Err(err) = ensure_loopback(peer_addr) {
                    eprintln!("rejecting connection: {err}");
                    continue;
                }

                let session_id = session_counter.fetch_add(1, Ordering::Relaxed);
                let out_dir_owned = out_dir.to_path_buf();
                tokio::spawn(async move {
                    let upstream_stream = match TcpStream::connect(upstream).await {
                        Ok(s) => s,
                        Err(err) => {
                            eprintln!("session #{session_id}: failed to connect to upstream {upstream}: {err}");
                            return;
                        }
                    };

                    let (rec_path, rec_file) = match create_recording_file(&out_dir_owned, session_id).await {
                        Ok(pair) => pair,
                        Err(err) => {
                            eprintln!("session #{session_id}: failed to create .rec file: {err}");
                            return;
                        }
                    };

                    println!("session #{session_id}: recording to {}", rec_path.display());
                    if let Err(err) = proxy_session(client_stream, upstream_stream, rec_file).await {
                        eprintln!("session #{session_id} ended with I/O error: {err}");
                    } else {
                        println!("session #{session_id} closed cleanly ({})", rec_path.display());
                    }
                });
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args()? {
        CliMode::Inspect(path) => {
            let report = inspect_file(&path)
                .await
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            print!("{report}");
            Ok(())
        }
        CliMode::ExtractConfig {
            rec_path,
            out_path,
            overwrite,
        } => {
            let stats = extract_config_file(&rec_path, &out_path, overwrite)
                .await
                .with_context(|| {
                    format!(
                        "failed to extract configuration from {} to {}",
                        rec_path.display(),
                        out_path.display()
                    )
                })?;
            print!("{}", stats.format_counts_only());
            Ok(())
        }
        CliMode::Proxy {
            listen,
            upstream,
            out_dir,
        } => run_proxy(listen, upstream, &out_dir).await,
    }
}
