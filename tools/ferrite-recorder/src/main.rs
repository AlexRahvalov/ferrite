//! CLI entrypoint for `ferrite-recorder`.
//!
//! Modes:
//! - Proxy mode (default): listens on `127.0.0.1:25566`, forwards to `127.0.0.1:25565`,
//!   and writes Login + Configuration frames into `recordings/session-<ts>-<n>.rec`.
//! - Inspect mode (`--inspect <file.rec>`): prints packet order, IDs, byte lengths,
//!   and `Login Success` structural metadata without dumping registry/tag contents.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use ferrite_recorder::{create_recording_file, ensure_loopback, inspect_file, proxy_session};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_LISTEN: &str = "127.0.0.1:25566";
const DEFAULT_UPSTREAM: &str = "127.0.0.1:25565";
const DEFAULT_OUT_DIR: &str = "recordings";

enum CliMode {
    Inspect(PathBuf),
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

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--inspect" => {
                let path = args
                    .next()
                    .context("missing file path after --inspect")?;
                return Ok(CliMode::Inspect(PathBuf::from(path)));
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
                "unknown argument `{other}` (supported: --inspect <file.rec>, --listen <addr>, --upstream <addr>, --out-dir <dir>)"
            ),
        }
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
        CliMode::Proxy {
            listen,
            upstream,
            out_dir,
        } => run_proxy(listen, upstream, &out_dir).await,
    }
}
