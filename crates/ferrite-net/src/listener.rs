//! TCP listener and resilient connection accept loop.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use ferrite_protocol::ServerStatus;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::session::handle_connection_with_timeouts;
use crate::{NetConfig, NetError, ACCEPT_ERROR_BACKOFF};

/// TCP server listener handling incoming client connections.
pub struct ServerListener {
    listener: TcpListener,
    status: Arc<ServerStatus>,
    config: NetConfig,
    connection_limit: Arc<Semaphore>,
}

impl ServerListener {
    /// Binds a TCP listener to `addr` with the given status payload and network limits.
    pub async fn bind(
        addr: &str,
        status: ServerStatus,
        config: NetConfig,
    ) -> Result<Self, NetError> {
        let listener = TcpListener::bind(addr).await?;
        let max_connections = config.max_connections.max(1);
        Ok(Self {
            listener,
            status: Arc::new(status),
            config: NetConfig {
                max_connections,
                ..config
            },
            connection_limit: Arc::new(Semaphore::new(max_connections)),
        })
    }

    /// Returns the local socket address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts connections until `shutdown` completes.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), NetError> {
        let listener = self.listener;
        serve_accept_loop(
            || async {
                let (stream, peer_addr) = listener.accept().await?;
                let _ = stream.set_nodelay(true);
                Ok((stream, peer_addr))
            },
            self.status,
            self.config,
            self.connection_limit,
            shutdown,
        )
        .await
    }
}

pub(crate) async fn serve_accept_loop<S, F, Fut>(
    mut accept_next: F,
    status: Arc<ServerStatus>,
    config: NetConfig,
    connection_limit: Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), NetError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<(S, SocketAddr)>>,
{
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                break;
            }
            accepted = accept_next() => {
                let (stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        eprintln!("failed to accept incoming connection: {err}");
                        tokio::select! {
                            () = &mut shutdown => break,
                            () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => continue,
                        }
                    }
                };
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    eprintln!(
                        "connection limit ({}) reached, rejecting {peer_addr}",
                        config.max_connections
                    );
                    continue;
                };

                let status = Arc::clone(&status);
                let read_timeout = config.read_timeout;
                let write_timeout = config.write_timeout;
                let capture_dir = config.capture_dir.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection_with_timeouts(
                        stream,
                        status,
                        read_timeout,
                        write_timeout,
                        capture_dir.as_deref(),
                    )
                    .await
                    {
                        eprintln!("connection {peer_addr} closed with error: {err}");
                    }
                });
            }
        }
    }

    Ok(())
}
