//! Pure-Rust SSH2 backend built on `russh`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use russh::client;
use russh_keys::PublicKeyBase64 as _;
use secrecy::ExposeSecret as _;
use spt_auth::{AuthConfig, AuthMethod, SecretRef as AuthSecretRef};
use spt_core::{BindAddr, Error, Result};
use spt_protocol::{
    Endpoint, ForwardHandle, ForwardId, ForwardState, LocalForwardSpec, RemoteForwardSpec,
    SessionInfo, TargetAddr, TunnelSession, UdpForwardSpec,
};
use spt_secrets::SecretBackend;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tracing::warn;

use crate::auth;
use crate::crypto::CryptoPolicy;
use crate::hostkey::TrustVerifier;

type RusshHandle = client::Handle<ClientHandler>;
type SharedHandle = Arc<AsyncMutex<RusshHandle>>;
type RemoteForwardMap = Arc<AsyncMutex<HashMap<RemoteForwardKey, mpsc::Sender<ForwardedTcpip>>>>;
type ConnectFuture = Pin<Box<dyn Future<Output = Result<RusshSsh2Session>> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RemoteForwardKey {
    address: String,
    port: u32,
}

struct ForwardedTcpip {
    channel: russh::Channel<client::Msg>,
}

struct ClientHandler {
    host: String,
    port: u16,
    trust: TrustVerifier,
    trust_failure: Arc<parking_lot::Mutex<Option<String>>>,
    remote_forwards: RemoteForwardMap,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match russh_key_to_ssh_key(server_public_key)
            .and_then(|key| self.trust.verify(&self.host, self.port, &key).map(|_| ()))
        {
            Ok(()) => Ok(true),
            Err(e) => {
                *self.trust_failure.lock() = Some(e.to_string());
                Ok(false)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let exact = RemoteForwardKey {
            address: connected_address.to_owned(),
            port: connected_port,
        };
        let sender = {
            let map = self.remote_forwards.lock().await;
            map.get(&exact).cloned().or_else(|| {
                map.iter()
                    .find(|(key, _)| key.port == connected_port)
                    .map(|(_, tx)| tx.clone())
            })
        };

        if let Some(tx) = sender {
            if tx.send(ForwardedTcpip { channel }).await.is_err() {
                warn!(
                    target: "spt_ssh2::russh",
                    address = connected_address,
                    port = connected_port,
                    "remote forward channel arrived after receiver closed"
                );
            }
        } else {
            let _ = channel.close().await;
            warn!(
                target: "spt_ssh2::russh",
                address = connected_address,
                port = connected_port,
                "dropping unregistered remote forward channel"
            );
        }
        Ok(())
    }
}

pub(crate) fn connect(
    endpoint: Endpoint,
    auth_cfg: AuthConfig,
    crypto: CryptoPolicy,
    trust: TrustVerifier,
    backends: Vec<Arc<dyn SecretBackend>>,
    has_hops: bool,
) -> ConnectFuture {
    Box::pin(
        async move { connect_inner(endpoint, auth_cfg, crypto, trust, backends, has_hops).await },
    )
}

async fn connect_inner(
    endpoint: Endpoint,
    auth_cfg: AuthConfig,
    crypto: CryptoPolicy,
    trust: TrustVerifier,
    backends: Vec<Arc<dyn SecretBackend>>,
    has_hops: bool,
) -> Result<RusshSsh2Session> {
    if has_hops {
        return Err(Error::UnsupportedPlatform(
            "russh SSH2 backend does not yet support multi-hop profiles; use ssh2_backend = \"libssh2\" for this profile while migration continues".into(),
        ));
    }

    let cfg = Arc::new(client::Config {
        preferred: build_preferred(&crypto)?,
        ..Default::default()
    });
    let trust_failure = Arc::new(parking_lot::Mutex::new(None));
    let remote_forwards = RemoteForwardMap::default();
    let handler = ClientHandler {
        host: endpoint.host.clone(),
        port: endpoint.port,
        trust,
        trust_failure: Arc::clone(&trust_failure),
        remote_forwards: Arc::clone(&remote_forwards),
    };

    let mut handle =
        match client::connect(cfg, (endpoint.host.clone(), endpoint.port), handler).await {
            Ok(handle) => handle,
            Err(e) => {
                if let Some(reason) = trust_failure.lock().clone() {
                    return Err(Error::TrustFailed(reason));
                }
                return Err(Error::NetworkUnreachable(format!(
                    "russh connect to {}:{}: {e}",
                    endpoint.host, endpoint.port
                )));
            }
        };

    run_auth(&mut handle, auth_cfg, backends).await?;
    let info = SessionInfo {
        backend: "ssh2-russh".into(),
        peer_version: None,
        negotiated: Some("russh negotiated algorithms".into()),
        established_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    Ok(RusshSsh2Session {
        handle: Arc::new(AsyncMutex::new(handle)),
        remote_forwards,
        info,
    })
}

pub(crate) struct RusshSsh2Session {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    info: SessionInfo,
}

#[async_trait]
impl TunnelSession for RusshSsh2Session {
    async fn open_local_forward(&mut self, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
        open_local(Arc::clone(&self.handle), spec).await
    }

    async fn open_remote_forward(&mut self, spec: &RemoteForwardSpec) -> Result<ForwardHandle> {
        open_remote(
            Arc::clone(&self.handle),
            Arc::clone(&self.remote_forwards),
            spec,
        )
        .await
    }

    async fn open_udp_forward(&mut self, _spec: &UdpForwardSpec) -> Result<ForwardHandle> {
        Err(Error::UnsupportedPlatform(
            "SSH2/russh does not support UDP forwards; use SSH3 for UDP forwarding".into(),
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        // russh drives protocol keepalives from client::Config. The trait call
        // remains a no-op so the supervisor can keep a uniform backend API.
        Ok(())
    }

    async fn close(self: Box<Self>) -> Result<()> {
        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "spt: session close", "")
            .await
            .map_err(|e| Error::SessionCloseFailed(format!("russh disconnect: {e}")))
    }

    fn session_info(&self) -> SessionInfo {
        self.info.clone()
    }
}

fn build_preferred(crypto: &CryptoPolicy) -> Result<russh::Preferred> {
    let mut preferred = russh::Preferred::DEFAULT;
    if !crypto.kex.is_empty() {
        preferred.kex = Cow::Owned(parse_names("kex", &crypto.kex)?);
    }
    if !crypto.host_keys.is_empty() {
        preferred.key = Cow::Owned(parse_names("host_key", &crypto.host_keys)?);
    }
    if !crypto.ciphers.is_empty() {
        preferred.cipher = Cow::Owned(parse_names("cipher", &crypto.ciphers)?);
    }
    if !crypto.macs.is_empty() {
        preferred.mac = Cow::Owned(parse_names("mac", &crypto.macs)?);
    }
    if !crypto.compression.is_empty() {
        preferred.compression = Cow::Owned(parse_names("compression", &crypto.compression)?);
    }
    Ok(preferred)
}

fn parse_names<T>(field: &str, values: &[String]) -> Result<Vec<T>>
where
    for<'a> T: TryFrom<&'a str>,
{
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(T::try_from(value.as_str()).map_err(|_| {
            Error::InvalidConfig(format!(
                "russh SSH2 backend does not support {field} algorithm `{value}`"
            ))
        })?);
    }
    Ok(parsed)
}

async fn run_auth(
    handle: &mut RusshHandle,
    auth_cfg: AuthConfig,
    backends: Vec<Arc<dyn SecretBackend>>,
) -> Result<()> {
    if auth_cfg.methods.is_empty() {
        return Err(Error::AuthFailed("no auth methods configured".into()));
    }

    let mut last_err: Option<Error> = None;
    for method in auth_cfg.methods {
        match try_auth_method(
            handle,
            auth_cfg.username.clone(),
            method.clone(),
            backends.clone(),
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {
                last_err = Some(Error::AuthFailed(format!(
                    "method `{}` rejected by server",
                    method_name(&method)
                )));
            }
            Err(e) => {
                warn!(
                    target: "spt_ssh2::russh",
                    method = method_name(&method),
                    error = %e,
                    "auth method failed"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::AuthFailed("all auth methods failed".into())))
}

async fn try_auth_method(
    handle: &mut RusshHandle,
    username: String,
    method: AuthMethod,
    backends: Vec<Arc<dyn SecretBackend>>,
) -> Result<bool> {
    match method {
        AuthMethod::Password { secret } => {
            let password = {
                let refs = backend_refs(&backends);
                let bytes = auth::resolve_secret(&refs, &secret)?;
                std::str::from_utf8(bytes.expose_secret())
                    .map_err(|_| Error::AuthFailed("password secret is not utf-8".into()))?
                    .to_owned()
            };
            handle
                .authenticate_password(username, password)
                .await
                .map_err(|e| Error::AuthFailed(format!("russh password auth: {e}")))
        }
        AuthMethod::PublicKey {
            identity_file,
            passphrase,
        } => {
            let passphrase = resolve_passphrase(&backends, passphrase.as_ref())?;
            let key = russh_keys::load_secret_key(&identity_file, passphrase.as_deref())
                .map_err(|e| Error::KeyFailure(format!("load private key: {e}")))?;
            handle
                .authenticate_publickey(username, Arc::new(key))
                .await
                .map_err(|e| Error::AuthFailed(format!("russh public key auth: {e}")))
        }
        AuthMethod::Certificate {
            cert,
            key,
            passphrase,
        } => {
            let passphrase = resolve_passphrase(&backends, passphrase.as_ref())?;
            let key = russh_keys::load_secret_key(&key, passphrase.as_deref())
                .map_err(|e| Error::KeyFailure(format!("load private key: {e}")))?;
            let cert = russh_keys::load_openssh_certificate(&cert)
                .map_err(|e| Error::KeyFailure(format!("load OpenSSH certificate: {e}")))?;
            handle
                .authenticate_openssh_cert(username, Arc::new(key), cert)
                .await
                .map_err(|e| Error::AuthFailed(format!("russh certificate auth: {e}")))
        }
        AuthMethod::Agent { .. } => Err(Error::UnsupportedPlatform(
            "SSH2/russh agent auth requires the dedicated russh agent actor; use public_key/password auth or ssh2_backend = \"libssh2\" for agent auth during migration".into(),
        )),
        AuthMethod::KeyboardInteractive { responder } => {
            try_keyboard_interactive(handle, username, responder, backends).await
        }
        AuthMethod::Bearer { .. }
        | AuthMethod::Basic { .. }
        | AuthMethod::OidcDeviceFlow { .. } => Err(Error::InvalidConfig(format!(
            "auth method `{}` is SSH3-only; not supported by SSH2/russh backend",
            method_name(&method)
        ))),
    }
}

async fn try_keyboard_interactive(
    handle: &mut RusshHandle,
    username: String,
    responder: Vec<spt_auth::KbiAnswer>,
    backends: Vec<Arc<dyn SecretBackend>>,
) -> Result<bool> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await
        .map_err(|e| Error::AuthFailed(format!("russh keyboard-interactive start: {e}")))?;
    loop {
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let prompt_lc = prompt.prompt.to_ascii_lowercase();
                    let answer = responder
                        .iter()
                        .find(|candidate| {
                            prompt_lc.contains(&candidate.pattern.to_ascii_lowercase())
                        })
                        .ok_or_else(|| {
                            Error::AuthFailed(format!(
                                "no keyboard-interactive responder matched prompt `{}`",
                                prompt.prompt
                            ))
                        })?;
                    if answer.echo != prompt.echo {
                        warn!(
                            target: "spt_ssh2::russh",
                            prompt = %prompt.prompt,
                            configured_echo = answer.echo,
                            server_echo = prompt.echo,
                            "keyboard-interactive echo flag mismatch"
                        );
                    }
                    let value = {
                        let refs = backend_refs(&backends);
                        let bytes = auth::resolve_secret(&refs, &answer.response)?;
                        std::str::from_utf8(bytes.expose_secret())
                            .map_err(|_| {
                                Error::AuthFailed("keyboard-interactive secret is not utf-8".into())
                            })?
                            .to_owned()
                    };
                    answers.push(value);
                }
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| {
                        Error::AuthFailed(format!("russh keyboard-interactive response: {e}"))
                    })?;
            }
        }
    }
}

fn resolve_passphrase(
    backends: &[Arc<dyn SecretBackend>],
    passphrase: Option<&AuthSecretRef>,
) -> Result<Option<String>> {
    match passphrase {
        None => Ok(None),
        Some(reference) => {
            let refs = backend_refs(backends);
            let bytes = auth::resolve_secret(&refs, reference)?;
            let value = std::str::from_utf8(bytes.expose_secret())
                .map_err(|_| Error::AuthFailed("passphrase secret is not utf-8".into()))?;
            Ok(Some(value.to_owned()))
        }
    }
}

fn backend_refs(backends: &[Arc<dyn SecretBackend>]) -> Vec<&dyn SecretBackend> {
    backends.iter().map(std::convert::AsRef::as_ref).collect()
}

async fn open_local(handle: SharedHandle, spec: &LocalForwardSpec) -> Result<ForwardHandle> {
    let bind = bind_addr_string(&spec.listen)?;
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::LocalBindFailed {
            address: bind.clone(),
            reason: e.to_string(),
        })?;

    let (state_tx, state_rx) = watch::channel(ForwardState::Listening);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    tokio::spawn(local_loop(
        listener,
        handle,
        spec.target.clone(),
        state_tx,
        close_rx,
        spec.max_connections,
        name.clone(),
    ));
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

async fn local_loop(
    listener: TcpListener,
    handle: SharedHandle,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    mut close_rx: oneshot::Receiver<()>,
    max_connections: Option<u32>,
    name: String,
) {
    let _ = state_tx.send(ForwardState::Active);
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "local accept failed");
                        continue;
                    }
                };
                if let Some(limit) = max_connections {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= limit {
                        warn!(target: "spt_ssh2::russh", forward = %name, "max_connections reached");
                        continue;
                    }
                }
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let handle = Arc::clone(&handle);
                let target = target.clone();
                let active = Arc::clone(&active);
                let name = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_local(handle, sock, peer, &target).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "local bridge failed");
                    }
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
    }
    let _ = state_tx.send(ForwardState::Stopped);
}

async fn bridge_local(
    handle: SharedHandle,
    mut sock: TcpStream,
    peer: SocketAddr,
    target: &TargetAddr,
) -> Result<()> {
    let channel = {
        let handle = handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                target.host.clone(),
                u32::from(target.port),
                peer.ip().to_string(),
                u32::from(peer.port()),
            )
            .await
            .map_err(|e| Error::RuntimeFailure(format!("russh direct-tcpip: {e}")))?
    };
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut sock, &mut stream)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("russh local bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn open_remote(
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    spec: &RemoteForwardSpec,
) -> Result<ForwardHandle> {
    let (address, requested_port) = remote_listen_parts(&spec.listen)?;
    let (tx, rx) = mpsc::channel(64);
    let initial_key = RemoteForwardKey {
        address: address.clone(),
        port: u32::from(requested_port),
    };
    remote_forwards
        .lock()
        .await
        .insert(initial_key.clone(), tx.clone());

    let bound_port = {
        let mut handle = handle.lock().await;
        match handle
            .tcpip_forward(address.clone(), u32::from(requested_port))
            .await
        {
            Ok(0) => u32::from(requested_port),
            Ok(port) => port,
            Err(e) => {
                remote_forwards.lock().await.remove(&initial_key);
                return Err(Error::RemoteBindFailed {
                    address: format!("{address}:{requested_port}"),
                    reason: format!("russh tcpip-forward: {e}"),
                });
            }
        }
    };

    let active_key = RemoteForwardKey {
        address: address.clone(),
        port: bound_port,
    };
    if active_key != initial_key {
        let mut map = remote_forwards.lock().await;
        map.remove(&initial_key);
        map.insert(active_key.clone(), tx);
    }

    let (state_tx, state_rx) = watch::channel(ForwardState::Active);
    let (close_tx, close_rx) = oneshot::channel();
    let id = ForwardId::new();
    let name = spec.name.clone();
    tokio::spawn(remote_loop(
        rx,
        close_rx,
        RemoteLoopContext {
            handle: Arc::clone(&handle),
            remote_forwards,
            key: active_key,
            target: spec.target.clone(),
            state_tx,
            name: name.clone(),
        },
    ));
    Ok(ForwardHandle::new(id, name, state_rx, close_tx))
}

struct RemoteLoopContext {
    handle: SharedHandle,
    remote_forwards: RemoteForwardMap,
    key: RemoteForwardKey,
    target: TargetAddr,
    state_tx: watch::Sender<ForwardState>,
    name: String,
}

async fn remote_loop(
    mut rx: mpsc::Receiver<ForwardedTcpip>,
    mut close_rx: oneshot::Receiver<()>,
    ctx: RemoteLoopContext,
) {
    loop {
        tokio::select! {
            _ = &mut close_rx => break,
            forwarded = rx.recv() => {
                let Some(forwarded) = forwarded else { break; };
                let target = ctx.target.clone();
                let name = ctx.name.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge_remote(forwarded.channel, &target).await {
                        warn!(target: "spt_ssh2::russh", forward = %name, error = %e, "remote bridge failed");
                    }
                });
            }
        }
    }

    ctx.remote_forwards.lock().await.remove(&ctx.key);
    let handle = ctx.handle.lock().await;
    let _ = handle
        .cancel_tcpip_forward(ctx.key.address, ctx.key.port)
        .await;
    let _ = ctx.state_tx.send(ForwardState::Stopped);
}

async fn bridge_remote(channel: russh::Channel<client::Msg>, target: &TargetAddr) -> Result<()> {
    let mut stream = channel.into_stream();
    let mut sock = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            Error::NetworkUnreachable(format!(
                "connect remote-forward target {}:{}: {e}",
                target.host, target.port
            ))
        })?;
    tokio::io::copy_bidirectional(&mut stream, &mut sock)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("russh remote bridge I/O: {e}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn bind_addr_string(addr: &BindAddr) -> Result<String> {
    match addr {
        BindAddr::Tcp(sock) => Ok(sock.to_string()),
        BindAddr::TcpHostPort { host, port } => Ok(format!("{host}:{port}")),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "SSH2/russh forward listeners on unix sockets are not implemented".into(),
        )),
    }
}

fn remote_listen_parts(addr: &BindAddr) -> Result<(String, u16)> {
    match addr {
        BindAddr::Tcp(sock) => Ok((sock.ip().to_string(), sock.port())),
        BindAddr::TcpHostPort { host, port } => Ok((host.clone(), *port)),
        BindAddr::Unix(_) => Err(Error::UnsupportedPlatform(
            "SSH2/russh remote forward listeners on unix sockets are not supported".into(),
        )),
    }
}

fn russh_key_to_ssh_key(key: &russh_keys::key::PublicKey) -> Result<ssh_key::PublicKey> {
    ssh_key::PublicKey::from_bytes(&key.public_key_bytes())
        .map_err(|e| Error::TrustFailed(format!("parse russh host key: {e}")))
}

fn method_name(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::PublicKey { .. } => "public_key",
        AuthMethod::Agent { .. } => "agent",
        AuthMethod::Password { .. } => "password",
        AuthMethod::KeyboardInteractive { .. } => "keyboard_interactive",
        AuthMethod::Certificate { .. } => "certificate",
        AuthMethod::Bearer { .. } => "bearer",
        AuthMethod::Basic { .. } => "basic",
        AuthMethod::OidcDeviceFlow { .. } => "oidc_device_flow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_algorithm_names() {
        let policy = CryptoPolicy {
            ciphers: vec!["aes256-ctr".into()],
            kex: vec!["curve25519-sha256".into()],
            macs: vec!["hmac-sha2-256".into()],
            host_keys: vec!["ssh-ed25519".into()],
            compression: vec!["none".into()],
        };
        let preferred = build_preferred(&policy).unwrap();
        assert_eq!(preferred.cipher.len(), 1);
        assert_eq!(preferred.kex.len(), 1);
        assert_eq!(preferred.mac.len(), 1);
        assert_eq!(preferred.key.len(), 1);
        assert_eq!(preferred.compression.len(), 1);
    }

    #[test]
    fn rejects_unknown_algorithm_names() {
        let policy = CryptoPolicy {
            ciphers: vec!["made-up".into()],
            ..CryptoPolicy::default()
        };
        assert!(matches!(
            build_preferred(&policy),
            Err(Error::InvalidConfig(_))
        ));
    }
}
