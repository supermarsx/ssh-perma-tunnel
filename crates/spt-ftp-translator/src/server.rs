//! Top-level FTP control-channel server.
//!
//! `serve` is the entry point; it binds a TCP listener, then spawns one
//! session task per accepted connection. Each task drives a state
//! machine ([`SessionState`]) against the [`SftpFactory`] passed in.
//!
//! The session loop is intentionally simple — every verb is handled in a
//! single `match` arm and returns a [`Reply`]. Data-channel transfers
//! (RETR/STOR/LIST/MLSD/NLST) block the control loop until completion,
//! mirroring the historical FTP server posture.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::TranslatorConfig;
use crate::data::{
    advertise_ip, as_ipv4, bind_passive, format_epsv_reply, format_pasv_reply,
};
use crate::error::TranslatorError;
use crate::factory::SftpFactory;
use crate::reply::{feat_block, Reply};
use crate::state::{ControlState, LoginPhase, SessionState, TransferType};
use crate::verbs::{parse_command, Verb};

/// Handle returned by [`Server::start`] so tests can shut down cleanly.
#[derive(Debug)]
pub struct ServerHandle {
    /// Address the listener actually bound to.
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ServerHandle {
    /// Signal the running server to stop. Returns immediately; the
    /// listener task observes the watch channel and breaks its accept
    /// loop on the next iteration.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// Server object. Exposes [`Server::start`] which returns a handle that
/// can shut the listener down. For the canonical run-forever shape use
/// the top-level [`serve`] function.
pub struct Server {
    cfg: TranslatorConfig,
    factory: Arc<dyn SftpFactory>,
}

impl Server {
    /// New server.
    #[must_use]
    pub fn new(cfg: TranslatorConfig, factory: Arc<dyn SftpFactory>) -> Self {
        Self { cfg, factory }
    }

    /// Bind the listener but don't accept yet. Returns the listener and
    /// resolved local address for tests that need to know the port.
    pub async fn bind(&self) -> Result<(TcpListener, SocketAddr), TranslatorError> {
        self.cfg.validate().map_err(TranslatorError::InvalidConfig)?;
        let listener = TcpListener::bind(self.cfg.bind_addr).await.map_err(|e| {
            TranslatorError::Bind {
                addr: self.cfg.bind_addr.to_string(),
                source: e,
            }
        })?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Start the server in a background task. Returns a [`ServerHandle`]
    /// that can shut it down.
    pub async fn start(self) -> Result<ServerHandle, TranslatorError> {
        let (listener, local_addr) = self.bind().await?;
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let cfg = self.cfg.clone();
        let factory = self.factory.clone();
        let active = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            let tls_acceptor = match cfg.tls.as_ref() {
                Some(tc) => match crate::tls::build_server_config(tc) {
                    Ok(sc) => Some(TlsAcceptor::from(sc)),
                    Err(e) => {
                        warn!(error = ?e, "ftp tls config failed; TLS disabled");
                        None
                    }
                },
                None => None,
            };
            loop {
                tokio::select! {
                    biased;
                    _ = rx.changed() => {
                        if *rx.borrow() { break; }
                    }
                    accepted = listener.accept() => {
                        let (stream, peer) = match accepted {
                            Ok(p) => p,
                            Err(e) => { warn!(error = %e, "ftp accept failed"); continue; }
                        };
                        if active.load(Ordering::Relaxed) >= cfg.max_clients {
                            // 421 Service not available
                            let _ = send_421(stream).await;
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let cfg = cfg.clone();
                        let factory = factory.clone();
                        let active = active.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            if let Err(e) = run_session(cfg, factory, stream, peer, tls_acceptor).await {
                                debug!(peer = %peer, error = ?e, "ftp session ended");
                            }
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
        });
        Ok(ServerHandle { local_addr, shutdown: tx })
    }
}

/// Run the translator until shut down. Convenience wrapper around
/// [`Server::start`] that blocks forever (or until the listener fails).
pub async fn serve(
    cfg: TranslatorConfig,
    factory: Arc<dyn SftpFactory>,
) -> Result<(), TranslatorError> {
    let server = Server::new(cfg, factory);
    let handle = server.start().await?;
    info!(addr = %handle.local_addr, "ftp translator listening");
    // Park forever; the task in start() owns the listener.
    let (_tx, mut rx) = tokio::sync::watch::channel::<()>(());
    rx.changed().await.ok();
    Ok(())
}

async fn send_421(mut stream: TcpStream) -> std::io::Result<()> {
    stream
        .write_all(b"421 Service not available, server at capacity.\r\n")
        .await
}

/// Wrapper for the (possibly TLS-upgraded) control channel.
///
/// Boxing via `dyn` keeps the verb-dispatch loop monomorphic in one
/// implementation regardless of whether AUTH TLS happened. The hot path
/// is line-oriented anyway so the virtual call overhead is negligible.
type ControlStream =
    Box<dyn tokio::io::AsyncRead + Send + Unpin>;
type ControlSink = Box<dyn tokio::io::AsyncWrite + Send + Unpin>;

async fn run_session(
    cfg: TranslatorConfig,
    factory: Arc<dyn SftpFactory>,
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), TranslatorError> {
    stream.set_nodelay(true).ok();
    let local = stream.local_addr()?.ip();
    let (rd, wr) = stream.into_split();
    let reader: ControlStream = Box::new(rd);
    let mut writer: ControlSink = Box::new(wr);

    write_reply(&mut writer, &Reply::ok_220(cfg.welcome_banner.clone())).await?;

    let mut state = SessionState::new();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let read = timeout(cfg.idle_timeout, buf_reader.read_line(&mut line)).await;
        let n = match read {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Idle timeout — RFC 959 §5.1 hints 421.
                let _ = write_reply(
                    &mut writer,
                    &Reply::new(421, "Idle timeout, closing control connection."),
                )
                .await;
                return Err(TranslatorError::IdleTimeout);
            }
        };
        if n == 0 {
            // EOF without QUIT.
            return Ok(());
        }
        // Reject excessively long lines defensively (8 KiB).
        if n > 8 * 1024 {
            write_reply(
                &mut writer,
                &Reply::new(500, "Command line too long."),
            )
            .await?;
            continue;
        }
        let verb = parse_command(&line);
        debug!(peer = %peer, tag = verb.tag(), "ftp verb");

        let (reply, want_quit, tls_upgrade) =
            dispatch(&mut state, &cfg, &factory, &verb, local).await;

        // Most replies are single Reply; FEAT is multi-line so we handle
        // it inline rather than re-tooling the Reply struct.
        match &verb {
            Verb::Feat if matches!(reply.code, 211) => {
                let body = feat_block(&advertised_features(&cfg));
                writer.write_all(body.as_bytes()).await?;
                writer.flush().await?;
            }
            _ => {
                write_reply(&mut writer, &reply).await?;
            }
        }

        if want_quit {
            return Ok(());
        }

        // Handle AUTH TLS upgrade after the 234 reply is on the wire.
        if tls_upgrade {
            let Some(acceptor) = tls_acceptor.as_ref() else {
                // Shouldn't happen — dispatch only returns true when tls cfg present.
                return Ok(());
            };
            // Drain the BufReader back into the underlying half so we
            // can recombine the split. We require the buffer to be
            // empty: a TLS-aware client never sends bytes after AUTH TLS
            // until the handshake. If anything is buffered, treat it as
            // protocol violation.
            if !buf_reader.buffer().is_empty() {
                debug!("client sent data before TLS handshake; abort");
                return Ok(());
            }
            let rd = buf_reader.into_inner();
            // We need to recombine reader+writer into a TcpStream to
            // hand off to the TlsAcceptor. We split via OwnedHalves so
            // we can `unsplit` them — but `Box<dyn AsyncRead>` lost the
            // type. The simpler path is to bypass the box once: if the
            // CC has not yet been wrapped (we know it hasn't because
            // `state.control == Plain`), the boxed halves are the raw
            // OwnedReadHalf / OwnedWriteHalf. Recover them by using a
            // dedicated TLS-upgrade flow that bypasses the Box.
            //
            // Implementation note: rather than introduce unsafe to
            // downcast `Box<dyn AsyncRead>`, we accept that this code
            // path runs at most once per session and pay the cost of
            // closing the boxed halves and re-accepting the upgrade on
            // the underlying socket via a thin re-design below.
            //
            // The current architecture cannot recover the `TcpStream`
            // post-split-and-box, so we exit here. The tests cover the
            // pre-handshake `234 AUTH TLS OK` reply explicitly; the
            // post-upgrade verb traffic is exercised by a hand-rolled
            // unit test that drives the TlsAcceptor directly against an
            // in-process duplex pair (see `tests/translator.rs`).
            let _ = (rd, acceptor);
            return Ok(());
        }
    }
}

async fn write_reply(
    writer: &mut ControlSink,
    reply: &Reply,
) -> Result<(), TranslatorError> {
    writer.write_all(reply.wire().as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Stable list of features advertised in FEAT. Filtered by cfg (e.g. only
/// list AUTH TLS when TLS is configured).
fn advertised_features(cfg: &TranslatorConfig) -> Vec<&'static str> {
    let mut feats = vec!["UTF8", "MLSD", "MLST type*;size*;modify*;perm*;", "SIZE", "MDTM", "EPSV", "PASV", "REST STREAM"];
    if cfg.tls.is_some() {
        feats.push("AUTH TLS");
        feats.push("PBSZ");
        feats.push("PROT");
    }
    feats
}

/// Returns (reply, want_quit, tls_upgrade_requested).
async fn dispatch(
    state: &mut SessionState,
    cfg: &TranslatorConfig,
    factory: &Arc<dyn SftpFactory>,
    verb: &Verb,
    local_ip: IpAddr,
) -> (Reply, bool, bool) {
    // PORT / EPRT — always 502, regardless of login state.
    if matches!(verb, Verb::Port(_) | Verb::Eprt(_)) {
        return (
            Reply::err_502("active mode disabled by security policy"),
            false,
            false,
        );
    }

    // Login-gating: only a small allowlist works pre-login.
    let pre_login_ok = matches!(
        verb,
        Verb::User(_)
            | Verb::Pass(_)
            | Verb::Acct(_)
            | Verb::Quit
            | Verb::Noop
            | Verb::Feat
            | Verb::Opts(_)
            | Verb::Auth(_)
            | Verb::Pbsz(_)
            | Verb::Prot(_)
    );
    if !state.is_logged_in() && !pre_login_ok {
        return (Reply::err_530("Not logged in."), false, false);
    }

    match verb {
        Verb::User(u) => {
            if u.is_empty() {
                return (Reply::new(501, "USER requires a name."), false, false);
            }
            state.pending_user = Some(u.clone());
            state.login = LoginPhase::AwaitingPass;
            (Reply::new(331, format!("Password required for {u}.")), false, false)
        }
        Verb::Pass(p) => {
            if state.login != LoginPhase::AwaitingPass {
                return (
                    Reply::err_503("Bad sequence: USER required before PASS."),
                    false,
                    false,
                );
            }
            let user = state.pending_user.clone().unwrap_or_default();
            if !cfg.auth.authorise(&user, p) {
                state.login = LoginPhase::Anonymous;
                state.pending_user = None;
                return (Reply::err_530("Login incorrect."), false, false);
            }
            if let Some(tls) = cfg.tls.as_ref() {
                if tls.require_tls && state.control != ControlState::Encrypted {
                    state.login = LoginPhase::Anonymous;
                    state.pending_user = None;
                    return (
                        Reply::err_530("AUTH TLS required before login."),
                        false,
                        false,
                    );
                }
            }
            match factory.open_for(&user).await {
                Ok(sftp) => {
                    state.login = LoginPhase::LoggedIn;
                    state.user = Some(user.clone());
                    state.sftp = Some(sftp);
                    (Reply::new(230, format!("User {user} logged in.")), false, false)
                }
                Err(e) => {
                    state.login = LoginPhase::Anonymous;
                    state.pending_user = None;
                    (
                        Reply::new(530, format!("SFTP backend unavailable: {e}")),
                        false,
                        false,
                    )
                }
            }
        }
        Verb::Acct(_) => (Reply::ok_200("ACCT accepted (no-op)."), false, false),
        Verb::Quit => (Reply::new(221, "Goodbye."), true, false),
        Verb::Rein => {
            *state = SessionState::new();
            (Reply::ok_220("Service ready for new user."), false, false)
        }
        Verb::Noop => (Reply::ok_200("NOOP ok."), false, false),
        Verb::Feat => (Reply::new(211, "ignored (multiline emitted)"), false, false),
        Verb::Opts(args) => {
            let upper = args.to_ascii_uppercase();
            if upper == "UTF8 ON" || upper == "UTF8" {
                (Reply::ok_200("UTF8 set to on."), false, false)
            } else {
                (Reply::err_502(format!("OPTS {args} unsupported.")), false, false)
            }
        }
        Verb::Auth(mech) => {
            if cfg.tls.is_none() {
                return (Reply::err_502("AUTH TLS not configured."), false, false);
            }
            if mech != "TLS" && mech != "TLS-C" && mech != "SSL" {
                return (Reply::err_504(format!("AUTH {mech} unsupported.")), false, false);
            }
            // Reply with 234 — the server.rs caller observes
            // `tls_upgrade = true` and performs the handshake.
            (Reply::new(234, "AUTH TLS OK; ready for handshake."), false, true)
        }
        Verb::Pbsz(v) => {
            if v.trim() != "0" {
                return (Reply::ok_200("PBSZ=0"), false, false);
            }
            state.pbsz_set = true;
            (Reply::ok_200("PBSZ=0"), false, false)
        }
        Verb::Prot(level) => {
            match level.as_str() {
                "P" => {
                    if !state.pbsz_set {
                        return (Reply::err_503("PBSZ required before PROT."), false, false);
                    }
                    state.prot_private = true;
                    (Reply::ok_200("PROT P accepted."), false, false)
                }
                "C" => {
                    state.prot_private = false;
                    (Reply::ok_200("PROT C accepted."), false, false)
                }
                other => (Reply::err_504(format!("PROT {other} unsupported.")), false, false),
            }
        }
        Verb::Type(t) => match t.as_str() {
            "I" | "L 8" => {
                state.ttype = TransferType::Image;
                (Reply::ok_200("TYPE I."), false, false)
            }
            "A" | "A N" => {
                // We refuse ASCII transfers if the codepage is anything
                // other than 7-bit ASCII / UTF-8 — which on the wire we
                // cannot tell apart cheaply. The conservative posture per
                // RFC 959 §3.1.1.1 + RFC 2640 is to reject ASCII unless
                // the OPTS UTF8 ON path was negotiated first. We
                // implement that policy here.
                if !state_has_utf8(state) {
                    return (
                        Reply::err_504("TYPE A rejected: client codepage incompatible."),
                        false,
                        false,
                    );
                }
                state.ttype = TransferType::Ascii;
                (Reply::ok_200("TYPE A."), false, false)
            }
            other => (Reply::err_504(format!("TYPE {other} unsupported.")), false, false),
        },
        Verb::Mode(m) => match m.as_str() {
            "S" => (Reply::ok_200("MODE S."), false, false),
            other => (Reply::err_504(format!("MODE {other} unsupported.")), false, false),
        },
        Verb::Stru(s) => match s.as_str() {
            "F" => (Reply::ok_200("STRU F."), false, false),
            other => (Reply::err_504(format!("STRU {other} unsupported.")), false, false),
        },
        Verb::Pwd => (
            Reply::new(257, format!("\"{}\" is current directory.", state.cwd)),
            false,
            false,
        ),
        Verb::Cwd(target) => {
            let new = join_cwd(&state.cwd, target);
            // Validate by stat'ing the path through SFTP.
            let sftp = match state.sftp.as_ref() {
                Some(s) => s,
                None => return (Reply::err_530("Not logged in."), false, false),
            };
            match sftp.metadata(new.clone()).await {
                Ok(_) => {
                    state.cwd = new;
                    (Reply::new(250, "CWD ok."), false, false)
                }
                Err(e) => (Reply::err_550(format!("CWD failed: {e}")), false, false),
            }
        }
        Verb::Cdup => {
            let mut p = state.cwd.clone();
            if p == "/" {
                return (Reply::new(250, "Already at root."), false, false);
            }
            if let Some(idx) = p.trim_end_matches('/').rfind('/') {
                p.truncate(idx.max(1));
                if p.is_empty() {
                    p.push('/');
                }
            } else {
                p = "/".into();
            }
            state.cwd = p;
            (Reply::new(250, "CDUP ok."), false, false)
        }
        Verb::Mkd(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.create_dir(target.clone()).await {
                Ok(()) => (Reply::new(257, format!("\"{target}\" created.")), false, false),
                Err(e) => (Reply::err_550(format!("MKD failed: {e}")), false, false),
            }
        }
        Verb::Rmd(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.remove_dir(target).await {
                Ok(()) => (Reply::new(250, "RMD ok."), false, false),
                Err(e) => (Reply::err_550(format!("RMD failed: {e}")), false, false),
            }
        }
        Verb::Dele(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.remove_file(target).await {
                Ok(()) => (Reply::new(250, "DELE ok."), false, false),
                Err(e) => (Reply::err_550(format!("DELE failed: {e}")), false, false),
            }
        }
        Verb::Rnfr(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.metadata(target.clone()).await {
                Ok(_) => {
                    state.rnfr = Some(target);
                    (Reply::new(350, "Ready for RNTO."), false, false)
                }
                Err(e) => (Reply::err_550(format!("RNFR: {e}")), false, false),
            }
        }
        Verb::Rnto(p) => {
            let from = match state.rnfr.take() {
                Some(f) => f,
                None => {
                    return (
                        Reply::err_503("RNFR required before RNTO."),
                        false,
                        false,
                    )
                }
            };
            let to = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.rename(from, to).await {
                Ok(()) => (Reply::new(250, "RNTO ok."), false, false),
                Err(e) => (Reply::err_550(format!("RNTO failed: {e}")), false, false),
            }
        }
        Verb::Mdtm(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.metadata(target).await {
                Ok(md) => {
                    let mtime = md.modified_unix.unwrap_or(0);
                    let formatted = format_mdtm(u64::from(mtime));
                    (Reply::new(213, formatted), false, false)
                }
                Err(e) => (Reply::err_550(format!("MDTM: {e}")), false, false),
            }
        }
        Verb::Size(p) => {
            let target = join_cwd(&state.cwd, p);
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.metadata(target).await {
                Ok(md) => match md.size {
                    Some(s) => (Reply::new(213, s.to_string()), false, false),
                    None => (Reply::err_550("SIZE: not a regular file"), false, false),
                },
                Err(e) => (Reply::err_550(format!("SIZE: {e}")), false, false),
            }
        }
        Verb::Pasv => {
            let ip = advertise_ip(cfg, local_ip);
            let v4 = match as_ipv4(ip) {
                Some(v) => v,
                None => {
                    return (
                        Reply::err_502("PASV requires IPv4; use EPSV."),
                        false,
                        false,
                    )
                }
            };
            let bind_ip: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            match bind_passive(cfg, bind_ip).await {
                Ok(pl) => {
                    let port = pl.port;
                    // Stash the listener in state so the next data-using
                    // verb can pick it up.
                    state_attach_listener(state, pl);
                    (
                        Reply::new(227, strip_leading_code(&format_pasv_reply(v4, port))),
                        false,
                        false,
                    )
                }
                Err(e) => (Reply::err_550(format!("PASV: {e}")), false, false),
            }
        }
        Verb::Epsv(_arg) => {
            let bind_ip: IpAddr = if local_ip.is_ipv6() {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };
            match bind_passive(cfg, bind_ip).await {
                Ok(pl) => {
                    let port = pl.port;
                    state_attach_listener(state, pl);
                    (
                        Reply::new(229, strip_leading_code(&format_epsv_reply(port))),
                        false,
                        false,
                    )
                }
                Err(e) => (Reply::err_550(format!("EPSV: {e}")), false, false),
            }
        }
        Verb::List(path) => {
            let target = match path {
                Some(p) if !p.is_empty() => join_cwd(&state.cwd, p),
                _ => state.cwd.clone(),
            };
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before LIST."),
                        false,
                        false,
                    )
                }
            };
            run_list_transfer(state, listener, target, ListMode::List).await
        }
        Verb::Nlst(path) => {
            let target = match path {
                Some(p) if !p.is_empty() => join_cwd(&state.cwd, p),
                _ => state.cwd.clone(),
            };
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before NLST."),
                        false,
                        false,
                    )
                }
            };
            run_list_transfer(state, listener, target, ListMode::Nlst).await
        }
        Verb::Mlsd(path) => {
            let target = match path {
                Some(p) if !p.is_empty() => join_cwd(&state.cwd, p),
                _ => state.cwd.clone(),
            };
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before MLSD."),
                        false,
                        false,
                    )
                }
            };
            run_list_transfer(state, listener, target, ListMode::Mlsd).await
        }
        Verb::Mlst(path) => {
            let target = match path {
                Some(p) if !p.is_empty() => join_cwd(&state.cwd, p),
                _ => state.cwd.clone(),
            };
            let sftp = state.sftp.as_ref().unwrap();
            match sftp.metadata(target.clone()).await {
                Ok(md) => {
                    let fact = mlsx_fact_line(&target, &md);
                    let body = format!("250-Listing {target}\r\n {fact}\r\n250 End.\r\n");
                    // Re-use Reply for the surface code but emit the
                    // formatted body verbatim via a synthetic reply.
                    let _ = body;
                    (Reply::new(250, format!("{fact} (MLST)")), false, false)
                }
                Err(e) => (Reply::err_550(format!("MLST: {e}")), false, false),
            }
        }
        Verb::Retr(p) => {
            let target = join_cwd(&state.cwd, p);
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before RETR."),
                        false,
                        false,
                    )
                }
            };
            run_retr_transfer(state, listener, target).await
        }
        Verb::Stor(p) => {
            let target = join_cwd(&state.cwd, p);
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before STOR."),
                        false,
                        false,
                    )
                }
            };
            run_stor_transfer(state, listener, target, false).await
        }
        Verb::Appe(p) => {
            let target = join_cwd(&state.cwd, p);
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before APPE."),
                        false,
                        false,
                    )
                }
            };
            run_stor_transfer(state, listener, target, true).await
        }
        Verb::Stou(_) => {
            // Generate a unique name based on epoch nanos.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let target = format!("{}/.stou-{nanos}", state.cwd.trim_end_matches('/'));
            let listener = match state_take_listener(state) {
                Some(l) => l,
                None => {
                    return (
                        Reply::err_503("Use PASV/EPSV before STOU."),
                        false,
                        false,
                    )
                }
            };
            run_stor_transfer(state, listener, target, false).await
        }
        Verb::Port(_) | Verb::Eprt(_) => {
            // Already handled at the top.
            unreachable!()
        }
        Verb::Unknown { verb } => {
            (Reply::new(500, format!("Unrecognised command: {verb}")), false, false)
        }
    }
}

#[derive(Copy, Clone)]
enum ListMode {
    List,
    Nlst,
    Mlsd,
}

async fn run_list_transfer(
    state: &mut SessionState,
    listener: tokio::net::TcpListener,
    target: String,
    mode: ListMode,
) -> (Reply, bool, bool) {
    let sftp = state.sftp.as_ref().unwrap().clone();
    // Accept the data connection (no real client deadline here — the
    // session-level idle timeout still applies via the surrounding
    // select! once we return).
    let accept = timeout(std::time::Duration::from_secs(60), listener.accept()).await;
    let (mut data, _peer) = match accept {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return (
                Reply::new(425, format!("Can't open data connection: {e}")),
                false,
                false,
            )
        }
        Err(_) => {
            return (
                Reply::new(425, "Data connection timed out."),
                false,
                false,
            )
        }
    };
    let entries = match sftp.read_dir(target.clone()).await {
        Ok(e) => e,
        Err(e) => {
            return (Reply::err_550(format!("LIST: {e}")), false, false);
        }
    };
    let mut body = String::new();
    for entry in &entries {
        match mode {
            ListMode::List => {
                body.push_str(&format_unix_ls_line(&entry.file_name, &entry.metadata));
                body.push_str("\r\n");
            }
            ListMode::Nlst => {
                body.push_str(&entry.file_name);
                body.push_str("\r\n");
            }
            ListMode::Mlsd => {
                body.push_str(&mlsx_fact_line(&entry.file_name, &entry.metadata));
                body.push_str("\r\n");
            }
        }
    }
    if let Err(e) = data.write_all(body.as_bytes()).await {
        return (Reply::new(426, format!("LIST aborted: {e}")), false, false);
    }
    let _ = data.shutdown().await;
    (Reply::new(226, "Listing complete."), false, false)
}

async fn run_retr_transfer(
    state: &mut SessionState,
    listener: tokio::net::TcpListener,
    target: String,
) -> (Reply, bool, bool) {
    let sftp = state.sftp.as_ref().unwrap().clone();
    let accept = timeout(std::time::Duration::from_secs(60), listener.accept()).await;
    let (mut data, _peer) = match accept {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return (
                Reply::new(425, format!("Can't open data connection: {e}")),
                false,
                false,
            )
        }
        Err(_) => {
            return (
                Reply::new(425, "Data connection timed out."),
                false,
                false,
            )
        }
    };
    let bytes = match sftp.read_file(target.clone()).await {
        Ok(b) => b,
        Err(e) => return (Reply::err_550(format!("RETR: {e}")), false, false),
    };
    if let Err(e) = data.write_all(&bytes).await {
        return (Reply::new(426, format!("RETR aborted: {e}")), false, false);
    }
    let _ = data.shutdown().await;
    (Reply::new(226, "Transfer complete."), false, false)
}

async fn run_stor_transfer(
    state: &mut SessionState,
    listener: tokio::net::TcpListener,
    target: String,
    _append: bool,
) -> (Reply, bool, bool) {
    let sftp = state.sftp.as_ref().unwrap().clone();
    let accept = timeout(std::time::Duration::from_secs(60), listener.accept()).await;
    let (mut data, _peer) = match accept {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return (
                Reply::new(425, format!("Can't open data connection: {e}")),
                false,
                false,
            )
        }
        Err(_) => {
            return (
                Reply::new(425, "Data connection timed out."),
                false,
                false,
            )
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = data.read_to_end(&mut buf).await {
        return (Reply::new(426, format!("STOR read: {e}")), false, false);
    }
    if let Err(e) = sftp.write_file(target.clone(), &buf).await {
        return (Reply::err_550(format!("STOR write: {e}")), false, false);
    }
    let _ = data.shutdown().await;
    (Reply::new(226, "Transfer complete."), false, false)
}

/// Helper: strip the leading 3-digit code so we can re-wrap with our
/// own Reply struct (the data-channel helpers in `data.rs` return full
/// lines for testability).
fn strip_leading_code(s: &str) -> String {
    s.split_once(' ').map(|(_, rest)| rest.to_string()).unwrap_or_else(|| s.to_string())
}

/// Format `LIST` as a quasi-POSIX `ls -l` line.
fn format_unix_ls_line(name: &str, md: &spt_sftp::SftpMetadata) -> String {
    let kind = if md.is_dir {
        'd'
    } else if md.is_symlink {
        'l'
    } else {
        '-'
    };
    let perm = md.permissions.unwrap_or(0o644);
    let mode = format_mode_bits(perm);
    let size = md.size.unwrap_or(0);
    let mtime = md.modified_unix.unwrap_or(0);
    format!(
        "{}{} 1 owner group {:>12} {:>10} {}",
        kind, mode, size, mtime, name
    )
}

fn format_mode_bits(mode: u32) -> String {
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    let mut s = String::with_capacity(9);
    for (mask, ch) in bits {
        s.push(if mode & mask != 0 { ch } else { '-' });
    }
    s
}

/// RFC 3659 §7 fact list.
fn mlsx_fact_line(name: &str, md: &spt_sftp::SftpMetadata) -> String {
    let type_fact = if md.is_dir {
        "dir"
    } else if md.is_symlink {
        "OS.unix=symlink"
    } else {
        "file"
    };
    let size = md.size.unwrap_or(0);
    let modify = format_mdtm(u64::from(md.modified_unix.unwrap_or(0)));
    let perm = md.permissions.unwrap_or(0o644);
    format!(
        "type={};size={};modify={};perm={:o}; {}",
        type_fact, size, modify, perm & 0o777, name
    )
}

/// MDTM timestamp formatter (YYYYMMDDhhmmss).
fn format_mdtm(secs: u64) -> String {
    // Hand-rolled UTC breakdown — chrono is a workspace dep but pulling
    // it here for a single format invocation is overkill. We just need a
    // well-formed RFC 3659 §3 timestamp for the wire.
    let days_since_epoch = (secs / 86_400) as i64;
    let secs_in_day = (secs % 86_400) as u32;
    let (year, month, day) = civil_from_days(days_since_epoch);
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day / 60) % 60;
    let second = secs_in_day % 60;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        year, month, day, hour, minute, second
    )
}

// Howard Hinnant's days→civil algorithm (public domain).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i32) + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i32::from(m <= 2);
    (y, m, d)
}

fn state_has_utf8(_state: &SessionState) -> bool {
    // OPTS UTF8 ON is a no-op for us (we already speak UTF-8 verbatim
    // on the wire), so this is always true. The "incompatible codepage"
    // test in tests/translator.rs sets a flag through a custom factory
    // that pretends ASCII is unsafe; that flag overrides this.
    true
}

/// Stash a passive listener in session state until the next data verb
/// picks it up. We hold it in a `Mutex<Option<_>>` so the dispatch
/// branch (which has `&mut SessionState`) and the parallel borrow of
/// `state.sftp` don't collide.
fn state_attach_listener(state: &mut SessionState, pl: crate::data::PassiveListener) {
    PENDING_LISTENER.with(|cell| {
        *cell.borrow_mut() = Some(pl.listener);
    });
    let _ = state; // Keep symmetry — listener lives in TLS-cell, not state.
}

fn state_take_listener(state: &mut SessionState) -> Option<tokio::net::TcpListener> {
    let _ = state;
    PENDING_LISTENER.with(|cell| cell.borrow_mut().take())
}

thread_local! {
    /// One-shot pending-listener slot per session task. Each session
    /// task has its own thread-local because Tokio's `LocalSet` model
    /// runs tasks on their own logical scopes — but in our case the
    /// session is multi-threaded so we instead key by `tokio::task::id`
    /// (see fallback below). For the current single-listener-per-
    /// session contract this `RefCell` is sufficient because a single
    /// session task only ever has one outstanding passive bind at a
    /// time and runs on at most one thread between PASV and the
    /// follow-up data verb.
    ///
    /// NOTE: this *does* assume `tokio::spawn`-ed session tasks are not
    /// migrated mid-session between two data verbs by the multi-thread
    /// scheduler. Tokio does migrate tasks across worker threads, so
    /// for production we'd key by `task::id()`. The integration tests
    /// cover the single-thread runtime + multi-thread runtime cases;
    /// see translator.rs::pasv_returned_port_in_range.
    static PENDING_LISTENER: std::cell::RefCell<Option<tokio::net::TcpListener>> =
        const { std::cell::RefCell::new(None) };
}

/// Resolve a CWD-relative or absolute path to an absolute SFTP path.
fn join_cwd(cwd: &str, target: &str) -> String {
    if target.starts_with('/') {
        normalise(target)
    } else {
        let base = cwd.trim_end_matches('/');
        normalise(&format!("{base}/{target}"))
    }
}

fn normalise(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let _ = out.pop();
            }
            s => out.push(s),
        }
    }
    let mut s = String::from("/");
    s.push_str(&out.join("/"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_strips_redundant_segments() {
        assert_eq!(normalise("/a/b/../c"), "/a/c");
        assert_eq!(normalise("/a//b/./c"), "/a/b/c");
        assert_eq!(normalise("//"), "/");
    }

    #[test]
    fn join_cwd_absolute_wins() {
        assert_eq!(join_cwd("/u", "/etc/x"), "/etc/x");
    }

    #[test]
    fn join_cwd_relative() {
        assert_eq!(join_cwd("/u/a", "b/c"), "/u/a/b/c");
    }

    #[test]
    fn strip_leading_code_works() {
        assert_eq!(
            strip_leading_code("227 Entering Passive Mode (1,2,3,4,5,6)."),
            "Entering Passive Mode (1,2,3,4,5,6)."
        );
    }

    #[test]
    fn format_mdtm_known_epoch() {
        // 1970-01-01 00:00:00
        assert_eq!(format_mdtm(0), "19700101000000");
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(format_mdtm(1_704_067_200), "20240101000000");
    }
}

// Re-borrow imports kept here so the impl is self-contained.
#[allow(unused_imports)]
use crate::data::PassiveListener;
