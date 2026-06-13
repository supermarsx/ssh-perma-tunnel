//! Integration tests for the split-horizon DNS server.
//!
//! Strategy: bind on `127.0.0.1:0` (ephemeral). Use `hickory-resolver` over
//! TCP as a client to query against the bound address. For the forwarder path
//! we run a tiny in-process upstream responder with `Server`.
//!
//! hickory 0.26 migration notes (0.24 -> 0.26, two majors):
//! * `TokioAsyncResolver::tokio` + `NameServerConfigGroup` were removed in the
//!   0.25 rework. The client is built via `Resolver::builder_with_config` +
//!   `TokioRuntimeProvider`, assembling a `NameServerConfig` with UDP/TCP
//!   `ConnectionConfig`s carrying the bound port.
//! * `ServerFuture` -> `Server`.
//! * `RequestHandler::handle_request` gained a second generic `T: Time`; the
//!   request header is now `Metadata` (a field, accessed via the `Request`
//!   deref to `MessageRequest`), there's no `request.query()`/`request.header()`.
//! * `MessageResponseBuilder` moved to `hickory_server::zone_handler`;
//!   `build`/`error_msg` take `Metadata` and `Metadata::response_from_request`
//!   replaces `Header::response_from_request`.
//! * `Record::with(..)` + `set_data(Some(..))` -> `Record::from_rdata`; rdata is
//!   the inline `data` field. `Lookup::records()` -> `answers()`. SRV fields
//!   (`priority`/`weight`/`port`/`target`) are public, not methods.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::rdata::A as ARdata;
use hickory_proto::rr::{Name, RData, Record as ProtoRecord, RecordType};
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::runtime::{Time, TokioRuntimeProvider};
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::Server;
use tokio::net::UdpSocket;

use spt_dns::{AnswerPolicy, DnsServerBuilder, ForwardHealth, HealthSource, ManagedZone, Record};

static DNS_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn dns_test_lock() -> &'static tokio::sync::Mutex<()> {
    DNS_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Build a TCP-only loopback resolver pointed at `addr`.
///
/// hickory 0.26: assemble a `NameServerConfig` directly (the old
/// `NameServerConfigGroup::from(..)` + `TokioAsyncResolver::tokio` path was
/// removed) and build through `Resolver::builder_with_config`.
fn loopback_resolver(addr: SocketAddr) -> TokioResolver {
    let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
    tcp.port = addr.port();
    let ns = NameServerConfig::new(addr.ip(), true, vec![tcp]);
    let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let mut builder = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(2);
        opts.attempts = 1;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    builder.build().expect("build loopback resolver")
}

#[tokio::test]
async fn managed_a_record_answered() {
    let _guard = dns_test_lock().lock().await;

    let mut zone = ManagedZone::new("tunnel.local.");
    zone.add(Record::a(
        "mail.tunnel.local.",
        "10.0.0.7".parse().unwrap(),
        Duration::from_secs(60),
    ))
    .unwrap();

    let handle = DnsServerBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_zone(zone)
        .run()
        .await
        .expect("dns server starts");

    let resolver = loopback_resolver(handle.tcp_addr());
    let lookup = resolver
        .lookup_ip("mail.tunnel.local.")
        .await
        .expect("query resolves");
    let ips: Vec<IpAddr> = lookup.iter().collect();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]);

    handle.shutdown().await;
}

#[tokio::test]
async fn unmanaged_name_forwarded_to_upstream() {
    // Build a tiny upstream that hard-codes one A record.
    struct UpstreamHandler;
    #[async_trait]
    impl RequestHandler for UpstreamHandler {
        async fn handle_request<R: ResponseHandler, T: Time>(
            &self,
            request: &Request,
            mut response_handle: R,
        ) -> ResponseInfo {
            let q = request.queries.queries().first().expect("a query");
            let qname_str = q.original().name().to_string();
            if q.query_type() == RecordType::A
                && qname_str.to_ascii_lowercase().starts_with("upstream-only.")
            {
                let qname = Name::from_utf8(&qname_str).unwrap();
                let rec =
                    ProtoRecord::from_rdata(qname, 30, RData::A(ARdata(Ipv4Addr::new(8, 8, 4, 4))));
                let answers = [rec];
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.authoritative = true;
                let response = builder.build(metadata, &answers, &[], &[], &[]);
                return response_handle.send_response(response).await.unwrap();
            }
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(&request.metadata, ResponseCode::NXDomain);
            response_handle.send_response(response).await.unwrap()
        }
    }

    let _guard = dns_test_lock().lock().await;

    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let mut up = Server::new(UpstreamHandler);
    up.register_socket(upstream_socket);
    let upstream_task = tokio::spawn(async move {
        let _ = up.block_until_done().await;
    });

    let mut zone = ManagedZone::new("tunnel.local.");
    zone.add(Record::a(
        "mail.tunnel.local.",
        "10.0.0.7".parse().unwrap(),
        Duration::from_secs(60),
    ))
    .unwrap();

    let handle = DnsServerBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_zone(zone)
        .upstream(vec![upstream_addr])
        .run()
        .await
        .expect("dns server starts");

    let resolver = loopback_resolver(handle.tcp_addr());
    let lookup = resolver
        .lookup_ip("upstream-only.example.")
        .await
        .expect("forwarded query resolves");
    let ips: Vec<IpAddr> = lookup.iter().collect();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))]);

    handle.shutdown().await;
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn answer_when_healthy_filters_unhealthy() {
    use parking_lot::RwLock;

    struct Toggle(Arc<RwLock<bool>>);

    #[async_trait]
    impl HealthSource for Toggle {
        async fn forward_health(&self, _id: &str) -> ForwardHealth {
            ForwardHealth {
                listening: *self.0.read(),
                healthy: *self.0.read(),
            }
        }
    }

    let _guard = dns_test_lock().lock().await;

    let flag = Arc::new(RwLock::new(false));
    let src = Arc::new(Toggle(flag.clone()));

    let mut zone = ManagedZone::new("tunnel.local.");
    zone.add(
        Record::a(
            "mail.tunnel.local.",
            "10.0.0.7".parse().unwrap(),
            Duration::from_secs(60),
        )
        .with_policy(AnswerPolicy::AnswerWhenHealthy, Some("svc/smtp".into())),
    )
    .unwrap();

    let handle = DnsServerBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_zone(zone)
        .health_source(src)
        .run()
        .await
        .unwrap();

    let resolver = loopback_resolver(handle.tcp_addr());

    // Unhealthy → NXDOMAIN (we have no upstream, but managed zone owns the name).
    let r1 = resolver.lookup_ip("mail.tunnel.local.").await;
    assert!(r1.is_err(), "expected NXDOMAIN while unhealthy");

    // Flip healthy → answer flows.
    *flag.write() = true;
    let r2 = resolver
        .lookup("mail.tunnel.local.", RecordType::A)
        .await
        .expect("answers when healthy");
    let mut found = false;
    for rec in r2.answers() {
        if let RData::A(a) = &rec.data {
            assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 7));
            found = true;
        }
    }
    assert!(found, "expected A record after health flip");

    handle.shutdown().await;
}

#[tokio::test]
async fn srv_synthesis_record_resolves() {
    use spt_dns::srv::{synthesize_srv_records, SrvSource};

    let _guard = dns_test_lock().lock().await;

    let mut zone = ManagedZone::new("tunnel.local.");
    let srvs = synthesize_srv_records(
        "tunnel.local.",
        &[SrvSource {
            service: "smtp".into(),
            transport: "tcp".into(),
            target: "mail.tunnel.local.".into(),
            port: 25,
            priority: 10,
            weight: 5,
            ttl: Duration::from_secs(60),
            answer_policy: AnswerPolicy::AlwaysAnswer,
            forward_id: None,
        }],
    );
    for r in srvs {
        zone.add(r).unwrap();
    }

    let handle = DnsServerBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .add_zone(zone)
        .run()
        .await
        .unwrap();

    let resolver = loopback_resolver(handle.tcp_addr());
    // hickory 0.26: `srv_lookup` returns a generic `Lookup`; iterate its
    // `answers()` and match `RData::SRV` (SRV fields are now public).
    let lookup = resolver
        .srv_lookup("_smtp._tcp.tunnel.local.")
        .await
        .expect("srv answer present");
    let mut found = false;
    for rec in lookup.answers() {
        if let RData::SRV(srv) = &rec.data {
            if srv.port == 25
                && srv
                    .target
                    .to_string()
                    .eq_ignore_ascii_case("mail.tunnel.local.")
            {
                found = true;
                break;
            }
        }
    }
    assert!(found, "expected synthesized SRV in answer");

    handle.shutdown().await;
}
