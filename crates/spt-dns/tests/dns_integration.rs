//! Integration tests for the split-horizon DNS server.
//!
//! Strategy: bind on `127.0.0.1:0` (ephemeral). Use `hickory-resolver` as a
//! client to query against the bound address. For the forwarder path we run
//! a tiny in-process upstream responder with `ServerFuture`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::rdata::A as ARdata;
use hickory_proto::rr::{Name, RData, Record as ProtoRecord, RecordType};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use tokio::net::UdpSocket;

use spt_dns::{
    AnswerPolicy, DnsServerBuilder, ForwardHealth, HealthSource, ManagedZone, Record,
};

fn loopback_resolver(addr: SocketAddr) -> TokioAsyncResolver {
    let group = NameServerConfigGroup::from_ips_clear(&[addr.ip()], addr.port(), true);
    let cfg = ResolverConfig::from_parts(None, vec![], group);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    // disable use of /etc/hosts and similar.
    opts.use_hosts_file = false;
    TokioAsyncResolver::tokio(cfg, opts)
}

#[tokio::test]
async fn managed_a_record_answered() {
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

    let resolver = loopback_resolver(handle.udp_addr());
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
        async fn handle_request<R: ResponseHandler>(
            &self,
            request: &Request,
            mut response_handle: R,
        ) -> ResponseInfo {
            let q = request.query();
            if q.query_type() == RecordType::A
                && q.name().to_string().to_ascii_lowercase().starts_with("upstream-only.")
            {
                let qname = Name::from_utf8(q.name().to_string()).unwrap();
                let mut rec = ProtoRecord::with(qname, RecordType::A, 30);
                rec.set_data(Some(RData::A(ARdata(Ipv4Addr::new(8, 8, 4, 4)))));
                let answers = [rec];
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());
                header.set_authoritative(true);
                let response = builder.build(header, &answers, &[], &[], &[]);
                return response_handle.send_response(response).await.unwrap();
            }
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(request.header(), ResponseCode::NXDomain);
            response_handle.send_response(response).await.unwrap()
        }
    }

    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let mut up = ServerFuture::new(UpstreamHandler);
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

    let resolver = loopback_resolver(handle.udp_addr());
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

    let resolver = loopback_resolver(handle.udp_addr());

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
    for rec in r2.records() {
        if let Some(RData::A(a)) = rec.data() {
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

    let resolver = loopback_resolver(handle.udp_addr());
    let lookup = resolver
        .srv_lookup("_smtp._tcp.tunnel.local.")
        .await
        .expect("srv answer present");
    let mut found = false;
    for srv in lookup.iter() {
        if srv.port() == 25 && srv.target().to_string().eq_ignore_ascii_case("mail.tunnel.local.") {
            found = true;
            break;
        }
    }
    assert!(found, "expected synthesized SRV in answer");

    handle.shutdown().await;
}
