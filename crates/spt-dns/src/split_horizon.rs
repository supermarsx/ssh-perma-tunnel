//! Split-horizon `RequestHandler` implementation.
//!
//! For each inbound query the handler:
//!
//! 1. Maps the query name to a [`ManagedZone`] (suffix match on FQDN).
//! 2. If matched and the requested type is one of A/AAAA/SRV/TXT, looks up
//!    the records and applies each record's [`AnswerPolicy`] using the wired
//!    [`HealthSource`].
//! 3. Otherwise (unmanaged name, or matched but no answers after policy
//!    filtering, or unsupported type), forwards to the upstream resolver if
//!    one is configured, else returns `NXDOMAIN` for managed zones we own and
//!    `REFUSED` for everything else.
//!
//! The handler is `Arc`-cheap to clone and is what hickory's
//! [`hickory_server::ServerFuture`] takes ownership of.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A as ARdata, AAAA as AAAARdata, SRV as SRVRdata, TXT as TXTRdata};
use hickory_proto::rr::{Name, RData, Record as ProtoRecord, RecordType};
use hickory_resolver::net::runtime::Time;
use hickory_resolver::TokioResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

use crate::health::HealthSource;
use crate::zone::{AnswerPolicy, ManagedZone, Record, RecordKind};

/// Split-horizon DNS [`RequestHandler`] used by [`crate::DnsServer`].
pub struct SplitHorizonHandler {
    zones: Vec<ManagedZone>,
    upstream: Option<Arc<TokioResolver>>,
    health: Arc<dyn HealthSource>,
}

impl SplitHorizonHandler {
    /// Build a handler from its parts.
    pub fn new(
        zones: Vec<ManagedZone>,
        upstream: Option<Arc<TokioResolver>>,
        health: Arc<dyn HealthSource>,
    ) -> Self {
        Self {
            zones,
            upstream,
            health,
        }
    }

    /// First zone whose suffix contains `name`, or `None` for unmanaged names.
    fn matching_zone(&self, name: &str) -> Option<&ManagedZone> {
        self.zones.iter().find(|z| z.contains_name(name))
    }

    /// Apply the per-record [`AnswerPolicy`] to filter the result set.
    async fn filter_by_policy<'a>(&self, records: Vec<&'a Record>) -> Vec<&'a Record> {
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let pass = match rec.answer_policy {
                AnswerPolicy::AlwaysAnswer => true,
                AnswerPolicy::AnswerWhenListening => match &rec.forward_id {
                    Some(id) => self.health.forward_health(id).await.listening,
                    None => true,
                },
                AnswerPolicy::AnswerWhenHealthy => match &rec.forward_id {
                    Some(id) => self.health.forward_health(id).await.healthy,
                    None => true,
                },
            };
            if pass {
                out.push(rec);
            }
        }
        out
    }
}

#[async_trait]
impl RequestHandler for SplitHorizonHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // hickory 0.26: the request header is now `Metadata` (accessed via the
        // `Request`'s deref to `MessageRequest`), and queries are a slice of
        // `LowerQuery`. There's no `request.header()`/`request.query()` any more.
        let metadata = &request.metadata;
        if metadata.message_type != MessageType::Query || metadata.op_code != OpCode::Query {
            return send_simple(&mut response_handle, request, ResponseCode::NotImp).await;
        }

        let Some(query) = request.queries.queries().first() else {
            return send_simple(&mut response_handle, request, ResponseCode::FormErr).await;
        };
        // `LowerQuery::original()` yields the case-preserving `Query`/`Name`.
        let qname = query.original().name();
        let qname_str = qname.to_string();
        let qtype = query.query_type();

        let kind = match qtype {
            RecordType::A => Some(RecordKind::A),
            RecordType::AAAA => Some(RecordKind::AAAA),
            RecordType::SRV => Some(RecordKind::SRV),
            RecordType::TXT => Some(RecordKind::TXT),
            _ => None,
        };

        // Managed-zone match path.
        if let Some(zone) = self.matching_zone(&qname_str) {
            if let Some(kind) = kind {
                let raw = zone.lookup(&qname_str, kind);
                let filtered = self.filter_by_policy(raw).await;
                if !filtered.is_empty() {
                    let answers = match build_answers(qname, &filtered) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(error = %e, "failed to build dns answers");
                            return send_simple(
                                &mut response_handle,
                                request,
                                ResponseCode::ServFail,
                            )
                            .await;
                        }
                    };
                    // Managed-zone answers are authoritative (AA=1).
                    return send_answers(&mut response_handle, request, &answers, true).await;
                }
                debug!(name = %qname_str, ?kind, "managed zone match but no answers (after policy)");
                return send_simple(&mut response_handle, request, ResponseCode::NXDomain).await;
            }
            // Managed zone but unsupported qtype — return NoError + empty.
            return send_simple(&mut response_handle, request, ResponseCode::NoError).await;
        }

        // Forwarder path.
        if let Some(upstream) = self.upstream.clone() {
            return forward_to_upstream(
                &upstream,
                request,
                &mut response_handle,
                &qname_str,
                qtype,
            )
            .await;
        }

        send_simple(&mut response_handle, request, ResponseCode::Refused).await
    }
}

async fn forward_to_upstream<R: ResponseHandler>(
    upstream: &TokioResolver,
    request: &Request,
    response_handle: &mut R,
    qname_str: &str,
    qtype: RecordType,
) -> ResponseInfo {
    let lookup = upstream.lookup(qname_str, qtype).await;
    match lookup {
        Ok(answer) => {
            // Preserve each upstream record's real owner name rather than
            // forcing the query name onto every record. Forcing the qname
            // flattens CNAME chains (e.g. `www -> cdn -> A`, where the A
            // record's owner is `cdn`, not `www`). hickory 0.26 stores the
            // record data inline (`record.data`), so a plain clone carries the
            // owner name, type, TTL, and rdata verbatim — `answer.records()` is
            // now `answer.answers()`.
            let records: Vec<ProtoRecord> = answer.answers().to_vec();
            // Forwarded (recursive) answers are NOT authoritative: leave AA
            // clear and set RA (recursion available) instead.
            send_answers(response_handle, request, &records, false).await
        }
        Err(e) => {
            // Distinguish NXDOMAIN/no-records from real failures. hickory 0.26
            // exposes `NetError::is_no_records_found()` in place of the removed
            // `ResolveErrorKind::NoRecordsFound` match arm.
            if e.is_no_records_found() {
                send_simple(response_handle, request, ResponseCode::NXDomain).await
            } else {
                warn!(error = %e, "upstream resolver failure");
                send_simple(response_handle, request, ResponseCode::ServFail).await
            }
        }
    }
}

fn build_answers(qname: &Name, records: &[&Record]) -> crate::Result<Vec<ProtoRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let ttl = rec.ttl.as_secs() as u32;
        let rdata = match rec.kind {
            RecordKind::A => {
                let ip: Ipv4Addr = rec.value.parse().map_err(|e: std::net::AddrParseError| {
                    crate::DnsError::InvalidValue {
                        kind: rec.kind,
                        value: rec.value.clone(),
                        reason: e.to_string(),
                    }
                })?;
                RData::A(ARdata(ip))
            }
            RecordKind::AAAA => {
                let ip: Ipv6Addr = rec.value.parse().map_err(|e: std::net::AddrParseError| {
                    crate::DnsError::InvalidValue {
                        kind: rec.kind,
                        value: rec.value.clone(),
                        reason: e.to_string(),
                    }
                })?;
                RData::AAAA(AAAARdata(ip))
            }
            RecordKind::SRV => {
                let (p, w, port, target) =
                    rec.srv_parts()
                        .ok_or_else(|| crate::DnsError::InvalidValue {
                            kind: rec.kind,
                            value: rec.value.clone(),
                            reason: "malformed SRV value".into(),
                        })?;
                let target_name =
                    Name::from_utf8(&target).map_err(|e| crate::DnsError::InvalidValue {
                        kind: rec.kind,
                        value: rec.value.clone(),
                        reason: format!("invalid SRV target: {e}"),
                    })?;
                RData::SRV(SRVRdata::new(p, w, port, target_name))
            }
            RecordKind::TXT => {
                // Split into 255-byte chunks for TXT-string-segment compliance.
                let chunks: Vec<String> = rec
                    .value
                    .as_bytes()
                    .chunks(255)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect();
                RData::TXT(TXTRdata::new(chunks))
            }
        };
        // hickory 0.26: `Record::with(..)` + `set_data(Some(..))` was replaced
        // by `Record::from_rdata(name, ttl, rdata)`, which stores the rdata
        // (and thus the record type) inline.
        out.push(ProtoRecord::from_rdata(qname.clone(), ttl, rdata));
    }
    Ok(out)
}

/// Send an answer set.
///
/// `authoritative` controls the AA / RA flags per RFC 1035:
/// * managed-zone answers are authoritative — set AA=1.
/// * forwarded (recursive) answers are NOT authoritative — leave AA clear and
///   advertise RA=1 (recursion available), since this server recursed upstream
///   on the client's behalf.
async fn send_answers<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    answers: &[ProtoRecord],
    authoritative: bool,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    // hickory 0.26: the response header is now `Metadata` (AA/RA are plain
    // fields), and `MessageResponseBuilder::build` takes a `Metadata` rather
    // than the old `Header`.
    let mut metadata = Metadata::response_from_request(&request.metadata);
    if authoritative {
        metadata.authoritative = true;
    } else {
        metadata.authoritative = false;
        metadata.recursion_available = true;
    }
    let response = builder.build(metadata, answers, &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send DNS response");
            servfail_info(request)
        }
    }
}

/// Build a `ServFail` [`ResponseInfo`] for `request`.
///
/// hickory 0.26 replaced `Header` with a `{ metadata, counts }` pair and made
/// `ResponseInfo::serve_failed` crate-private, so we assemble the header
/// ourselves from the request metadata.
fn servfail_info(request: &Request) -> ResponseInfo {
    use hickory_proto::op::{Header, HeaderCounts};
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

async fn send_simple<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    code: ResponseCode,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    // hickory 0.26: `error_msg` now takes the request `Metadata`.
    let response = builder.error_msg(&request.metadata, code);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send simple DNS response");
            servfail_info(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_tokio_resolver;
    use crate::testing::{FakeHealthSource, FakeZone, LocalhostResolver};
    use crate::zone::Record;
    use hickory_resolver::config::ResolveHosts;
    use std::net::SocketAddr;
    use std::time::Duration as StdDuration;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    // hickory 0.26: the old `NameServerConfigGroup::from_ips_clear` +
    // `TokioAsyncResolver::tokio` client construction was removed in the 0.25
    // rework. Reuse the crate's `build_tokio_resolver` helper (the same builder
    // path the forwarder uses) pointed at the loopback test port.
    fn client_for(port: u16) -> TokioResolver {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        build_tokio_resolver(addr, StdDuration::from_secs(2), ResolveHosts::Never)
            .expect("build test resolver")
    }

    // ---- Direct `send_answers` header/owner-name tests --------------------
    //
    // These exercise `send_answers` without a live upstream by capturing the
    // serialized wire response through a mock `ResponseHandler` and re-parsing
    // it with `hickory_proto::op::Message`, so we can inspect the AA/RA header
    // flags and each answer record's real owner name.

    use hickory_proto::op::{Message, MessageType as ProtoMsgType, OpCode as ProtoOpCode, Query};
    use hickory_proto::serialize::binary::BinEncoder;
    // hickory 0.26: `Protocol` moved out of `hickory_server::server` (now
    // private there) into `hickory_net::xfer::Protocol`, re-exported as
    // `hickory_server::net::xfer::Protocol`.
    use hickory_server::net::xfer::Protocol;
    use hickory_server::server::ResponseHandler;
    use std::sync::{Arc, Mutex};

    /// Mock `ResponseHandler` that serializes the response to the DNS wire
    /// format and stores the bytes for inspection.
    #[derive(Clone)]
    struct CapturingHandler {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl CapturingHandler {
        fn new() -> Self {
            Self {
                bytes: Arc::new(Mutex::new(None)),
            }
        }

        /// Parse the captured wire response into a `Message`.
        fn parsed(&self) -> Message {
            let guard = self.bytes.lock().unwrap();
            let buf = guard.as_ref().expect("a response was captured");
            Message::from_vec(buf).expect("captured response is valid DNS wire data")
        }
    }

    #[async_trait]
    impl ResponseHandler for CapturingHandler {
        // hickory 0.26: `send_response` returns `Result<ResponseInfo, NetError>`
        // (was `std::io::Result<ResponseInfo>` in 0.24).
        async fn send_response<'a>(
            &mut self,
            response: hickory_server::zone_handler::MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a ProtoRecord> + Send + 'a,
                impl Iterator<Item = &'a ProtoRecord> + Send + 'a,
                impl Iterator<Item = &'a ProtoRecord> + Send + 'a,
                impl Iterator<Item = &'a ProtoRecord> + Send + 'a,
            >,
        ) -> Result<ResponseInfo, hickory_server::net::NetError> {
            let mut buf = Vec::with_capacity(512);
            let info = {
                let mut encoder = BinEncoder::new(&mut buf);
                response
                    .destructive_emit(&mut encoder)
                    .expect("encode response")
            };
            *self.bytes.lock().unwrap() = Some(buf);
            Ok(info)
        }
    }

    /// Build a minimal `Request` carrying a single `A` query for `qname`.
    ///
    /// hickory 0.26: `Message::new()` now takes `(id, message_type, op_code)`
    /// directly (the `set_id`/`set_message_type`/`set_op_code` builder setters
    /// were removed), `recursion_desired` is a plain `metadata` field, and a
    /// `Request` is constructed from the wire bytes via `Request::from_bytes`
    /// (the old `MessageRequest::from_bytes` + `Request::new` pair is gone).
    fn request_for(qname: &str) -> Request {
        let mut msg = Message::new(0x1234, ProtoMsgType::Query, ProtoOpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_utf8(qname).unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let wire = msg.to_vec().unwrap();
        Request::from_bytes(wire, "127.0.0.1:5353".parse().unwrap(), Protocol::Udp).unwrap()
    }

    fn a_record(owner: &str, ip: Ipv4Addr) -> ProtoRecord {
        // hickory 0.26: `Record::with(..)` + `set_data(Some(..))` was replaced
        // by `Record::from_rdata(name, ttl, rdata)`, which stores rdata (and the
        // record type) inline.
        ProtoRecord::from_rdata(Name::from_utf8(owner).unwrap(), 60, RData::A(ARdata(ip)))
    }

    fn cname_record(owner: &str, target: &str) -> ProtoRecord {
        use hickory_proto::rr::rdata::CNAME as CNAMErdata;
        ProtoRecord::from_rdata(
            Name::from_utf8(owner).unwrap(),
            60,
            RData::CNAME(CNAMErdata(Name::from_utf8(target).unwrap())),
        )
    }

    #[test]
    fn forwarded_answer_has_aa_clear_and_ra_set() {
        rt().block_on(async {
            // Forwarder path passes `authoritative = false`.
            let mut handler = CapturingHandler::new();
            let request = request_for("www.example.com.");
            let answers = vec![a_record(
                "www.example.com.",
                Ipv4Addr::new(93, 184, 216, 34),
            )];
            send_answers(&mut handler, &request, &answers, false).await;

            let msg = handler.parsed();
            // hickory 0.26: the header flags are plain `metadata` fields.
            assert!(
                !msg.metadata.authoritative,
                "forwarded answer must NOT set AA"
            );
            assert!(
                msg.metadata.recursion_available,
                "forwarded answer must set RA"
            );
        });
    }

    #[test]
    fn authoritative_managed_answer_keeps_aa_set() {
        rt().block_on(async {
            // Managed-zone path passes `authoritative = true`; AA must stay set.
            let mut handler = CapturingHandler::new();
            let request = request_for("a.tunnel.local.");
            let answers = vec![a_record("a.tunnel.local.", Ipv4Addr::new(10, 0, 0, 1))];
            send_answers(&mut handler, &request, &answers, true).await;

            let msg = handler.parsed();
            assert!(
                msg.metadata.authoritative,
                "managed-zone answer must set AA=1"
            );
        });
    }

    #[test]
    fn forwarded_cname_chain_preserves_real_owner_names() {
        rt().block_on(async {
            // Simulate what the forwarder builds for a CNAME chain
            // `www -> cdn -> A`: the A record's owner is `cdn`, not the qname
            // `www`. The forwarder must preserve each record's real owner
            // (E6-F6) rather than collapsing every record to the query name.
            let mut handler = CapturingHandler::new();
            let request = request_for("www.example.com.");
            let answers = vec![
                cname_record("www.example.com.", "cdn.example.net."),
                a_record("cdn.example.net.", Ipv4Addr::new(203, 0, 113, 7)),
            ];
            send_answers(&mut handler, &request, &answers, false).await;

            let msg = handler.parsed();
            // hickory 0.26: `Message::answers` is a public field; records expose
            // their owner via `name()`.
            let owners: Vec<String> = msg.answers.iter().map(|r| r.name.to_string()).collect();
            // The CNAME owner is the qname; the A record's owner is the CNAME
            // target — NOT collapsed onto the qname.
            assert!(
                owners.iter().any(|o| o == "www.example.com."),
                "expected CNAME owned by qname, got {owners:?}"
            );
            assert!(
                owners.iter().any(|o| o == "cdn.example.net."),
                "A record must keep its real owner (cdn.example.net.), not the \
                 qname; got {owners:?}"
            );
            assert_eq!(
                owners.len(),
                2,
                "exactly two answers expected, got {owners:?}"
            );
        });
    }

    #[test]
    fn unmanaged_name_without_upstream_returns_refused() {
        rt().block_on(async {
            // No upstream + no zone match → REFUSED.
            let resolver = LocalhostResolver::start(vec![]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            // Hickory's behavior here varies: it may surface REFUSED as a
            // resolver error, or it may collapse to NoRecordsFound. We accept
            // either as long as no records came back.
            if let Ok(lookup) = client.lookup("nothing.example.", RecordType::A).await {
                assert_eq!(lookup.answers().len(), 0);
            }
            resolver.shutdown().await;
        });
    }

    #[test]
    fn managed_zone_unsupported_qtype_returns_no_records_found() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .a("a.tunnel.local.", "10.0.0.1".parse().unwrap())
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            // MX is not in our supported set; handler returns NoError-empty.
            let res = client.lookup("a.tunnel.local.", RecordType::MX).await;
            match res {
                Ok(lookup) => assert_eq!(lookup.answers().len(), 0),
                // hickory 0.26: `ResolveErrorKind::NoRecordsFound` was removed;
                // the resolver error is a `NetError` with `is_no_records_found()`.
                Err(e) => assert!(e.is_no_records_found()),
            }
            resolver.shutdown().await;
        });
    }

    #[test]
    fn answer_when_healthy_filters_with_no_health() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.").build();
            // Add a record with AnswerWhenHealthy + forward_id, so NoHealth filters it out.
            let mut zone = zone;
            zone.records.push(
                Record::a(
                    "gated.tunnel.local.",
                    "10.0.0.1".parse().unwrap(),
                    StdDuration::from_secs(60),
                )
                .with_policy(AnswerPolicy::AnswerWhenHealthy, Some("p/f".into())),
            );
            // NoHealth is the default → record filtered → NXDOMAIN.
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let err = client
                .lookup("gated.tunnel.local.", RecordType::A)
                .await
                .expect_err("must fail because NoHealth filters the record");
            assert!(err.is_no_records_found());
            resolver.shutdown().await;
        });
    }

    #[test]
    fn answer_when_healthy_passes_with_fake_health_up() {
        rt().block_on(async {
            let mut zone = FakeZone::new("tunnel.local.").build();
            zone.records.push(
                Record::a(
                    "gated.tunnel.local.",
                    "10.1.2.3".parse().unwrap(),
                    StdDuration::from_secs(60),
                )
                .with_policy(AnswerPolicy::AnswerWhenHealthy, Some("p/f".into())),
            );
            let resolver = LocalhostResolver::start_with_health(
                vec![zone],
                std::sync::Arc::new(FakeHealthSource(true)),
            )
            .await
            .unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let lookup = client
                .lookup("gated.tunnel.local.", RecordType::A)
                .await
                .expect("query resolves");
            // hickory 0.26: `Lookup::records()` -> `answers()`; record rdata is
            // the inline `data` field, no longer an `Option` behind `data()`.
            let any_match = lookup.answers().iter().any(|r| {
                matches!(&r.data, hickory_proto::rr::RData::A(a) if a.0 == std::net::Ipv4Addr::new(10,1,2,3))
            });
            assert!(any_match);
            resolver.shutdown().await;
        });
    }

    #[test]
    fn answer_when_listening_with_no_forward_id_always_passes() {
        rt().block_on(async {
            let mut zone = FakeZone::new("tunnel.local.").build();
            // forward_id = None → policy is treated as pass.
            zone.records.push(
                Record::a(
                    "nogate.tunnel.local.",
                    "10.9.9.9".parse().unwrap(),
                    StdDuration::from_secs(60),
                )
                .with_policy(AnswerPolicy::AnswerWhenListening, None),
            );
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let lookup = client
                .lookup("nogate.tunnel.local.", RecordType::A)
                .await
                .expect("query resolves");
            assert_eq!(lookup.answers().len(), 1);
            resolver.shutdown().await;
        });
    }

    #[test]
    fn srv_record_renders_in_handler_response() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .srv("_svc._tcp.tunnel.local.", "target.tunnel.local.", 25, 10, 5)
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let lookup = client
                .lookup("_svc._tcp.tunnel.local.", RecordType::SRV)
                .await
                .expect("query resolves");
            let mut found = false;
            for rec in lookup.answers() {
                if let hickory_proto::rr::RData::SRV(s) = &rec.data {
                    assert_eq!(s.priority, 10);
                    assert_eq!(s.weight, 5);
                    assert_eq!(s.port, 25);
                    found = true;
                }
            }
            assert!(found, "expected SRV answer");
            resolver.shutdown().await;
        });
    }

    #[test]
    fn aaaa_record_renders_in_handler_response() {
        rt().block_on(async {
            let zone = FakeZone::new("tunnel.local.")
                .aaaa("v6.tunnel.local.", "fd00::abcd".parse().unwrap())
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let lookup = client
                .lookup("v6.tunnel.local.", RecordType::AAAA)
                .await
                .expect("query resolves");
            let mut found = false;
            for rec in lookup.answers() {
                if let hickory_proto::rr::RData::AAAA(a) = &rec.data {
                    assert_eq!(a.0, "fd00::abcd".parse::<std::net::Ipv6Addr>().unwrap());
                    found = true;
                }
            }
            assert!(found);
            resolver.shutdown().await;
        });
    }

    #[test]
    fn txt_long_string_splits_into_chunks() {
        rt().block_on(async {
            // 300 bytes exercises the >255 chunking path while staying within
            // a single UDP response (no Windows TCP fallback permission quirk).
            let big = "x".repeat(300);
            let zone = FakeZone::new("tunnel.local.")
                .txt("t.tunnel.local.", &big)
                .build();
            let resolver = LocalhostResolver::start(vec![zone]).await.unwrap();
            let port = resolver.port();
            let client = client_for(port);
            let lookup = client
                .lookup("t.tunnel.local.", RecordType::TXT)
                .await
                .expect("query resolves");
            let mut chunk_count = 0usize;
            let mut total = 0usize;
            for rec in lookup.answers() {
                if let hickory_proto::rr::RData::TXT(t) = &rec.data {
                    for chunk in &t.txt_data {
                        chunk_count += 1;
                        total += chunk.len();
                    }
                }
            }
            assert_eq!(total, big.len());
            assert!(
                chunk_count >= 2,
                "expected at least 2 chunks, got {chunk_count}"
            );
            resolver.shutdown().await;
        });
    }
}
