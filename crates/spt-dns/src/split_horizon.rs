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
use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A as ARdata, AAAA as AAAARdata, SRV as SRVRdata, TXT as TXTRdata};
use hickory_proto::rr::{Name, RData, Record as ProtoRecord, RecordType};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tracing::{debug, warn};

use crate::health::HealthSource;
use crate::zone::{AnswerPolicy, ManagedZone, Record, RecordKind};

/// Split-horizon DNS [`RequestHandler`] used by [`crate::DnsServer`].
pub struct SplitHorizonHandler {
    zones: Vec<ManagedZone>,
    upstream: Option<Arc<TokioAsyncResolver>>,
    health: Arc<dyn HealthSource>,
}

impl SplitHorizonHandler {
    /// Build a handler from its parts.
    pub fn new(
        zones: Vec<ManagedZone>,
        upstream: Option<Arc<TokioAsyncResolver>>,
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
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let header = request.header();
        if header.message_type() != MessageType::Query || header.op_code() != OpCode::Query {
            return send_simple(&mut response_handle, request, ResponseCode::NotImp).await;
        }

        let query = request.query();
        let qname_str = query.name().to_string();
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
                    let qname: Name = query.name().clone().into();
                    let answers = match build_answers(&qname, &filtered) {
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
                    return send_answers(&mut response_handle, request, &answers).await;
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
    upstream: &TokioAsyncResolver,
    request: &Request,
    response_handle: &mut R,
    qname_str: &str,
    qtype: RecordType,
) -> ResponseInfo {
    let lookup = upstream.lookup(qname_str, qtype).await;
    match lookup {
        Ok(answer) => {
            let qname = match Name::from_utf8(qname_str) {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "bad upstream qname");
                    return send_simple(response_handle, request, ResponseCode::ServFail).await;
                }
            };
            let mut records = Vec::new();
            for rec in answer.records() {
                let mut r = ProtoRecord::with(qname.clone(), rec.record_type(), rec.ttl());
                r.set_data(rec.data().cloned());
                records.push(r);
            }
            send_answers(response_handle, request, &records).await
        }
        Err(e) => {
            // Distinguish NXDOMAIN/no-records from real failures.
            match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    send_simple(response_handle, request, ResponseCode::NXDomain).await
                }
                _ => {
                    warn!(error = %e, "upstream resolver failure");
                    send_simple(response_handle, request, ResponseCode::ServFail).await
                }
            }
        }
    }
}

fn build_answers(qname: &Name, records: &[&Record]) -> crate::Result<Vec<ProtoRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let mut r = ProtoRecord::with(
            qname.clone(),
            rec.kind.to_record_type(),
            rec.ttl.as_secs() as u32,
        );
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
        r.set_data(Some(rdata));
        out.push(r);
    }
    Ok(out)
}

async fn send_answers<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    answers: &[ProtoRecord],
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    let response = builder.build(header, answers, &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send DNS response");
            let mut hdr = Header::response_from_request(request.header());
            hdr.set_response_code(ResponseCode::ServFail);
            hdr.into()
        }
    }
}

async fn send_simple<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    code: ResponseCode,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(request.header(), code);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send simple DNS response");
            let mut hdr = Header::response_from_request(request.header());
            hdr.set_response_code(ResponseCode::ServFail);
            hdr.into()
        }
    }
}
