//! Cross-platform default-gateway / egress-interface resolution.
//!
//! This module answers two questions about the host's live routing table:
//!
//! * [`GatewayResolver::default_route`] — what is the current default
//!   gateway IP and the interface that egresses it?
//! * [`GatewayResolver::route_to`] — for a given destination IP, which
//!   gateway / interface would the kernel actually select?
//!
//! It backs the `[network.gateway]` runtime safety guard in spt-bin ("only
//! run the tunnel when the host is actually on the expected network"). The
//! comparison / fail-closed policy lives in spt-bin; this crate only supplies
//! the raw routing facts through the [`GatewayResolver`] seam so the policy is
//! unit-testable with a fake resolver.
//!
//! ## Per-OS backends
//!
//! * **Linux** — pure `std`: parse `/proc/net/route` (IPv4) and
//!   `/proc/net/ipv6_route` (IPv6). No extra dependency. Longest-prefix match
//!   for [`route_to`](GatewayResolver::route_to), default route
//!   (destination `0.0.0.0/0` / `::/0`, lowest metric) for
//!   [`default_route`](GatewayResolver::default_route).
//! * **Windows** — `GetIpForwardTable2` (default route) and `GetBestRoute2`
//!   (route to a target) from the already-present `windows` crate, with the
//!   interface name resolved via `ConvertInterfaceLuidToAlias`.
//! * **macOS / other BSD** — shell out to the system `route -n get` tool and
//!   parse its `gateway:` / `interface:` lines. This is a documented
//!   best-effort fallback (see [`RouteInfo`] caveats).
//!
//! The fiddly byte-twiddling parsers ([`mod@parse`]) are compiled and
//! unit-tested on **every** target — even where the on-disk format is not
//! native — so a bug in the hex/endianness handling is caught by CI on all
//! runners, not only Linux ones.
//!
//! ## "Cannot determine" contract
//!
//! A resolver returns `Err(..)` only when the routing table could not be read
//! at all (I/O error, failed syscall). When the table *was* read but no
//! matching route exists, it returns `Ok(RouteInfo::default())` — an empty
//! result. Callers MUST treat an empty result as "unknown, not a match": the
//! enforcement layer fails closed on it rather than silently passing.

use std::net::IpAddr;

use spt_core::error::Result;

/// Routing facts resolved for a destination (or the system default route).
///
/// Both fields are best-effort. On Windows the [`interface`](Self::interface)
/// is the adapter *alias* (e.g. `"Ethernet"`); on macOS it is the BSD device
/// name (e.g. `"en0"`); on Linux it is the kernel interface name (e.g.
/// `"eth0"`). These match the names surfaced by
/// [`crate::interfaces::list`] on the same platform.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteInfo {
    /// Next-hop gateway IP for the route, if it has one. `None` for a
    /// directly-connected (on-link) route, or when the gateway could not be
    /// determined.
    pub gateway: Option<IpAddr>,
    /// Egress interface name for the route, if known.
    pub interface: Option<String>,
}

impl RouteInfo {
    /// True when neither a gateway nor an interface could be determined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none() && self.interface.is_none()
    }
}

/// Abstraction over the host routing table.
///
/// Production code uses [`SystemGatewayResolver`]; tests inject a fake so the
/// `[network.gateway]` enforcement logic can be exercised without depending on
/// the CI runner's real network configuration.
pub trait GatewayResolver {
    /// Resolve the system default route (destination `0.0.0.0/0` on IPv4 or
    /// `::/0` on IPv6). IPv4 is preferred when both exist.
    ///
    /// Returns `Ok(RouteInfo::default())` (empty) when the table was read but
    /// carries no default route; `Err` only on a table-read failure.
    fn default_route(&self) -> Result<RouteInfo>;

    /// Resolve the route the kernel would select for `target` (longest-prefix
    /// match). Returns an empty [`RouteInfo`] when no route matches.
    fn route_to(&self, target: IpAddr) -> Result<RouteInfo>;
}

/// Production [`GatewayResolver`] backed by the OS routing table.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemGatewayResolver;

impl GatewayResolver for SystemGatewayResolver {
    fn default_route(&self) -> Result<RouteInfo> {
        platform::default_route()
    }

    fn route_to(&self, target: IpAddr) -> Result<RouteInfo> {
        platform::route_to(target)
    }
}

// ---------------------------------------------------------------------------
// Pure parsers — compiled and tested on every target.
// ---------------------------------------------------------------------------

/// Pure parsers for the platform routing-table text formats.
///
/// Deliberately free of any `cfg(target_os)` gating so the endianness / hex
/// handling is compiled and unit-tested on every CI runner (a Linux
/// `/proc/net/route` line parses identically on a Windows runner).
///
/// `allow(dead_code)`: each helper is consumed by exactly one per-OS backend
/// (the Linux `/proc` reader / the macOS `route` parser) plus the always-on
/// unit tests, so on any *single* target's non-test build a subset looks unused
/// even though every function is exercised somewhere.
#[allow(dead_code)]
mod parse {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::RouteInfo;

    /// One IPv4 route parsed from a `/proc/net/route` line.
    ///
    /// `dest`/`mask`/`gateway` are stored as big-endian *numeric* `u32`
    /// (the form [`Ipv4Addr::from`] expects), already converted from the
    /// little-endian on-disk hex.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct V4Route {
        pub iface: String,
        pub dest: u32,
        pub mask: u32,
        pub gateway: u32,
        pub metric: u32,
    }

    /// One IPv6 route parsed from a `/proc/net/ipv6_route` line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct V6Route {
        pub iface: String,
        pub dest: Ipv6Addr,
        pub prefix_len: u8,
        pub gateway: Ipv6Addr,
        pub metric: u32,
    }

    /// `/proc/net/route` stores IPv4 addresses as the CPU-native `u32` of the
    /// network-byte-order value; on the little-endian Linux CI targets
    /// (`x86_64` + `aarch64`) that is the byte-reversed numeric address. Convert
    /// the parsed hex into the big-endian numeric form once here.
    fn le_hex_to_numeric(raw: u32) -> u32 {
        raw.swap_bytes()
    }

    /// Parse the whole `/proc/net/route` file into IPv4 routes, skipping the
    /// header and any malformed line.
    pub(super) fn parse_proc_net_route(contents: &str) -> Vec<V4Route> {
        let mut out = Vec::new();
        for line in contents.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            // Header row: `Iface Destination Gateway ...`.
            if f[0].eq_ignore_ascii_case("iface") {
                continue;
            }
            let (Ok(dest), Ok(gateway), Ok(metric), Ok(mask)) = (
                u32::from_str_radix(f[1], 16),
                u32::from_str_radix(f[2], 16),
                f[6].parse::<u32>(),
                u32::from_str_radix(f[7], 16),
            ) else {
                continue;
            };
            out.push(V4Route {
                iface: f[0].to_owned(),
                dest: le_hex_to_numeric(dest),
                mask: le_hex_to_numeric(mask),
                gateway: le_hex_to_numeric(gateway),
                metric,
            });
        }
        out
    }

    /// Decode a 32-hex-char `/proc/net/ipv6_route` field into an [`Ipv6Addr`].
    fn hex_to_v6(s: &str) -> Option<Ipv6Addr> {
        if s.len() != 32 || !s.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (dst, src) in bytes.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
            let hex = std::str::from_utf8(src).ok()?;
            *dst = u8::from_str_radix(hex, 16).ok()?;
        }
        Some(Ipv6Addr::from(bytes))
    }

    /// Parse the whole `/proc/net/ipv6_route` file into IPv6 routes.
    pub(super) fn parse_proc_net_ipv6_route(contents: &str) -> Vec<V6Route> {
        let mut out = Vec::new();
        for line in contents.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            // dest destlen src srclen nexthop metric refcnt use flags iface
            if f.len() < 10 {
                continue;
            }
            let (Some(dest), Some(gateway)) = (hex_to_v6(f[0]), hex_to_v6(f[4])) else {
                continue;
            };
            let (Ok(prefix_len), Ok(metric)) =
                (u8::from_str_radix(f[1], 16), u32::from_str_radix(f[5], 16))
            else {
                continue;
            };
            out.push(V6Route {
                iface: f[f.len() - 1].to_owned(),
                dest,
                prefix_len,
                gateway,
                metric,
            });
        }
        out
    }

    /// Map a raw IPv4 next-hop into an optional gateway (`0.0.0.0` ⇒ on-link).
    fn v4_gateway(gw: u32) -> Option<IpAddr> {
        if gw == 0 {
            None
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(gw)))
        }
    }

    /// Map a raw IPv6 next-hop into an optional gateway (`::` ⇒ on-link).
    fn v6_gateway(gw: Ipv6Addr) -> Option<IpAddr> {
        if gw.is_unspecified() {
            None
        } else {
            Some(IpAddr::V6(gw))
        }
    }

    /// Convert a selected IPv4 route into a [`RouteInfo`].
    pub(super) fn v4_route_info(r: &V4Route) -> RouteInfo {
        RouteInfo {
            gateway: v4_gateway(r.gateway),
            interface: Some(r.iface.clone()),
        }
    }

    /// Convert a selected IPv6 route into a [`RouteInfo`].
    pub(super) fn v6_route_info(r: &V6Route) -> RouteInfo {
        RouteInfo {
            gateway: v6_gateway(r.gateway),
            interface: Some(r.iface.clone()),
        }
    }

    /// Pick the IPv4 default route (destination `0.0.0.0/0`, lowest metric).
    pub(super) fn select_v4_default(routes: &[V4Route]) -> Option<&V4Route> {
        routes
            .iter()
            .filter(|r| r.mask == 0 && r.dest == 0)
            .min_by_key(|r| r.metric)
    }

    /// Longest-prefix match for an IPv4 target; ties broken by lowest metric.
    pub(super) fn select_v4_route_to(routes: &[V4Route], target: Ipv4Addr) -> Option<&V4Route> {
        let t = u32::from(target);
        routes
            .iter()
            .filter(|r| (t & r.mask) == r.dest)
            .max_by(|a, b| {
                a.mask
                    .count_ones()
                    .cmp(&b.mask.count_ones())
                    .then_with(|| b.metric.cmp(&a.metric))
            })
    }

    /// Pick the IPv6 default route (destination `::/0`, lowest metric).
    pub(super) fn select_v6_default(routes: &[V6Route]) -> Option<&V6Route> {
        routes
            .iter()
            .filter(|r| r.prefix_len == 0)
            .min_by_key(|r| r.metric)
    }

    /// True when `target` falls inside `dest`/`prefix_len`.
    fn v6_in_prefix(target: Ipv6Addr, dest: Ipv6Addr, prefix_len: u8) -> bool {
        let t = u128::from(target);
        let d = u128::from(dest);
        if prefix_len == 0 {
            return true;
        }
        if prefix_len >= 128 {
            return t == d;
        }
        let mask = u128::MAX << (128 - u32::from(prefix_len));
        (t & mask) == (d & mask)
    }

    /// Longest-prefix match for an IPv6 target; ties broken by lowest metric.
    pub(super) fn select_v6_route_to(routes: &[V6Route], target: Ipv6Addr) -> Option<&V6Route> {
        routes
            .iter()
            .filter(|r| v6_in_prefix(target, r.dest, r.prefix_len))
            .max_by(|a, b| {
                a.prefix_len
                    .cmp(&b.prefix_len)
                    .then_with(|| b.metric.cmp(&a.metric))
            })
    }

    /// Parse the `gateway:` / `interface:` lines of `route -n get` output
    /// (macOS / BSD). Lines whose gateway is not an IP literal (e.g.
    /// `link#4` for an on-link route) leave [`RouteInfo::gateway`] `None`.
    pub(super) fn parse_route_get(stdout: &str) -> RouteInfo {
        let mut info = RouteInfo::default();
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("gateway:") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    info.gateway = Some(ip);
                }
            } else if let Some(rest) = line.strip_prefix("interface:") {
                let name = rest.trim();
                if !name.is_empty() {
                    info.interface = Some(name.to_owned());
                }
            }
        }
        info
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const PROC_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
wg0\t0000FEA9\t00000000\t0001\t0\t0\t50\t0000FFFF\t0\t0\t0
";

        #[test]
        fn parses_ipv4_default_gateway() {
            let routes = parse_proc_net_route(PROC_ROUTE);
            let def = select_v4_default(&routes).expect("default route present");
            let info = v4_route_info(def);
            assert_eq!(info.interface.as_deref(), Some("eth0"));
            assert_eq!(
                info.gateway,
                Some("192.168.2.1".parse::<IpAddr>().unwrap()),
                "gateway hex 0102A8C0 (LE) decodes to 192.168.2.1"
            );
        }

        #[test]
        fn on_link_route_has_no_gateway() {
            let routes = parse_proc_net_route(PROC_ROUTE);
            // 192.168.0.5 matches the 192.168.0.0/24 on-link row.
            let target = "192.168.0.5".parse::<std::net::Ipv4Addr>().unwrap();
            let r = select_v4_route_to(&routes, target).expect("match");
            let info = v4_route_info(r);
            assert_eq!(info.interface.as_deref(), Some("eth0"));
            assert_eq!(info.gateway, None, "directly-connected → no gateway");
        }

        #[test]
        fn route_to_prefers_longest_prefix_over_default() {
            let routes = parse_proc_net_route(PROC_ROUTE);
            // A public IP only matches the 0.0.0.0/0 default.
            let target = "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap();
            let r = select_v4_route_to(&routes, target).expect("default matches");
            assert_eq!(r.mask, 0);
            assert_eq!(v4_route_info(r).interface.as_deref(), Some("eth0"));
        }

        const PROC_V6: &str = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
";

        #[test]
        fn parses_ipv6_default() {
            let routes = parse_proc_net_ipv6_route(PROC_V6);
            let def = select_v6_default(&routes).expect("v6 default present");
            let info = v6_route_info(def);
            assert_eq!(info.interface.as_deref(), Some("eth0"));
            assert_eq!(info.gateway, Some("fe80::1".parse::<IpAddr>().unwrap()));
        }

        #[test]
        fn ipv6_route_to_link_local_is_on_link() {
            let routes = parse_proc_net_ipv6_route(PROC_V6);
            let target = "fe80::abcd".parse::<Ipv6Addr>().unwrap();
            let r = select_v6_route_to(&routes, target).expect("fe80::/64 matches");
            assert_eq!(r.prefix_len, 64, "0x40 hex prefix decodes to /64");
            assert_eq!(v6_route_info(r).gateway, None);
        }

        #[test]
        fn parses_macos_route_get() {
            let out = "\
   route to: 8.8.8.8
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
";
            let info = parse_route_get(out);
            assert_eq!(info.gateway, Some("192.168.1.1".parse::<IpAddr>().unwrap()));
            assert_eq!(info.interface.as_deref(), Some("en0"));
        }

        #[test]
        fn macos_on_link_route_get_has_no_ip_gateway() {
            let out = "\
   route to: 192.168.1.20
    gateway: link#4
  interface: en0
";
            let info = parse_route_get(out);
            assert_eq!(info.gateway, None, "`link#4` is not an IP literal");
            assert_eq!(info.interface.as_deref(), Some("en0"));
        }

        #[test]
        fn empty_input_yields_nothing() {
            assert!(parse_proc_net_route("").is_empty());
            assert!(parse_proc_net_ipv6_route("").is_empty());
            assert!(parse_route_get("").is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Per-OS backends.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use std::net::IpAddr;

    use spt_core::error::{Error, Result};

    use super::{parse, RouteInfo};

    fn read_table(path: &str) -> Result<String> {
        std::fs::read_to_string(path)
            .map_err(|e| Error::RuntimeFailure(format!("could not read {path}: {e}")))
    }

    pub(super) fn default_route() -> Result<RouteInfo> {
        // Prefer an IPv4 default; fall back to the IPv6 default route.
        let v4 = read_table("/proc/net/route")?;
        if let Some(r) = parse::select_v4_default(&parse::parse_proc_net_route(&v4)) {
            return Ok(parse::v4_route_info(r));
        }
        // IPv6 table is absent when IPv6 is disabled — treat that as "no v6
        // default" rather than a hard error.
        if let Ok(v6) = read_table("/proc/net/ipv6_route") {
            if let Some(r) = parse::select_v6_default(&parse::parse_proc_net_ipv6_route(&v6)) {
                return Ok(parse::v6_route_info(r));
            }
        }
        Ok(RouteInfo::default())
    }

    pub(super) fn route_to(target: IpAddr) -> Result<RouteInfo> {
        match target {
            IpAddr::V4(v4) => {
                let contents = read_table("/proc/net/route")?;
                let routes = parse::parse_proc_net_route(&contents);
                Ok(parse::select_v4_route_to(&routes, v4)
                    .map(parse::v4_route_info)
                    .unwrap_or_default())
            }
            IpAddr::V6(v6) => {
                let contents = read_table("/proc/net/ipv6_route")?;
                let routes = parse::parse_proc_net_ipv6_route(&contents);
                Ok(parse::select_v6_route_to(&routes, v6)
                    .map(parse::v6_route_info)
                    .unwrap_or_default())
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use spt_core::error::{Error, Result};
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToAlias, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
        MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET,
    };

    use super::RouteInfo;

    /// Read the family tag of a route's destination prefix.
    fn dest_family(row: &MIB_IPFORWARD_ROW2) -> u16 {
        // SAFETY: `si_family` is the common initial member of the
        // `SOCKADDR_INET` union and is valid to read for any populated row.
        unsafe { row.DestinationPrefix.Prefix.si_family.0 }
    }

    /// Convert a `SOCKADDR_INET` next-hop into an optional gateway IP.
    fn sockaddr_to_ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: discriminate the union via `si_family`, then read the arm it
        // selects. Both arms are plain-old-data.
        unsafe {
            let family = sa.si_family;
            if family == AF_INET {
                let addr = sa.Ipv4.sin_addr.S_un.S_addr; // network byte order
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr))))
            } else if family == AF_INET6 {
                Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte)))
            } else {
                None
            }
        }
    }

    /// Resolve an interface LUID to its adapter alias (e.g. `"Ethernet"`).
    fn luid_to_alias(luid: &NET_LUID_LH) -> Option<String> {
        // NDIS_IF_MAX_STRING_SIZE is 255; +1 for the NUL terminator.
        let mut buf = [0u16; 256];
        // SAFETY: `luid` is a valid pointer for the call; `buf` is a valid
        // mutable wide buffer whose length is passed to the FFI.
        let rc = unsafe { ConvertInterfaceLuidToAlias(std::ptr::from_ref(luid), &mut buf) };
        if rc != NO_ERROR {
            return None;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let alias = String::from_utf16_lossy(&buf[..len]);
        if alias.is_empty() {
            None
        } else {
            Some(alias)
        }
    }

    fn row_to_info(row: &MIB_IPFORWARD_ROW2) -> RouteInfo {
        let gateway = sockaddr_to_ip(&row.NextHop).filter(|ip| !ip.is_unspecified());
        RouteInfo {
            gateway,
            interface: luid_to_alias(&row.InterfaceLuid),
        }
    }

    /// Build a `SOCKADDR_INET` for the given target IP.
    fn ip_to_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
        let mut sa = SOCKADDR_INET::default();
        // Writing (as opposed to reading) union fields is safe; the whole value
        // was zero-initialised via `default()`.
        match ip {
            IpAddr::V4(v4) => {
                sa.Ipv4.sin_family = AF_INET;
                // octets() is network byte order; store the raw bytes.
                sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            }
            IpAddr::V6(v6) => {
                sa.Ipv6.sin6_family = AF_INET6;
                sa.Ipv6.sin6_addr.u.Byte = v6.octets();
            }
        }
        sa
    }

    pub(super) fn default_route() -> Result<RouteInfo> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: `table` is a valid out-pointer; on success Windows allocates
        // the table and we free it via `FreeMibTable` before returning.
        let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &raw mut table) };
        if rc != NO_ERROR {
            return Err(Error::RuntimeFailure(format!(
                "GetIpForwardTable2 failed: {}",
                rc.0
            )));
        }
        if table.is_null() {
            return Err(Error::RuntimeFailure(
                "GetIpForwardTable2 returned a null table".into(),
            ));
        }
        // SAFETY: `table` is non-null and points to a `MIB_IPFORWARD_TABLE2`
        // whose `Table` is a `NumEntries`-long array (C flexible-array idiom).
        let info = unsafe {
            let count = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            select_default(rows).map(row_to_info)
        };
        // SAFETY: `table` was allocated by `GetIpForwardTable2`; free exactly
        // once, after the last read of `rows` above.
        unsafe {
            let mem: *const core::ffi::c_void = table.cast();
            FreeMibTable(mem);
        }
        Ok(info.unwrap_or_default())
    }

    /// Choose the default route: IPv4 first (lowest metric), then IPv6.
    fn select_default(rows: &[MIB_IPFORWARD_ROW2]) -> Option<&MIB_IPFORWARD_ROW2> {
        let pick = |family: ADDRESS_FAMILY| {
            rows.iter()
                .filter(|r| r.DestinationPrefix.PrefixLength == 0 && dest_family(r) == family.0)
                .min_by_key(|r| r.Metric)
        };
        pick(AF_INET).or_else(|| pick(AF_INET6))
    }

    pub(super) fn route_to(target: IpAddr) -> Result<RouteInfo> {
        let dest = ip_to_sockaddr(target);
        let mut best = MIB_IPFORWARD_ROW2::default();
        let mut best_source = SOCKADDR_INET::default();
        // SAFETY: `dest` is a valid populated `SOCKADDR_INET`; `best` and
        // `best_source` are valid out-params. No interface / source hint.
        let rc = unsafe {
            GetBestRoute2(
                None,
                0,
                None,
                &raw const dest,
                0,
                &raw mut best,
                &raw mut best_source,
            )
        };
        if rc != NO_ERROR {
            return Err(Error::RuntimeFailure(format!(
                "GetBestRoute2 failed: {}",
                rc.0
            )));
        }
        Ok(row_to_info(&best))
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    //! macOS / other BSD: shell out to the system `route` tool.
    use std::net::IpAddr;
    use std::process::Command;

    use spt_core::error::{Error, Result};

    use super::{parse, RouteInfo};

    fn run_route(target: &str) -> Result<RouteInfo> {
        let output = Command::new("route")
            .args(["-n", "get", target])
            .output()
            .map_err(|e| Error::RuntimeFailure(format!("could not run `route -n get`: {e}")))?;
        if !output.status.success() {
            // A non-zero exit for a specific target means "no route" — surface
            // an empty result rather than a hard error so the enforcement layer
            // treats it as "undetermined".
            return Ok(RouteInfo::default());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse::parse_route_get(&stdout))
    }

    pub(super) fn default_route() -> Result<RouteInfo> {
        run_route("default")
    }

    pub(super) fn route_to(target: IpAddr) -> Result<RouteInfo> {
        run_route(&target.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_resolver_default_route_does_not_panic() {
        // Host-dependent: we only assert the call is well-formed and, when it
        // succeeds, yields a self-consistent result. A network-isolated CI
        // container may legitimately have no default route (empty RouteInfo)
        // or fail to read the table (Err) — both are acceptable here.
        match SystemGatewayResolver.default_route() {
            Ok(info) => {
                if let Some(iface) = info.interface.as_ref() {
                    assert!(!iface.is_empty(), "interface name should be non-empty");
                }
            }
            Err(_) => { /* acceptable in a sandbox without routing tables */ }
        }
    }

    #[test]
    fn system_resolver_route_to_does_not_panic() {
        let target: IpAddr = "8.8.8.8".parse().unwrap();
        let _ = SystemGatewayResolver.route_to(target);
    }
}
