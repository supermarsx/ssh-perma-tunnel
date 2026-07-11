use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};

const PASSIVE_SCAN_START: usize = 56_000;
const PASSIVE_SCAN_END: usize = 65_000;
const PASSIVE_STRIDE_PAD: usize = 17;

static NEXT_PASSIVE_BASE: AtomicUsize = AtomicUsize::new(PASSIVE_SCAN_START);

pub fn passive_range(ip: IpAddr, width: u16) -> (u16, u16) {
    try_passive_range(ip, width).unwrap_or_else(|| {
        panic!("no bindable passive port range with width {width} for {ip}");
    })
}

pub fn try_passive_range(ip: IpAddr, width: u16) -> Option<(u16, u16)> {
    let width = usize::from(width.max(1));
    let max_base = PASSIVE_SCAN_END.checked_sub(width - 1)?;
    let span = max_base.checked_sub(PASSIVE_SCAN_START)? + 1;

    for _ in 0..512 {
        let next = NEXT_PASSIVE_BASE.fetch_add(width + PASSIVE_STRIDE_PAD, Ordering::Relaxed);
        let base = PASSIVE_SCAN_START + (next.saturating_sub(PASSIVE_SCAN_START) % span);
        if range_bindable(ip, base, width) {
            return Some(range(base, width));
        }
    }

    for base in PASSIVE_SCAN_START..=max_base {
        if range_bindable(ip, base, width) {
            return Some(range(base, width));
        }
    }

    None
}

fn range_bindable(ip: IpAddr, base: usize, width: usize) -> bool {
    let mut listeners = Vec::with_capacity(width);
    for port in base..base + width {
        let Ok(listener) = TcpListener::bind(SocketAddr::new(ip, port as u16)) else {
            return false;
        };
        listeners.push(listener);
    }
    true
}

fn range(base: usize, width: usize) -> (u16, u16) {
    (base as u16, (base + width - 1) as u16)
}
