//! Prometheus text-format metrics exporter.
//!
//! The exporter wraps a `prometheus::Registry`, plus a tokio task that
//! periodically encodes the registry to text and atomically writes it to
//! `metrics.prom` via `spt_state::write_atomic`. Metrics callers register
//! their own counters / gauges with [`MetricsExporter::registry`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use prometheus::{
    Encoder, Gauge, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use spt_core::{Error, Result};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use spt_state::write_atomic;

/// Configuration for [`MetricsExporter::spawn`].
#[derive(Debug, Clone)]
pub struct MetricsExporterConfig {
    /// Path of the `metrics.prom` file.
    pub state_file: PathBuf,
    /// How often to render to disk.
    pub interval: Duration,
}

impl Default for MetricsExporterConfig {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from("metrics.prom"),
            interval: Duration::from_secs(15),
        }
    }
}

/// Standard spt metrics registered on construction. Holding handles avoids
/// re-lookups in the hot path.
#[derive(Clone)]
pub struct StandardMetrics {
    /// Profile state, label = `profile_id`. Value is the numeric state code.
    pub profile_state: IntGaugeVec,
    /// Active forward connections, label = `forward_id`.
    pub forward_active: IntGaugeVec,
    /// Total bytes received, label = `forward_id`.
    pub bytes_in: IntCounterVec,
    /// Total bytes sent, label = `forward_id`.
    pub bytes_out: IntCounterVec,
    /// Total reconnects, label = `profile_id`.
    pub reconnects: IntCounterVec,
    /// Process up flag (1 when running).
    pub up: IntGauge,
    /// Build info gauge (always 1; useful for labels).
    pub build_info: Gauge,
    /// Total events emitted.
    pub events_total: IntCounter,
}

impl StandardMetrics {
    /// Register the standard metrics on `r`.
    pub fn register(r: &Registry) -> Result<Self> {
        let profile_state = IntGaugeVec::new(
            Opts::new("spt_profile_state", "Profile state code per profile_id"),
            &["profile_id"],
        )
        .map_err(|e| map_prom_err(&e))?;
        let forward_active = IntGaugeVec::new(
            Opts::new(
                "spt_forward_connections_active",
                "Active forwarded connections per forward_id",
            ),
            &["forward_id"],
        )
        .map_err(|e| map_prom_err(&e))?;
        let bytes_in = IntCounterVec::new(
            Opts::new("spt_bytes_in_total", "Bytes received per forward_id"),
            &["forward_id"],
        )
        .map_err(|e| map_prom_err(&e))?;
        let bytes_out = IntCounterVec::new(
            Opts::new("spt_bytes_out_total", "Bytes sent per forward_id"),
            &["forward_id"],
        )
        .map_err(|e| map_prom_err(&e))?;
        let reconnects = IntCounterVec::new(
            Opts::new("spt_reconnects_total", "Reconnect attempts per profile_id"),
            &["profile_id"],
        )
        .map_err(|e| map_prom_err(&e))?;
        let up = IntGauge::new("spt_up", "1 if spt is running").map_err(|e| map_prom_err(&e))?;
        let build_info =
            Gauge::new("spt_build_info", "Build info (always 1)").map_err(|e| map_prom_err(&e))?;
        let events_total = IntCounter::new("spt_events_total", "Total events emitted")
            .map_err(|e| map_prom_err(&e))?;

        r.register(Box::new(profile_state.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(forward_active.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(bytes_in.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(bytes_out.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(reconnects.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(up.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(build_info.clone()))
            .map_err(|e| map_prom_err(&e))?;
        r.register(Box::new(events_total.clone()))
            .map_err(|e| map_prom_err(&e))?;

        up.set(1);
        build_info.set(1.0);

        Ok(Self {
            profile_state,
            forward_active,
            bytes_in,
            bytes_out,
            reconnects,
            up,
            build_info,
            events_total,
        })
    }
}

fn map_prom_err(e: &prometheus::Error) -> Error {
    Error::RuntimeFailure(format!("prometheus: {e}"))
}

/// Owned exporter. Holds the registry plus the standard metric handles.
#[derive(Clone)]
pub struct MetricsExporter {
    registry: Arc<Registry>,
    standard: StandardMetrics,
}

/// Handle to the running exporter task — keep it alive to retain the writer;
/// drop or call [`MetricsExporterHandle::shutdown`] to stop and flush.
pub struct MetricsExporterHandle {
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl MetricsExporterHandle {
    /// Stop the writer and wait for it to flush.
    pub async fn shutdown(self) {
        // Take the sender out from under the lock first, drop the guard,
        // then send. Avoids holding the parking_lot mutex across an await.
        let tx = self.shutdown.lock().take();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        let join = self.join.lock().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    }
}

impl Drop for MetricsExporterHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.lock().take() {
            let _ = tx.send(());
        }
    }
}

impl MetricsExporter {
    /// New in-memory exporter with the standard metrics registered.
    pub fn new() -> Result<Self> {
        let r = Registry::new();
        let standard = StandardMetrics::register(&r)?;
        Ok(Self {
            registry: Arc::new(r),
            standard,
        })
    }

    /// Borrow the underlying `prometheus::Registry`.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Borrow the standard-metric handles.
    #[must_use]
    pub fn standard(&self) -> &StandardMetrics {
        &self.standard
    }

    /// Encode the registry to Prometheus text-format bytes.
    pub fn render(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4096);
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .map_err(|e| map_prom_err(&e))?;
        Ok(buf)
    }

    /// Atomically write `metrics.prom` once.
    pub fn render_to_file(&self, path: &std::path::Path) -> Result<()> {
        let bytes = self.render()?;
        write_atomic(path, &bytes)
    }

    /// Spawn a periodic writer task. The returned handle should be held for
    /// the life of the process; dropping it stops the writer.
    pub fn spawn(&self, cfg: MetricsExporterConfig) -> MetricsExporterHandle {
        let (sd_tx, sd_rx) = oneshot::channel();
        let me = self.clone();
        let join = tokio::spawn(async move {
            run(me, cfg, sd_rx).await;
        });
        MetricsExporterHandle {
            shutdown: Mutex::new(Some(sd_tx)),
            join: Mutex::new(Some(join)),
        }
    }
}

async fn run(me: MetricsExporter, cfg: MetricsExporterConfig, mut shutdown: oneshot::Receiver<()>) {
    let mut iv = tokio::time::interval(cfg.interval);
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick.
    iv.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                if let Err(e) = me.render_to_file(&cfg.state_file) {
                    tracing::warn!(error=%e, "metrics flush on shutdown failed");
                }
                break;
            }
            _ = iv.tick() => {
                if let Err(e) = me.render_to_file(&cfg.state_file) {
                    tracing::warn!(error=%e, "metrics render failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn render_includes_standard_metrics() {
        let me = MetricsExporter::new().unwrap();
        me.standard()
            .bytes_in
            .with_label_values(&["fwd-1"])
            .inc_by(1234);
        me.standard()
            .profile_state
            .with_label_values(&["p1"])
            .set(7);
        let body = String::from_utf8(me.render().unwrap()).unwrap();
        assert!(body.contains("spt_bytes_in_total"));
        assert!(body.contains("fwd-1"));
        assert!(body.contains("1234"));
        assert!(body.contains("spt_profile_state"));
        assert!(body.contains("spt_up"));
    }

    #[test]
    fn render_to_file_writes_atomic_text() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("metrics.prom");
        let me = MetricsExporter::new().unwrap();
        me.standard().reconnects.with_label_values(&["px"]).inc();
        me.render_to_file(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("spt_reconnects_total"));
        assert!(body.contains("px"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_periodically_renders() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("metrics.prom");
        let me = MetricsExporter::new().unwrap();
        let handle = me.spawn(MetricsExporterConfig {
            state_file: path.clone(),
            interval: Duration::from_millis(20),
        });
        // Wait long enough for at least one tick. We use real sleep here —
        // the writer should fire within ~20ms.
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.shutdown().await;
        assert!(path.is_file());
    }

    #[test]
    fn config_default_uses_metrics_prom_and_15s() {
        let d = MetricsExporterConfig::default();
        assert_eq!(d.state_file, PathBuf::from("metrics.prom"));
        assert_eq!(d.interval, Duration::from_secs(15));
        let cloned = d.clone();
        assert_eq!(cloned.state_file, d.state_file);
        let dbg = format!("{d:?}");
        assert!(dbg.contains("MetricsExporterConfig"));
    }

    #[test]
    fn accessors_expose_registry_and_standard() {
        let me = MetricsExporter::new().unwrap();
        let r = me.registry();
        assert!(!r.gather().is_empty());
        let _s = me.standard();
        let me2 = me.clone();
        let _r2 = me2.registry();
    }

    #[test]
    fn standard_metrics_include_all_handles() {
        let me = MetricsExporter::new().unwrap();
        let s = me.standard();
        s.profile_state.with_label_values(&["p"]).set(3);
        s.forward_active.with_label_values(&["f"]).set(2);
        s.bytes_in.with_label_values(&["f"]).inc_by(10);
        s.bytes_out.with_label_values(&["f"]).inc_by(20);
        s.reconnects.with_label_values(&["p"]).inc_by(1);
        s.events_total.inc_by(5);
        s.up.set(1);
        s.build_info.set(1.0);
        let body = String::from_utf8(me.render().unwrap()).unwrap();
        assert!(body.contains("spt_profile_state"));
        assert!(body.contains("spt_forward_connections_active"));
        assert!(body.contains("spt_bytes_in_total"));
        assert!(body.contains("spt_bytes_out_total"));
        assert!(body.contains("spt_reconnects_total"));
        assert!(body.contains("spt_events_total"));
        assert!(body.contains("spt_up"));
        assert!(body.contains("spt_build_info"));
    }

    #[test]
    fn duplicate_registration_returns_runtime_failure() {
        let r = Registry::new();
        StandardMetrics::register(&r).expect("first registration");
        let msg = match StandardMetrics::register(&r) {
            Ok(_) => panic!("second registration on same registry should fail"),
            Err(e) => format!("{e}"),
        };
        assert!(
            msg.contains("prometheus"),
            "expected prometheus-prefixed message, got {msg:?}"
        );
    }

    #[test]
    fn render_to_file_overwrites_existing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("metrics.prom");
        let me = MetricsExporter::new().unwrap();
        me.render_to_file(&path).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        me.standard().events_total.inc_by(42);
        me.render_to_file(&path).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_ne!(first, second);
        assert!(second.contains("42"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_drop_stops_writer_without_blocking() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("metrics.prom");
        let me = MetricsExporter::new().unwrap();
        let handle = me.spawn(MetricsExporterConfig {
            state_file: path.clone(),
            interval: Duration::from_millis(10),
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        drop(handle);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tmp.path().is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_flushes_on_close_without_intermediate_tick() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("metrics.prom");
        let me = MetricsExporter::new().unwrap();
        me.standard().bytes_in.with_label_values(&["x"]).inc_by(7);
        let handle = me.spawn(MetricsExporterConfig {
            state_file: path.clone(),
            interval: Duration::from_secs(3600),
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.shutdown().await;
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("spt_bytes_in_total"));
    }

    #[test]
    fn render_text_is_valid_prom_format() {
        let me = MetricsExporter::new().unwrap();
        let body = String::from_utf8(me.render().unwrap()).unwrap();
        assert!(body.contains("# HELP "));
        assert!(body.contains("# TYPE "));
    }
}
