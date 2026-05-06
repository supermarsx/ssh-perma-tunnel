//! Command-execution sink.
//!
//! Runs an allow-listed external program with argument templating. **No
//! shell expansion** — args are passed directly to `Command::args` so
//! attackers can't smuggle metacharacters through templated event fields.
//! Per spec §9.7, the binding's `[[events.commands]]` entry must opt in
//! with `allow_exec = true` for the dispatcher to register the sink at
//! all; we trust that gate at the call-site and don't re-check here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::timeout;

use crate::event::Event;
use crate::sinks::{Sink, SinkError};
use crate::template;

/// Trait that runs a child process. Production wires this to
/// `tokio::process::Command`; tests inject a recording impl.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` and a timeout. Return Ok on success
    /// (exit code 0) or [`SinkError`] otherwise.
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> Result<(), SinkError>;
}

/// Production runner using `tokio::process::Command`.
#[derive(Default)]
pub struct ProcessRunner;

#[async_trait]
impl CommandRunner for ProcessRunner {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        to: Duration,
    ) -> Result<(), SinkError> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.kill_on_drop(true);
        let fut = cmd.status();
        match timeout(to, fut).await {
            Err(_) => Err(SinkError::Transient(format!(
                "command {} timed out after {:?}",
                program.display(),
                to
            ))),
            Ok(Err(e)) => Err(SinkError::Permanent(format!("spawn failed: {e}"))),
            Ok(Ok(s)) if s.success() => Ok(()),
            Ok(Ok(s)) => Err(SinkError::Transient(format!(
                "command exit code {:?}",
                s.code()
            ))),
        }
    }
}

/// Command sink.
pub struct CommandSink {
    name: String,
    program: PathBuf,
    arg_templates: Vec<String>,
    timeout: Duration,
    runner: Arc<dyn CommandRunner>,
}

impl CommandSink {
    /// Construct. `program` MUST already be allow-listed by the caller.
    pub fn new(
        name: impl Into<String>,
        program: PathBuf,
        arg_templates: Vec<String>,
        timeout: Duration,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            name: name.into(),
            program,
            arg_templates,
            timeout,
            runner,
        }
    }
}

#[async_trait]
impl Sink for CommandSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "command"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let args: Vec<String> = self
            .arg_templates
            .iter()
            .map(|t| template::render_template(t, &event).0)
            .collect();
        self.runner.run(&self.program, &args, self.timeout).await
    }
}

/// Test runner.
#[derive(Default)]
pub struct RecordingRunner {
    pub calls: parking_lot::Mutex<Vec<(PathBuf, Vec<String>)>>,
    pub fail_with: parking_lot::Mutex<Option<SinkError>>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_once(&self, err: SinkError) {
        *self.fail_with.lock() = Some(err);
    }
    pub fn calls(&self) -> Vec<(PathBuf, Vec<String>)> {
        self.calls.lock().clone()
    }
}

#[async_trait]
impl CommandRunner for RecordingRunner {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        _to: Duration,
    ) -> Result<(), SinkError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
        self.calls
            .lock()
            .push((program.to_path_buf(), args.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_runs_with_templated_args() {
        let r = Arc::new(RecordingRunner::new());
        let sink = CommandSink::new(
            "notify",
            PathBuf::from("/usr/local/bin/notify"),
            vec!["--kind".into(), "{{kind}}".into(), "--msg".into(), "{{message}}".into()],
            Duration::from_secs(5),
            r.clone(),
        );
        let ev = Event::builder("profile.failed", Severity::Error)
            .message("oops")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1,
            vec!["--kind", "profile.failed", "--msg", "oops"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_propagates_failure() {
        let r = Arc::new(RecordingRunner::new());
        r.fail_once(SinkError::Transient("boom".into()));
        let sink = CommandSink::new(
            "x",
            PathBuf::from("nope"),
            vec![],
            Duration::from_secs(1),
            r,
        );
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(err.is_retryable());
    }
}
