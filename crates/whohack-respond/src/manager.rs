use crate::{
    Backend, Capabilities, Lease,
    quarantine::{Entry, Vault, write_json},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use whohack_core::{Action, ProcessInfo, ResponseMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Pending,
    Active,
    Degraded,
    Completed,
    Released,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: String,
    pub alert_id: i64,
    pub ts: i64,
    pub target: ProcessInfo,
    pub action: Action,
    pub status: ActionStatus,
    pub detail: String,
    pub quarantine_id: Option<String>,
    #[serde(default)]
    pub recovery: serde_json::Value,
}

#[derive(Debug)]
pub struct Manager {
    enabled: bool,
    automatic_enabled: bool,
    pause_downloads: bool,
    backend: Box<dyn Backend>,
    vault: Vault,
    journal: PathBuf,
    records: Vec<ActionRecord>,
    leases: BTreeMap<String, Box<dyn Lease>>,
}
impl Manager {
    pub fn open(data_dir: PathBuf, enabled: bool, backend: Box<dyn Backend>) -> Result<Self> {
        let vault = Vault::open(data_dir.join("quarantine"))?;
        let journal = data_dir.join("responses.json");
        let mut records: Vec<ActionRecord> = if journal.exists() {
            let f = File::open(&journal)?;
            ensure!(
                f.metadata()?.len() <= 32 * 1024 * 1024,
                "response journal exceeds 32 MiB"
            );
            serde_json::from_reader(f).context("read response journal")?
        } else {
            vec![]
        };
        ensure!(
            records.len() <= 10_000,
            "response journal exceeds 10000 operations"
        );
        for r in &mut records {
            if matches!(
                r.status,
                ActionStatus::Active | ActionStatus::Pending | ActionStatus::Degraded
            ) {
                #[cfg(windows)]
                if r.action == Action::BlockNetwork {
                    r.status = ActionStatus::Released;
                    r.detail = "Windows removed this dynamic WFP block when the previous service session ended".into();
                    continue;
                }
                r.status = ActionStatus::RecoveryRequired;
                r.detail = "The service stopped before recording completion. Inspect the target and quarantine journal before retrying; no PID-only recovery was attempted.".into();
            }
        }
        let result = Self {
            enabled,
            automatic_enabled: false,
            pause_downloads: false,
            backend,
            vault,
            journal,
            records,
            leases: BTreeMap::new(),
        };
        result.save()?;
        Ok(result)
    }
    pub fn capabilities(&self) -> Capabilities {
        let mut capabilities = if self.enabled {
            self.backend.capabilities()
        } else {
            Capabilities {
                limitation: "Response is disabled in the service configuration".into(),
                ..Default::default()
            }
        };
        if !self.vault.recovery_errors().is_empty() {
            capabilities.limitation.push_str(&format!(" {} interrupted quarantine operation(s) need inspection; see the service log. Original bytes were retained.", self.vault.recovery_errors().len()));
        }
        if self.enabled && !self.automatic_enabled() && !self.download_pause_enabled() {
            capabilities
                .limitation
                .push_str(" Automatic responses are disabled; actions require your confirmation.");
        }
        capabilities
    }
    pub fn with_download_pause(mut self, enabled: bool) -> Self {
        self.pause_downloads = enabled;
        self
    }
    pub fn download_pause_enabled(&self) -> bool {
        self.enabled && self.pause_downloads && self.backend.capabilities().suspend
    }
    /// Independent of firewall elevation and model-driven Auto. The caller must
    /// qualify evidence and check integrity/trust before requesting this pause.
    pub fn pause_download(
        &mut self,
        alert_id: i64,
        target: &ProcessInfo,
        qualified: bool,
        mode: ResponseMode,
    ) -> Result<Option<ActionRecord>> {
        if !self.download_pause_enabled()
            || !qualified
            || !target.tainted
            || mode == ResponseMode::Monitor
        {
            return Ok(None);
        }
        // Duplicate evidence must not stack suspensions of the same process.
        if let Some(record) = self.records.iter().find(|r| {
            r.target.pid == target.pid
                && r.target.start_time == target.start_time
                && r.action == Action::SuspendAndAsk
                && matches!(r.status, ActionStatus::Active | ActionStatus::Degraded)
        }) {
            return Ok(Some(record.clone()));
        }
        self.apply(alert_id, target, Action::SuspendAndAsk)
            .map(Some)
    }
    pub fn with_automatic(mut self, enabled: bool) -> Self {
        self.automatic_enabled = enabled;
        self
    }
    pub fn automatic_enabled(&self) -> bool {
        self.enabled && self.automatic_enabled && self.backend.automatic_available()
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn records(&self) -> &[ActionRecord] {
        &self.records
    }

    pub fn verify_active(&mut self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        for (id, lease) in &self.leases {
            let problem = match lease.intact() {
                Ok(true) => continue,
                Ok(false) => "An active whohack network filter was removed externally".to_string(),
                Err(error) => format!("An active response could not be verified: {error:#}"),
            };
            if let Some(record) = self.records.iter_mut().find(|r| &r.id == id)
                && record.detail != problem
            {
                record.detail = problem.clone();
                record.status = ActionStatus::Degraded;
                // Retain the lease so the user can still release remaining effects.
                problems.push(problem);
            }
        }
        if !problems.is_empty() {
            self.save()?;
        }
        Ok(problems)
    }
    pub fn quarantine_entries(&self) -> Result<Vec<Entry>> {
        self.vault.list()
    }
    pub fn restore(&self, id: &str) -> Result<PathBuf> {
        self.vault.restore(id)
    }
    fn save(&self) -> Result<()> {
        write_json(&self.journal, &self.records)
    }

    /// Monitor never changes the machine. Prompt automatically blocks only;
    /// stronger actions require an explicit resolve request from the user.
    pub fn automatic(
        &mut self,
        alert_id: i64,
        target: &ProcessInfo,
        action: Action,
        mode: ResponseMode,
    ) -> Result<Option<ActionRecord>> {
        if !self.automatic_enabled()
            || mode == ResponseMode::Monitor
            || action < Action::BlockNetwork
        {
            return Ok(None);
        }
        let action = if mode == ResponseMode::Prompt {
            Action::BlockNetwork
        } else {
            action
        };
        ensure!(
            action != Action::BlockNetwork || target.script.is_none(),
            "Automatic executable-wide blocking of a shared script interpreter requires user review"
        );
        self.apply(alert_id, target, action).map(Some)
    }
    pub fn apply(
        &mut self,
        alert_id: i64,
        target: &ProcessInfo,
        action: Action,
    ) -> Result<ActionRecord> {
        ensure!(
            self.enabled,
            "response is disabled in the service configuration"
        );
        ensure!(
            action >= Action::BlockNetwork,
            "use release for reversible allow actions"
        );
        crate::guard(target)?;
        let quarantine_file = if action == Action::KillAndQuarantine {
            Some(quarantine_target(target)?.clone())
        } else {
            None
        };
        if let Some(r) = self.records.iter().find(|r| {
            r.alert_id == alert_id
                && r.action == action
                && matches!(r.status, ActionStatus::Active | ActionStatus::Completed)
        }) {
            return Ok(r.clone());
        }
        ensure!(
            self.records.len() < 10_000,
            "response journal full; export and archive it before further actions"
        );
        let id = format!("{:032x}", rand::random::<u128>());
        let record = ActionRecord {
            id: id.clone(),
            alert_id,
            ts: whohack_core::time::now_ms(),
            target: target.clone(),
            action,
            status: ActionStatus::Pending,
            detail: "Operation requested; completion not yet confirmed".into(),
            quarantine_id: None,
            recovery: serde_json::Value::Null,
        };
        self.records.push(record);
        self.save()?; // journal intention BEFORE any effect
        let result =
            match action {
                Action::BlockNetwork => self.backend.block(target).map(|lease| {
                    self.leases.insert(id, lease);
                    (
                        ActionStatus::Active,
                        self.backend.capabilities().network_scope,
                        None,
                    )
                }),
                Action::SuspendAndAsk => self.backend.suspend(target).map(|lease| {
                    self.leases.insert(id, lease);
                    (
                        ActionStatus::Active,
                        "Process suspended; use Resume to release whohack's suspension".into(),
                        None,
                    )
                }),
                Action::KillAndQuarantine => {
                    self.backend.terminate(target).and_then(|()| {
                        // A script's interpreter belongs to the OS/application vendor.
                        // Only the captured script is quarantined in that case.
                        self.vault
                    .quarantine(quarantine_file.as_ref().expect("validated quarantine target"))
                    .context("process terminated, but quarantine failed; inspect the original file")
                    .map(|e| {
                        (
                            ActionStatus::Completed,
                            "Process terminated and file quarantined. Restore does not restart it."
                                .into(),
                            Some(e.id),
                        )
                    })
                    })
                }
                _ => unreachable!("action checked above"),
            };
        let record = self.records.last_mut().expect("record appended above");
        if let Some(lease) = self.leases.get(&record.id) {
            record.recovery = lease.recovery_data();
        }
        match &result {
            Ok((status, detail, q)) => {
                record.status = *status;
                record.detail = detail.clone();
                record.quarantine_id = q.clone();
            }
            Err(error) => {
                record.status = ActionStatus::Failed;
                record.detail = format!("{error:#}");
            }
        }
        let record = record.clone();
        self.save()?;
        result?;
        Ok(record)
    }
    pub fn release_alert(&mut self, alert_id: i64) -> Result<()> {
        let ids: Vec<_> = self
            .records
            .iter()
            .filter(|r| {
                r.alert_id == alert_id
                    && matches!(r.status, ActionStatus::Active | ActionStatus::Degraded)
            })
            .map(|r| r.id.clone())
            .collect();
        for id in ids {
            self.release(&id)?;
        }
        Ok(())
    }
    /// New evidence may share an existing automatic pause of this process.
    /// Explicit Allow on any captured alert for it releases that same hold.
    pub fn release_process_pause(&mut self, target: &ProcessInfo) -> Result<()> {
        let ids: Vec<_> = self
            .records
            .iter()
            .filter(|r| {
                r.action == Action::SuspendAndAsk
                    && r.target.pid == target.pid
                    && r.target.start_time == target.start_time
                    && r.target.exe.sha256 == target.exe.sha256
                    && matches!(r.status, ActionStatus::Active | ActionStatus::Degraded)
            })
            .map(|r| r.id.clone())
            .collect();
        for id in ids {
            self.release(&id)?;
        }
        Ok(())
    }
    pub fn release(&mut self, id: &str) -> Result<()> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .context("unknown response operation")?;
        if record.status == ActionStatus::Released {
            return Ok(());
        }
        if record.status == ActionStatus::RecoveryRequired {
            self.backend
                .recover_release(&record.target, record.action, &record.recovery)?;
        } else {
            let lease = self.leases.get_mut(id).context(
                "operation is not active in this service session; review recovery information",
            )?;
            lease.release()?;
            self.leases.remove(id);
        }
        record.status = ActionStatus::Released;
        record.detail = "whohack released its response operation".into();
        self.save()
    }
    pub fn shutdown(&mut self) -> Result<()> {
        let ids: Vec<_> = self.leases.keys().cloned().collect();
        let mut errors = Vec::new();
        for id in ids {
            if let Err(e) = self.release(&id) {
                errors.push(format!("{id}: {e:#}"));
            }
        }
        ensure!(
            errors.is_empty(),
            "response cleanup errors: {}",
            errors.join("; ")
        );
        Ok(())
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            tracing::error!(error=%e, "response cleanup failed");
        }
    }
}

fn quarantine_target(target: &ProcessInfo) -> Result<&whohack_core::FileInfo> {
    if let Some(script) = &target.script {
        return Ok(script);
    }
    if !target.downloaded_inputs.is_empty() && target.exe.yara_hits.is_empty() {
        let mut matched = target
            .downloaded_inputs
            .iter()
            .filter(|i| !i.file.yara_hits.is_empty() && i.file.sha256 != [0; 32]);
        let input = matched.next().context("The harmful input file is not identified by a content signature. Keep the process paused; the shared viewer will not be quarantined.")?;
        ensure!(
            matched.next().is_none(),
            "Multiple input files matched; individual file review is required before quarantine"
        );
        return Ok(&input.file);
    }
    Ok(&target.exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Debug)]
    struct Fake(Arc<AtomicUsize>);
    #[derive(Debug)]
    struct Hold(Arc<AtomicUsize>);
    impl Lease for Hold {
        fn release(&mut self) -> Result<()> {
            self.0.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }
    impl Backend for Fake {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                network: true,
                network_scope: "test scope".into(),
                ..Default::default()
            }
        }
        fn block(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Hold(self.0.clone())))
        }
        fn suspend(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
            anyhow::bail!("test failure")
        }
        fn terminate(&mut self, _: &ProcessInfo) -> Result<()> {
            anyhow::bail!("test failure")
        }
    }
    fn target() -> ProcessInfo {
        ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: 12345,
            ppid: 1,
            start_time: 1,
            exe: whohack_core::FileInfo {
                path: "C:/test/app.exe".into(),
                sha256: [1; 32],
                origin: whohack_core::Origin::Unknown,
                sign: whohack_core::SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1,
            },
            script: None,
            path_class: whohack_core::PathClass::Other,
            tainted: true,
            taint_root: None,
            app_id: "test".into(),
        }
    }

    #[test]
    fn opened_media_never_quarantines_a_shared_viewer_without_content_evidence() {
        let mut p = target();
        let mut content = p.exe.clone();
        content.path = "C:/Downloads/movie.mp4".into();
        content.sha256 = [2; 32];
        p.downloaded_inputs.push(whohack_core::DownloadedInput {
            file: content,
            observed_at: 1,
            read_observed: true,
        });
        assert!(quarantine_target(&p).is_err());
        p.downloaded_inputs[0]
            .file
            .yara_hits
            .push("owned_fixture".into());
        assert_eq!(
            quarantine_target(&p).unwrap().path,
            "C:/Downloads/movie.mp4"
        );
        p.exe.origin = whohack_core::Origin::Downloaded {
            url: None,
            referrer: None,
        };
        assert_eq!(
            quarantine_target(&p).unwrap().path,
            "C:/Downloads/movie.mp4"
        );
        p.downloaded_inputs.push(p.downloaded_inputs[0].clone());
        assert!(quarantine_target(&p).is_err());
    }

    #[test]
    fn independent_download_pause_requires_consent_evidence_and_non_monitor_mode() {
        #[derive(Debug)]
        struct Pause(Arc<AtomicUsize>);
        impl Backend for Pause {
            fn capabilities(&self) -> Capabilities {
                Capabilities {
                    suspend: true,
                    ..Default::default()
                }
            }
            fn automatic_available(&self) -> bool {
                false
            }
            fn block(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
                anyhow::bail!("no firewall")
            }
            fn suspend(&mut self, _: &ProcessInfo) -> Result<Box<dyn Lease>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(Hold(self.0.clone())))
            }
            fn terminate(&mut self, _: &ProcessInfo) -> Result<()> {
                anyhow::bail!("no deletion")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let mut m = Manager::open(dir.path().into(), true, Box::new(Pause(n.clone()))).unwrap();
        let mut p = target();
        p.tainted = true;
        assert!(
            m.pause_download(1, &p, true, ResponseMode::Prompt)
                .unwrap()
                .is_none()
        );
        m = m.with_download_pause(true);
        assert!(!m.automatic_enabled());
        assert!(
            m.pause_download(1, &p, false, ResponseMode::Prompt)
                .unwrap()
                .is_none()
        );
        assert!(
            m.pause_download(1, &p, true, ResponseMode::Monitor)
                .unwrap()
                .is_none()
        );
        let r = m
            .pause_download(1, &p, true, ResponseMode::Prompt)
            .unwrap()
            .unwrap();
        let duplicate = m
            .pause_download(2, &p, true, ResponseMode::Prompt)
            .unwrap()
            .unwrap();
        assert_eq!(r.id, duplicate.id);
        assert_eq!(n.load(Ordering::SeqCst), 1);
        m.release_process_pause(&p).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 0);
        p.tainted = false;
        assert!(
            m.pause_download(3, &p, true, ResponseMode::Prompt)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn monitor_prompt_failure_release_and_restart_journal() {
        let t = tempfile::tempdir().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let mut m = Manager::open(t.path().into(), true, Box::new(Fake(n.clone())))
            .unwrap()
            .with_automatic(true);
        assert!(
            m.automatic(
                1,
                &target(),
                Action::KillAndQuarantine,
                ResponseMode::Monitor
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(n.load(Ordering::SeqCst), 0);
        let r = m
            .automatic(
                1,
                &target(),
                Action::KillAndQuarantine,
                ResponseMode::Prompt,
            )
            .unwrap()
            .unwrap();
        assert_eq!(r.action, Action::BlockNetwork);
        m.apply(1, &target(), Action::BlockNetwork).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert!(m.apply(2, &target(), Action::SuspendAndAsk).is_err());
        assert_eq!(m.records.last().unwrap().status, ActionStatus::Failed);
        m.release_alert(1).unwrap();
        m.release(&r.id).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 0);
        drop(m);
        let m = Manager::open(t.path().into(), false, Box::new(Fake(n))).unwrap();
        assert_eq!(m.records.len(), 2);
        assert!(!m.capabilities().network);
    }

    #[test]
    fn missing_filter_is_reported_once_and_allow_releases_remaining_effects() {
        #[derive(Debug)]
        struct Missing(Arc<AtomicUsize>);
        impl Lease for Missing {
            fn intact(&self) -> Result<bool> {
                Ok(false)
            }
            fn release(&mut self) -> Result<()> {
                self.0.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        }
        let t = tempfile::tempdir().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let mut m = Manager::open(t.path().into(), true, Box::new(Fake(n.clone()))).unwrap();
        let r = m.apply(1, &target(), Action::BlockNetwork).unwrap();
        m.leases.insert(r.id.clone(), Box::new(Missing(n.clone())));
        assert_eq!(m.verify_active().unwrap().len(), 1);
        assert_eq!(m.records()[0].status, ActionStatus::Degraded);
        assert!(m.verify_active().unwrap().is_empty());
        m.release_alert(1).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert_eq!(m.records()[0].status, ActionStatus::Released);
    }

    #[test]
    fn confirmation_only_survives_auto_mode_and_still_allows_explicit_response() {
        let t = tempfile::tempdir().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let mut m = Manager::open(t.path().into(), true, Box::new(Fake(n.clone()))).unwrap();
        for mode in [
            ResponseMode::Monitor,
            ResponseMode::Prompt,
            ResponseMode::Auto,
        ] {
            for action in [
                Action::BlockNetwork,
                Action::SuspendAndAsk,
                Action::KillAndQuarantine,
            ] {
                assert!(m.automatic(1, &target(), action, mode).unwrap().is_none());
            }
        }
        assert!(m.records().is_empty());
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert!(
            m.capabilities()
                .limitation
                .contains("require your confirmation")
        );
        m.apply(1, &target(), Action::BlockNetwork).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
        m.release_alert(1).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn automatic_block_does_not_disable_every_instance_of_a_script_interpreter() {
        let t = tempfile::tempdir().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let mut m = Manager::open(t.path().into(), true, Box::new(Fake(n.clone())))
            .unwrap()
            .with_automatic(true);
        let mut p = target();
        p.script = Some(p.exe.clone());
        assert!(
            m.automatic(1, &p, Action::BlockNetwork, ResponseMode::Prompt)
                .is_err()
        );
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert!(m.records().is_empty());
    }
}
