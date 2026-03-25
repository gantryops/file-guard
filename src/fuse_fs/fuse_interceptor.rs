use std::path::PathBuf;
use std::sync::Arc;

use fuser::MountOption;

use super::credential_fs::CredentialFs;
use crate::interceptor::{Interceptor, InterceptorArgs};
use crate::store::BackingStore;

struct MountSession {
    watched_path: PathBuf,
    session: fuser::BackgroundSession,
}

pub struct FuseInterceptor {
    args: Option<InterceptorArgs>,
    sessions: Vec<MountSession>,
    store: Option<Arc<dyn BackingStore>>,
    restore_on_stop: bool,
}

impl FuseInterceptor {
    pub fn new(args: InterceptorArgs) -> Self {
        return Self {
            args: Some(args),
            sessions: Vec::new(),
            store: None,
            restore_on_stop: false,
        };
    }

    fn prepare_mountpoint(
        watched_path: &PathBuf,
        store: &Arc<dyn BackingStore>,
    ) -> anyhow::Result<()> {
        let file_exists = watched_path.exists();
        let already_in_store = store.read(watched_path).is_ok();

        if file_exists && !already_in_store {
            let contents = std::fs::read(watched_path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", watched_path.display()))?;
            store.store(watched_path, &contents)?;
        }

        if file_exists {
            std::fs::remove_file(watched_path)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", watched_path.display()))?;
        }

        std::fs::write(watched_path, b"").map_err(|e| {
            anyhow::anyhow!(
                "failed to create mountpoint {}: {e}",
                watched_path.display()
            )
        })?;

        return Ok(());
    }

    fn restore_original(
        watched_path: &PathBuf,
        store: &Arc<dyn BackingStore>,
    ) -> anyhow::Result<()> {
        let contents = store.read(watched_path)?;
        std::fs::write(watched_path, contents)
            .map_err(|e| anyhow::anyhow!("failed to restore {}: {e}", watched_path.display()))?;

        return Ok(());
    }
}

impl Interceptor for FuseInterceptor {
    fn start(&mut self) -> anyhow::Result<()> {
        let args = self
            .args
            .take()
            .ok_or_else(|| anyhow::anyhow!("FuseInterceptor already started"))?;

        self.restore_on_stop = args.restore_on_stop;
        self.store = Some(args.store.clone());

        for watched_path in &args.watched_paths {
            Self::prepare_mountpoint(watched_path, &args.store)?;

            let credential_fs = CredentialFs::new(
                watched_path.clone(),
                args.store.clone(),
                args.policy.clone(),
                args.logger.clone(),
                args.rt_handle.clone(),
            )?;

            let mount_options = [
                MountOption::RO,
                MountOption::FSName("cred-guard".to_string()),
                MountOption::AllowRoot,
            ];

            let session = fuser::spawn_mount2(credential_fs, watched_path, &mount_options)
                .map_err(|e| {
                    anyhow::anyhow!("failed to mount FUSE at {}: {e}", watched_path.display())
                })?;

            self.sessions.push(MountSession {
                watched_path: watched_path.clone(),
                session,
            });

            tracing::info!("FUSE mounted at {}", watched_path.display());
        }

        tracing::info!(
            "cred-guard FUSE started, watching {} files",
            self.sessions.len()
        );

        return Ok(());
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        let sessions: Vec<MountSession> = self.sessions.drain(..).collect();
        let store = self.store.take();

        for mount in sessions {
            drop(mount.session);
            tracing::info!("FUSE unmounted at {}", mount.watched_path.display());

            let should_restore = self.restore_on_stop && store.is_some();
            if should_restore {
                let result = Self::restore_original(&mount.watched_path, store.as_ref().unwrap());
                if let Err(e) = result {
                    tracing::warn!("failed to restore {}: {e}", mount.watched_path.display());
                }
            }
        }

        return Ok(());
    }
}
