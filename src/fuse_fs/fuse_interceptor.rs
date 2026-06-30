use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuser::{Config, MountOption, SessionACL};

use super::credential_fs::CredentialFs;
use crate::interceptor::{Interceptor, InterceptorArgs};
use crate::store::BackingStore;

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash) the kernel writes for whitespace in `/proc/mounts` fields.
fn unescape_mount_field(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..=i + 3].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mountpoints in `/proc/mounts`-formatted `contents` that are file-guard
/// FUSE mounts (`<source> <target> <fstype> ...`, source field 1).
fn file_guard_mountpoints(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let source = f.next()?;
            let target = f.next()?;
            let fstype = f.next()?;
            (source == "file-guard" && fstype.starts_with("fuse"))
                .then(|| unescape_mount_field(target))
        })
        .collect()
}

/// Lazily detach any leftover file-guard mount at `watched_path`. A daemon that
/// died without running its unmount path (SIGKILL, crash, hard restart) leaves
/// the mountpoint as a wedged FUSE endpoint whose reads/writes fail with
/// ENOTCONN, so the next start can't recreate the file there. systemd runs a
/// single instance, so any file-guard mount still present at our path on start
/// is by definition orphaned and safe to detach — making startup self-healing.
fn clear_stale_mount(watched_path: &Path) {
    let proc_mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let target = watched_path.to_string_lossy();
    if !file_guard_mountpoints(&proc_mounts)
        .iter()
        .any(|m| m.as_str() == target)
    {
        return;
    }

    tracing::warn!(
        "clearing orphaned file-guard mount at {} (left by a previous daemon)",
        watched_path.display()
    );
    match CString::new(watched_path.as_os_str().as_bytes()) {
        // MNT_DETACH detaches even a wedged endpoint; the kernel completes the
        // teardown once the mount is no longer busy.
        Ok(c) => {
            if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } != 0 {
                tracing::warn!(
                    "failed to detach stale mount {}: {}",
                    watched_path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Err(e) => tracing::warn!("bad mountpoint path {}: {e}", watched_path.display()),
    }
}

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
        Self {
            args: Some(args),
            sessions: Vec::new(),
            store: None,
            restore_on_stop: false,
        }
    }

    /// Move the real credential into the backing store (if needed) and leave an
    /// empty file to mount over.
    fn prepare_mountpoint(
        watched_path: &Path,
        store: &Arc<dyn BackingStore>,
    ) -> anyhow::Result<()> {
        // Self-heal across an unclean shutdown: a leftover mount from a crashed
        // daemon wedges this path (ENOTCONN), so detach it before we touch it.
        clear_stale_mount(watched_path);

        // M3: never operate on a symlink - following it could expose or clobber
        // an unintended target. Require the operator to resolve it first.
        if let Ok(meta) = std::fs::symlink_metadata(watched_path)
            && meta.file_type().is_symlink()
        {
            anyhow::bail!(
                "{} is a symlink; refusing to guard it (point the watch at the real file)",
                watched_path.display()
            );
        }

        let on_disk = std::fs::read(watched_path).ok();
        let in_store = store.read(watched_path).ok();

        // H2: if there is real on-disk content the store doesn't already hold
        // (a brand-new file, or one the user edited while we were stopped), it
        // is authoritative - capture it before we replace it, so we never lose
        // newer credentials. An *empty* on-disk file is a leftover mountpoint
        // from a previous run and must NOT overwrite stored content.
        if let Some(disk) = &on_disk
            && !disk.is_empty()
            && in_store.as_deref() != Some(disk.as_slice())
        {
            store.store(watched_path, disk)?;
        }

        if on_disk.is_some() {
            std::fs::remove_file(watched_path)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", watched_path.display()))?;
        } else if let Some(parent) = watched_path.parent() {
            // H10: the watched file may not exist yet - make sure its directory
            // does, then mount an empty file there.
            std::fs::create_dir_all(parent).ok();
        }

        std::fs::write(watched_path, b"").map_err(|e| {
            anyhow::anyhow!(
                "failed to create mountpoint {}: {e}",
                watched_path.display()
            )
        })?;

        Ok(())
    }

    fn restore_original(watched_path: &Path, store: &Arc<dyn BackingStore>) -> anyhow::Result<()> {
        let contents = store.read(watched_path)?;
        std::fs::write(watched_path, contents)
            .map_err(|e| anyhow::anyhow!("failed to restore {}: {e}", watched_path.display()))?;

        Ok(())
    }

    /// H9: undo a partially-completed start. Unmount everything mounted so far
    /// and put every captured original back, so a failure midway never leaves
    /// credentials stranded in the store with no live mount.
    fn rollback(&mut self, store: &Arc<dyn BackingStore>, prepared: &[PathBuf]) {
        for mount in self.sessions.drain(..) {
            drop(mount.session);
        }
        for path in prepared {
            match store.read(path) {
                Ok(content) => {
                    let _ = std::fs::write(path, content);
                    let _ = store.delete(path);
                }
                // Nothing was captured (the original was absent) - just remove
                // the empty mountpoint we created.
                Err(_) => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
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

        let mut prepared: Vec<PathBuf> = Vec::new();

        for watched_path in &args.watched_paths {
            let setup = (|| -> anyhow::Result<()> {
                Self::prepare_mountpoint(watched_path, &args.store)?;
                prepared.push(watched_path.clone());

                let credential_fs = CredentialFs::new(
                    watched_path.clone(),
                    args.store.clone(),
                    args.policy.clone(),
                    args.logger.clone(),
                    args.rt_handle.clone(),
                )?;

                // Read-write mount: writes are gated per-open like reads.
                let mut config = Config::default();
                config.mount_options = vec![MountOption::FSName("file-guard".to_string())];
                // When the daemon runs as root (the privileged deployment), the
                // mount must be reachable by the guarded user's own processes.
                // Requires `user_allow_other` in /etc/fuse.conf
                // (NixOS: programs.fuse.userAllowOther = true).
                if unsafe { libc::geteuid() == 0 } {
                    config.acl = SessionACL::All;
                }

                let session =
                    fuser::spawn_mount2(credential_fs, watched_path, &config).map_err(|e| {
                        anyhow::anyhow!("failed to mount FUSE at {}: {e}", watched_path.display())
                    })?;

                self.sessions.push(MountSession {
                    watched_path: watched_path.clone(),
                    session,
                });
                tracing::info!("FUSE mounted at {}", watched_path.display());
                Ok(())
            })();

            if let Err(e) = setup {
                tracing::error!(
                    "failed to set up {}: {e}; rolling back",
                    watched_path.display()
                );
                self.rollback(&args.store, &prepared);
                return Err(e);
            }
        }

        tracing::info!(
            "file-guard FUSE started, watching {} files",
            self.sessions.len()
        );

        Ok(())
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{file_guard_mountpoints, unescape_mount_field};

    #[test]
    fn unescape_decodes_octal_whitespace() {
        assert_eq!(unescape_mount_field("/a/b"), "/a/b");
        assert_eq!(unescape_mount_field("/a\\040b"), "/a b"); // space
        assert_eq!(unescape_mount_field("/a\\134b"), "/a\\b"); // backslash
        assert_eq!(unescape_mount_field("trailing\\04"), "trailing\\04"); // not a full escape
    }

    #[test]
    fn finds_only_file_guard_fuse_mounts() {
        let proc_mounts = "\
proc /proc proc rw,nosuid 0 0
file-guard /home/u/.config/gcloud/credentials.db fuse rw,nosuid,allow_other 0 0
file-guard /home/u/with\\040space/adc.json fuse.file-guard rw 0 0
/dev/sda1 / ext4 rw 0 0
other-fuse /mnt/x fuse rw 0 0
";
        let mounts = file_guard_mountpoints(proc_mounts);
        assert_eq!(
            mounts,
            vec![
                "/home/u/.config/gcloud/credentials.db".to_string(),
                "/home/u/with space/adc.json".to_string(),
            ],
            "must match file-guard fuse mounts only, decoding escapes"
        );
    }
}
