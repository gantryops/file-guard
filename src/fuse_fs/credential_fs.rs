use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    FUSE_ROOT_ID, FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyEntry, ReplyOpen,
    Request,
};

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::store::BackingStore;

fn default_ttl() -> Duration {
    return Duration::from_secs(1);
}

fn build_file_attr(file_size: u64) -> FileAttr {
    let now = SystemTime::now();

    return FileAttr {
        ino: FUSE_ROOT_ID,
        size: file_size,
        blocks: 1,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::RegularFile,
        perm: 0o444,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 512,
        flags: 0,
    };
}

fn slice_content(content: &[u8], offset: i64, size: u32) -> &[u8] {
    let start = offset as usize;
    let content_len = content.len();
    let past_end = start >= content_len;
    if past_end {
        return &[];
    }

    let remaining = content_len - start;
    let read_size = std::cmp::min(size as usize, remaining);

    return &content[start..start + read_size];
}

pub struct CredentialFs {
    watched_path: PathBuf,
    store: Arc<dyn BackingStore>,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
    allowed_handles: Mutex<HashMap<u64, ()>>,
    next_fh: AtomicU64,
    file_size: u64,
}

impl CredentialFs {
    pub fn new(
        watched_path: PathBuf,
        store: Arc<dyn BackingStore>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let content = store.read(&watched_path)?;
        let file_size = content.len() as u64;

        return Ok(Self {
            watched_path,
            store,
            policy,
            logger,
            rt_handle,
            allowed_handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            file_size,
        });
    }

    fn handle_open_request(&self, pid: u32) -> bool {
        let identification = crate::process::identify::identify(pid);

        let info = match identification {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("failed to identify pid {pid}: {e}");
                return false;
            }
        };

        let decision = self
            .rt_handle
            .block_on(self.policy.evaluate(&info, &self.watched_path));
        self.logger.log(&info, &self.watched_path, &decision, None);
        let allowed = decision.is_allowed();

        return allowed;
    }

    fn is_handle_allowed(&self, fh: u64) -> bool {
        let handles = self.allowed_handles.lock().unwrap();
        let allowed = handles.contains_key(&fh);

        return allowed;
    }

    fn register_handle(&self) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.allowed_handles.lock().unwrap().insert(fh, ());

        return fh;
    }

    fn release_handle(&self, fh: u64) {
        self.allowed_handles.lock().unwrap().remove(&fh);
    }
}

impl Filesystem for CredentialFs {
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let is_root = ino == FUSE_ROOT_ID;
        if !is_root {
            reply.error(libc::ENOENT);
            return;
        }

        let attr = build_file_attr(self.file_size);
        reply.attr(&default_ttl(), &attr);
    }

    fn lookup(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: ReplyEntry) {
        reply.error(libc::ENOENT);
    }

    fn open(&mut self, req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let is_root = ino == FUSE_ROOT_ID;
        if !is_root {
            reply.error(libc::ENOENT);
            return;
        }

        let pid = req.pid();
        let allowed = self.handle_open_request(pid);
        if !allowed {
            reply.error(libc::EACCES);
            return;
        }

        let fh = self.register_handle();
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let is_root = ino == FUSE_ROOT_ID;
        if !is_root {
            reply.error(libc::ENOENT);
            return;
        }

        let allowed = self.is_handle_allowed(fh);
        if !allowed {
            reply.error(libc::EACCES);
            return;
        }

        let content = match self.store.read(&self.watched_path) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    "failed to read backing store for {}: {e}",
                    self.watched_path.display()
                );
                reply.error(libc::EIO);
                return;
            }
        };

        let slice = slice_content(&content, offset, size);
        reply.data(slice);
    }

    fn release(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let is_root = ino == FUSE_ROOT_ID;
        if !is_root {
            reply.error(libc::ENOENT);
            return;
        }

        self.release_handle(fh);
        reply.ok();
    }
}
