use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo,
    LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite,
    Request, TimeOrNow, WriteFlags,
};

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;
use crate::store::BackingStore;

/// Zero attribute TTL: the kernel must re-`getattr` rather than trust a cached
/// size. Paired with `FOPEN_DIRECT_IO` (see `open`), this keeps the kernel from
/// holding a stale, larger size and writing back cached pages over a file that
/// a truncate has since shrunk — the resurrection that corrupts on editor saves.
fn default_ttl() -> Duration {
    Duration::ZERO
}

fn build_file_attr(file_size: u64) -> FileAttr {
    let now = SystemTime::now();

    FileAttr {
        ino: INodeNo::ROOT,
        size: file_size,
        blocks: 1,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::RegularFile,
        // Writable: the mount now accepts gated writes (each write-open is
        // authorized like a read).
        perm: 0o644,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

fn slice_content(content: &[u8], offset: u64, size: u32) -> &[u8] {
    let start = offset as usize;
    let content_len = content.len();
    let past_end = start >= content_len;
    if past_end {
        return &[];
    }

    let remaining = content_len - start;
    let read_size = std::cmp::min(size as usize, remaining);

    &content[start..start + read_size]
}

/// Per-open-handle state. A write handle keeps a working copy of the file's
/// content (`buf`) which is persisted to the backing store on flush/release;
/// read handles serve directly from the store and keep `buf` empty.
struct HandleState {
    access: Access,
    buf: Vec<u8>,
    dirty: bool,
}

pub struct CredentialFs {
    watched_path: PathBuf,
    store: Arc<dyn BackingStore>,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
    handles: Mutex<HashMap<u64, HandleState>>,
    next_fh: AtomicU64,
    /// Live file size reported by `getattr`, updated as writes/truncates land.
    current_size: Mutex<u64>,
}

impl CredentialFs {
    pub fn new(
        watched_path: PathBuf,
        store: Arc<dyn BackingStore>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        // Tolerate an absent store entry (the watched file may not exist yet):
        // serve an empty file and let an authorized writer populate it.
        let file_size = store
            .read(&watched_path)
            .map(|c| c.len() as u64)
            .unwrap_or(0);

        Ok(Self {
            watched_path,
            store,
            policy,
            logger,
            rt_handle,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            current_size: Mutex::new(file_size),
        })
    }

    /// Identify the calling process, evaluate policy for `access`, and return
    /// the process info iff allowed.
    fn authorize(&self, pid: u32, access: Access) -> Option<ProcessInfo> {
        let info = match crate::process::identify::identify(pid) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("failed to identify pid {pid}: {e}");
                return None;
            }
        };

        let decision =
            self.rt_handle
                .block_on(self.policy.evaluate(&info, &self.watched_path, access));
        self.logger
            .log(&info, &self.watched_path, access, &decision, None);

        decision.is_allowed().then_some(info)
    }

    fn read_store_or_empty(&self) -> Vec<u8> {
        // A read error here is, in practice, "not stored yet" (new file) - serve
        // empty. Genuine IO errors on the root-owned store are surfaced by the
        // write path (store() errors map to EIO).
        self.store.read(&self.watched_path).unwrap_or_default()
    }

    fn set_size(&self, size: u64) {
        *self.current_size.lock().unwrap() = size;
    }

    fn grow_size_to(&self, size: u64) {
        let mut current = self.current_size.lock().unwrap();
        if size > *current {
            *current = size;
        }
    }

    fn register_handle(&self, state: HandleState) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(fh, state);
        fh
    }

    fn handle_access(&self, fh: u64) -> Option<Access> {
        self.handles.lock().unwrap().get(&fh).map(|s| s.access)
    }

    /// Persist a write handle's buffer to the store if dirty. Clones the buffer
    /// before releasing the lock so the store write doesn't block other ops; on
    /// failure `dirty` stays set so a later flush/release retries.
    fn persist_handle(&self, fh: u64) -> anyhow::Result<()> {
        let buf = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                Some(s) if s.access == Access::Write && s.dirty => s.buf.clone(),
                _ => return Ok(()),
            }
        };

        self.store.store(&self.watched_path, &buf)?;

        let mut handles = self.handles.lock().unwrap();
        if let Some(s) = handles.get_mut(&fh) {
            s.dirty = false;
        }
        self.set_size(buf.len() as u64);
        Ok(())
    }

    /// Apply a truncate, either against an open write handle's buffer or, when
    /// there is none, directly against the store.
    fn apply_truncate(&self, fh: Option<u64>, new_size: u64) -> anyhow::Result<()> {
        let n = new_size as usize;

        if let Some(h) = fh {
            let mut handles = self.handles.lock().unwrap();
            if let Some(state) = handles.get_mut(&h)
                && state.access == Access::Write
            {
                state.buf.resize(n, 0);
                state.dirty = true;
                drop(handles);
                self.set_size(new_size);
                return Ok(());
            }
        }

        // A truncate that carries no (matching) write handle — a path-based
        // truncate, or an `ftruncate` the kernel routed without an fh. Apply it
        // to the store, and — critically — to every open write handle's working
        // buffer too. A handle opened before this truncate still holds the older,
        // longer content; if left untouched it re-persists that stale buffer on
        // release and silently reverts the truncate, leaving the dropped tail
        // behind. Resizing the live handles keeps the truncate from being undone.
        {
            let mut handles = self.handles.lock().unwrap();
            for state in handles.values_mut() {
                if state.access == Access::Write {
                    state.buf.resize(n, 0);
                    state.dirty = true;
                }
            }
        }

        let mut content = self.read_store_or_empty();
        content.resize(n, 0);
        self.store.store(&self.watched_path, &content)?;
        self.set_size(new_size);
        Ok(())
    }
}

impl Filesystem for CredentialFs {
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let attr = build_file_attr(*self.current_size.lock().unwrap());
        reply.attr(&default_ttl(), &attr);
    }

    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        reply.error(Errno::ENOENT);
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let flags = flags.0;
        let access = Access::from_open_flags(flags);
        if self.authorize(req.pid(), access).is_none() {
            reply.error(Errno::EACCES);
            return;
        }

        let truncating = (flags & libc::O_TRUNC) != 0;
        let buf = if access == Access::Write {
            if truncating || (flags & libc::O_CREAT) != 0 {
                Vec::new()
            } else {
                self.read_store_or_empty()
            }
        } else {
            Vec::new()
        };

        // O_TRUNC empties the file immediately, even if the handle is closed
        // without a subsequent write - mark dirty so that empties is persisted.
        let dirty = access == Access::Write && truncating;
        if dirty {
            self.set_size(0);
        }

        // FOPEN_DIRECT_IO: bypass the kernel page cache entirely. Reads and
        // writes are delivered to us at the exact offsets/sizes the caller
        // issued, with no read-ahead and no deferred write-back. Without it the
        // kernel can cache pages for the old, longer file and flush stale ranges
        // after a shrink, appending resurrected bytes (the tail-duplication
        // corruption). Content is small, so the lost caching costs nothing.
        let fh = self.register_handle(HandleState { access, buf, dirty });
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        // A write handle reads back its own working buffer; a read handle reads
        // the store. An unknown fh was never authorized → EACCES.
        let from_buf = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh.0) {
                None => {
                    reply.error(Errno::EACCES);
                    return;
                }
                Some(s) if s.access == Access::Write => Some(s.buf.clone()),
                Some(_) => None,
            }
        };

        let content = from_buf.unwrap_or_else(|| self.read_store_or_empty());
        reply.data(slice_content(&content, offset, size));
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let new_len = {
            let mut handles = self.handles.lock().unwrap();
            let Some(state) = handles.get_mut(&fh.0) else {
                reply.error(Errno::EACCES);
                return;
            };
            if state.access != Access::Write {
                reply.error(Errno::EACCES);
                return;
            }

            let start = offset as usize;
            let end = start + data.len();
            if state.buf.len() < end {
                state.buf.resize(end, 0); // sparse gap zero-filled
            }
            state.buf[start..end].copy_from_slice(data);
            state.dirty = true;
            state.buf.len() as u64
        };

        self.grow_size_to(new_len);
        reply.written(data.len() as u32);
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        // The only attribute we enforce is size (truncate) - it is a write and
        // the easiest write-bypass to miss. An already-authorized write handle
        // passes; otherwise gate the truncate against the calling process.
        if let Some(new_size) = size {
            let authorized = match fh.and_then(|h| self.handle_access(h.0)) {
                Some(Access::Write) => true,
                Some(_) => false, // a read handle may not resize
                _ => self.authorize(req.pid(), Access::Write).is_some(),
            };
            if !authorized {
                reply.error(Errno::EACCES);
                return;
            }
            if let Err(e) = self.apply_truncate(fh.map(|h| h.0), new_size) {
                tracing::error!("truncate of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
                return;
            }
        }

        let attr = build_file_attr(*self.current_size.lock().unwrap());
        reply.attr(&default_ttl(), &attr);
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        match self.persist_handle(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("flush of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
            }
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        match self.persist_handle(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("fsync of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let persisted = self.persist_handle(fh.0);
        self.handles.lock().unwrap().remove(&fh.0);

        match persisted {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!(
                    "release persist of {} failed: {e}",
                    self.watched_path.display()
                );
                reply.error(Errno::EIO);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Settings};
    use crate::logging::AccessLogger;
    use crate::policy::engine::PolicyEngine;
    use crate::prompt::PromptClient;
    use std::collections::HashMap as StdHashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn slice_content_bounds() {
        let c = b"hello world";
        assert_eq!(slice_content(c, 0, 5), b"hello");
        assert_eq!(slice_content(c, 6, 100), b"world"); // size past end clamps
        assert_eq!(slice_content(c, 11, 10), b""); // at end
        assert_eq!(slice_content(c, 100, 10), b""); // past end
        assert_eq!(slice_content(c, 0, 0), b""); // zero size
    }

    struct MemStore(StdMutex<StdHashMap<PathBuf, Vec<u8>>>);

    impl BackingStore for MemStore {
        fn read(&self, id: &Path) -> anyhow::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not stored"))
        }
        fn store(&self, id: &Path, contents: &[u8]) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(id.to_path_buf(), contents.to_vec());
            Ok(())
        }
        fn delete(&self, id: &Path) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
        fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
            Ok(self.0.lock().unwrap().keys().cloned().collect())
        }
        fn exists(&self, id: &Path) -> bool {
            self.0.lock().unwrap().contains_key(id)
        }
    }

    /// A `CredentialFs` over an in-memory store, seeded with `initial`. The
    /// policy/logger are never exercised by the buffer-level methods under test.
    fn fixture(initial: &[u8]) -> (CredentialFs, PathBuf, Arc<MemStore>, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let watched = PathBuf::from("/credential");
        let store = Arc::new(MemStore(StdMutex::new(
            [(watched.clone(), initial.to_vec())].into_iter().collect(),
        )));
        let config = Config {
            settings: toml::from_str::<Settings>("default_action = \"deny\"").unwrap(),
            watch: vec![],
            rule: vec![],
        };
        let policy = Arc::new(PolicyEngine::new(
            &config,
            Arc::new(PromptClient::new(
                PathBuf::from("/nonexistent.sock"),
                Duration::from_millis(50),
                0,
            )),
        ));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(
            watched.clone(),
            store.clone() as Arc<dyn BackingStore>,
            policy,
            logger,
            rt.handle().clone(),
        )
        .unwrap();
        (fs, watched, store, rt)
    }

    /// The race that corrupted the ADC file: a write handle is open with the old,
    /// longer content buffered when a handle-less truncate (path truncate, or an
    /// `ftruncate` delivered without an fh) shrinks the file. The truncate must
    /// reach the live handle, or its stale buffer re-grows the file on release.
    #[test]
    fn fhless_truncate_is_not_reverted_by_open_write_handle() {
        let (fs, watched, store, _rt) = fixture(b"OLD-LONG-CONTENT");

        // Writer opens in place (no O_TRUNC): the handle preloads existing bytes.
        let buf = fs.read_store_or_empty();
        let fh = fs.register_handle(HandleState {
            access: Access::Write,
            buf,
            dirty: false,
        });

        // Writer overwrites the head with shorter content, leaving a stale tail
        // in the handle buffer (write() only grows — POSIX-correct on its own).
        // This mirrors `write(offset=0, b"NEW")` without a kernel `ReplyWrite`.
        {
            let mut handles = fs.handles.lock().unwrap();
            let state = handles.get_mut(&fh).unwrap();
            state.buf[0..3].copy_from_slice(b"NEW");
            state.dirty = true;
        }

        // A truncate arrives WITHOUT the fh (the bug trigger).
        fs.apply_truncate(None, 3).unwrap();

        // Release persists the handle. Pre-fix this re-wrote "NEW-LONG-CONTENT";
        // the truncate must win.
        fs.persist_handle(fh).unwrap();

        assert_eq!(
            store.read(&watched).unwrap(),
            b"NEW",
            "fh-less truncate was reverted by the open write handle's stale buffer"
        );
    }

    /// A truncate that DOES carry its write handle shrinks that handle's buffer,
    /// so the shorter content is what gets persisted (the editor ftruncate path).
    #[test]
    fn handle_truncate_shrinks_persisted_content() {
        let (fs, watched, store, _rt) = fixture(b"");
        let fh = fs.register_handle(HandleState {
            access: Access::Write,
            buf: b"HELLO WORLD".to_vec(),
            dirty: true,
        });
        fs.apply_truncate(Some(fh), 5).unwrap();
        fs.persist_handle(fh).unwrap();
        assert_eq!(store.read(&watched).unwrap(), b"HELLO");
    }
}
