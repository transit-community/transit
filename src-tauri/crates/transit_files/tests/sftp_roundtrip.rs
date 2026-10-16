//! End-to-end tests for the Files engine against a **real SFTP peer** —
//! `russh-sftp`'s own server half over `tokio::io::duplex`, backed by an
//! in-memory filesystem. No SSH server, no network, no fixtures on disk
//! except the tempdirs the local side legitimately writes to.
//!
//! This harness exists because the crate is stream-generic (plan §5): the
//! bytes on the wire are the same ones a Junos vEX would see, so protocol
//! behavior — chunked `readdir`, EOF semantics, `setstat`, close status —
//! is exercised for real rather than mocked.
//!
//! Traffic goes client ⇄ **relay** ⇄ server. The relay is a
//! `copy_bidirectional` task the tests own, so "the network died
//! mid-session" is expressible by aborting it — which is how the
//! load-bearing `closed_rx` lifecycle test (plan §4) is written.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh_sftp::protocol::{
    Attrs, Data, File as ProtoFile, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use tokio::io::DuplexStream;
use tokio::sync::mpsc::UnboundedReceiver;
use transit_files::{
    Direction, EntryKind, FilesConfig, FilesSession, OverwritePolicy, TransferEvent, TransferItem,
    TransferState,
};

const HOME: &str = "/home/alice";

// ---------------------------------------------------------------------
// In-memory filesystem
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Dir,
    File,
    Link,
}

#[derive(Clone, Debug)]
struct Node {
    kind: Kind,
    data: Vec<u8>,
    mtime: u32,
    target: String,
}

#[derive(Default)]
struct MemFs {
    /// Absolute, normalized paths → nodes.
    nodes: BTreeMap<String, Node>,
    /// Names a directory reports from `readdir` with **no backing node** —
    /// the hostile-server cases (`..`, `../evil`, `a/b`). Keyed by dir.
    hostile: BTreeMap<String, Vec<String>>,
    /// Canonical paths whose `open` the server refuses with
    /// `PermissionDenied` — drives the transfer-error path (finding M6).
    deny_open: BTreeSet<String>,
}

impl MemFs {
    fn new() -> Self {
        let mut fs = Self::default();
        fs.dir("/");
        fs.dir("/home");
        fs.dir(HOME);
        fs
    }

    fn dir(&mut self, path: &str) -> &mut Self {
        self.nodes.insert(
            path.to_string(),
            Node {
                kind: Kind::Dir,
                data: Vec::new(),
                mtime: 1_600_000_000,
                target: String::new(),
            },
        );
        self
    }

    fn file(&mut self, path: &str, body: &[u8], mtime: u32) -> &mut Self {
        self.nodes.insert(
            path.to_string(),
            Node {
                kind: Kind::File,
                data: body.to_vec(),
                mtime,
                target: String::new(),
            },
        );
        self
    }

    fn link(&mut self, path: &str, target: &str) -> &mut Self {
        self.nodes.insert(
            path.to_string(),
            Node {
                kind: Kind::Link,
                data: Vec::new(),
                mtime: 1_600_000_000,
                target: target.to_string(),
            },
        );
        self
    }

    fn hostile(&mut self, dir: &str, names: &[&str]) -> &mut Self {
        self.hostile.insert(
            dir.to_string(),
            names.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    fn deny_open(&mut self, path: &str) -> &mut Self {
        self.deny_open.insert(path.to_string());
        self
    }

    /// Resolve `.`/`..`/relative paths the way a POSIX server's
    /// `SSH_FXP_REALPATH` does. Works for non-existent paths too.
    fn canonicalize(&self, path: &str) -> String {
        let joined = if path.starts_with('/') {
            path.to_string()
        } else if path == "." || path.is_empty() {
            HOME.to_string()
        } else {
            format!("{HOME}/{path}")
        };
        let mut out: Vec<&str> = Vec::new();
        for seg in joined.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                s => out.push(s),
            }
        }
        format!("/{}", out.join("/"))
            .replace("//", "/")
            .trim_end_matches('/')
            .to_string()
            .or_root()
    }

    /// Direct children of `dir`, plus any hostile names configured for it.
    fn children(&self, dir: &str) -> Vec<(String, Option<Node>)> {
        let prefix = if dir == "/" {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        let mut out: Vec<(String, Option<Node>)> = self
            .nodes
            .iter()
            .filter_map(|(path, node)| {
                let rest = path.strip_prefix(&prefix)?;
                if rest.is_empty() || rest.contains('/') {
                    return None;
                }
                Some((rest.to_string(), Some(node.clone())))
            })
            .collect();
        if let Some(names) = self.hostile.get(dir) {
            for name in names {
                out.push((name.clone(), None));
            }
        }
        out
    }

    fn get(&self, path: &str) -> Option<&Node> {
        self.nodes.get(path)
    }
}

/// Tiny helper so `canonicalize` can collapse an empty result to `/`.
trait OrRoot {
    fn or_root(self) -> String;
}
impl OrRoot for String {
    fn or_root(self) -> String {
        if self.is_empty() {
            "/".to_string()
        } else {
            self
        }
    }
}

fn attrs_for(node: &Node) -> FileAttributes {
    let mut attrs = FileAttributes {
        size: Some(node.data.len() as u64),
        mtime: Some(node.mtime),
        atime: Some(node.mtime),
        permissions: Some(0o644),
        ..FileAttributes::default()
    };
    match node.kind {
        Kind::Dir => {
            attrs.permissions = Some(0o755);
            attrs.set_dir(true);
        }
        Kind::File => attrs.set_regular(true),
        // Deliberately NOT `set_regular` as well: the two mode bit sets
        // would OR into a third type.
        Kind::Link => attrs.set_symlink(true),
    }
    attrs
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

// ---------------------------------------------------------------------
// The server handler
// ---------------------------------------------------------------------

struct DirCursor {
    path: String,
    offset: usize,
}

struct FileCursor {
    path: String,
    writing: bool,
}

/// Chunk size for `readdir`, mirroring a real server: a big directory
/// arrives over several `SSH_FXP_NAME` packets terminated by `Eof`.
const READDIR_CHUNK: usize = 512;

struct Harness {
    fs: Arc<Mutex<MemFs>>,
    dirs: HashMap<String, DirCursor>,
    files: HashMap<String, FileCursor>,
    next_handle: u64,
    /// Injected latency per `read`, so a transfer can be cancelled while
    /// genuinely in flight.
    read_delay: Duration,
    /// Injected latency per `write`, so an UPLOAD can be cancelled while
    /// genuinely in flight (finding A1's cancel test).
    write_delay: Duration,
}

impl Harness {
    fn new(fs: Arc<Mutex<MemFs>>) -> Self {
        Self {
            fs,
            dirs: HashMap::new(),
            files: HashMap::new(),
            next_handle: 0,
            read_delay: Duration::ZERO,
            write_delay: Duration::ZERO,
        }
    }

    fn with_read_delay(mut self, delay: Duration) -> Self {
        self.read_delay = delay;
        self
    }

    fn with_write_delay(mut self, delay: Duration) -> Self {
        self.write_delay = delay;
        self
    }

    fn handle(&mut self, prefix: &str) -> String {
        self.next_handle += 1;
        format!("{prefix}-{}", self.next_handle)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemFs> {
        self.fs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl russh_sftp::server::Handler for Harness {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let canonical = self.lock().canonicalize(&path);
        Ok(Name {
            id,
            files: vec![ProtoFile::dummy(canonical)],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let canonical = self.lock().canonicalize(&path);
        match self.lock().get(&canonical) {
            Some(node) if node.kind == Kind::Dir => {}
            Some(_) => return Err(StatusCode::Failure),
            None => return Err(StatusCode::NoSuchFile),
        }
        let handle = self.handle("dir");
        self.dirs.insert(
            handle.clone(),
            DirCursor {
                path: canonical,
                offset: 0,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let cursor = self.dirs.get(&handle).ok_or(StatusCode::Failure)?;
        let (path, offset) = (cursor.path.clone(), cursor.offset);
        let children = self.lock().children(&path);
        if offset >= children.len() {
            return Err(StatusCode::Eof);
        }
        let end = (offset + READDIR_CHUNK).min(children.len());
        let files = children[offset..end]
            .iter()
            .map(|(name, node)| match node {
                Some(node) => ProtoFile::new(name.clone(), attrs_for(node)),
                // A hostile name with no node still needs plausible attrs.
                None => ProtoFile::new(name.clone(), FileAttributes::dummy()),
            })
            .collect();
        if let Some(cursor) = self.dirs.get_mut(&handle) {
            cursor.offset = end;
        }
        Ok(Name { id, files })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let fs = self.lock();
        let canonical = fs.canonicalize(&path);
        // `stat` follows links (one hop is enough for the fixtures).
        let node = fs.get(&canonical).ok_or(StatusCode::NoSuchFile)?;
        let node = if node.kind == Kind::Link {
            let target = fs.canonicalize(&node.target);
            fs.get(&target).ok_or(StatusCode::NoSuchFile)?
        } else {
            node
        };
        Ok(Attrs {
            id,
            attrs: attrs_for(node),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let fs = self.lock();
        let canonical = fs.canonicalize(&path);
        let node = fs.get(&canonical).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: attrs_for(node),
        })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let fs = self.lock();
        let canonical = fs.canonicalize(&path);
        let node = fs.get(&canonical).ok_or(StatusCode::NoSuchFile)?;
        if node.kind != Kind::Link {
            return Err(StatusCode::Failure);
        }
        Ok(Name {
            id,
            files: vec![ProtoFile::dummy(node.target.clone())],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let canonical = self.lock().canonicalize(&filename);
        // A server that refuses to open a specific path (finding M6).
        if self.lock().deny_open.contains(&canonical) {
            return Err(StatusCode::PermissionDenied);
        }
        let writing = pflags.contains(OpenFlags::WRITE);
        if writing {
            let mut fs = self.lock();
            // Refuse to create a file inside a directory that doesn't
            // exist, like a real server.
            let parent = canonical.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let parent = if parent.is_empty() { "/" } else { parent };
            match fs.get(parent) {
                Some(n) if n.kind == Kind::Dir => {}
                _ => return Err(StatusCode::NoSuchFile),
            }
            fs.file(&canonical, b"", 0);
        } else if self.lock().get(&canonical).is_none() {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = self.handle("file");
        self.files.insert(
            handle.clone(),
            FileCursor {
                path: canonical,
                writing,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        if !self.read_delay.is_zero() {
            tokio::time::sleep(self.read_delay).await;
        }
        let cursor = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let fs = self.lock();
        let node = fs.get(&cursor.path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= node.data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(node.data.len());
        Ok(Data {
            id,
            data: node.data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if !self.write_delay.is_zero() {
            tokio::time::sleep(self.write_delay).await;
        }
        let cursor = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        if !cursor.writing {
            return Err(StatusCode::PermissionDenied);
        }
        let path = cursor.path.clone();
        let mut fs = self.lock();
        let node = fs.nodes.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if node.data.len() < start + data.len() {
            node.data.resize(start + data.len(), 0);
        }
        node.data[start..start + data.len()].copy_from_slice(&data);
        Ok(ok_status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.dirs.remove(&handle);
        self.files.remove(&handle);
        Ok(ok_status(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let cursor = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let fs = self.lock();
        let node = fs.get(&cursor.path).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: attrs_for(node),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let mut fs = self.lock();
        let canonical = fs.canonicalize(&path);
        let node = fs.nodes.get_mut(&canonical).ok_or(StatusCode::NoSuchFile)?;
        if let Some(mtime) = attrs.mtime {
            node.mtime = mtime;
        }
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let mut fs = self.lock();
        let canonical = fs.canonicalize(&path);
        if fs.get(&canonical).is_some() {
            return Err(StatusCode::Failure);
        }
        fs.dir(&canonical);
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let mut fs = self.lock();
        let canonical = fs.canonicalize(&path);
        match fs.get(&canonical) {
            Some(node) if node.kind == Kind::Dir => {}
            Some(_) => return Err(StatusCode::Failure),
            None => return Err(StatusCode::NoSuchFile),
        }
        if !fs.children(&canonical).is_empty() {
            return Err(StatusCode::Failure);
        }
        fs.nodes.remove(&canonical);
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let mut fs = self.lock();
        let canonical = fs.canonicalize(&filename);
        match fs.get(&canonical) {
            Some(node) if node.kind == Kind::Dir => Err(StatusCode::Failure),
            Some(_) => {
                fs.nodes.remove(&canonical);
                Ok(ok_status(id))
            }
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let mut fs = self.lock();
        let from = fs.canonicalize(&oldpath);
        let to = fs.canonicalize(&newpath);
        let node = fs.nodes.remove(&from).ok_or(StatusCode::NoSuchFile)?;
        fs.nodes.insert(to, node);
        Ok(ok_status(id))
    }
}

// ---------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------

/// Start the in-memory server and return the client-side stream plus the
/// relay handle. Aborting the relay severs the link with both ends still
/// believing they are connected — the "network died" case.
async fn spawn_peer(harness: Harness) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, mut relay_client) = tokio::io::duplex(64 * 1024);
    let (mut relay_server, server) = tokio::io::duplex(64 * 1024);
    russh_sftp::server::run(server, harness).await;
    let relay = tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut relay_client, &mut relay_server).await;
    });
    (client, relay)
}

struct Peer {
    session: FilesSession,
    events: UnboundedReceiver<TransferEvent>,
    relay: tokio::task::JoinHandle<()>,
    fs: Arc<Mutex<MemFs>>,
}

async fn connect(fs: MemFs) -> Peer {
    connect_with(fs, Duration::ZERO, FilesConfig::default()).await
}

async fn connect_with(fs: MemFs, read_delay: Duration, config: FilesConfig) -> Peer {
    connect_with_delays(fs, read_delay, Duration::ZERO, config).await
}

/// Connect with a slow WRITE, so an upload can be cancelled mid-flight.
async fn connect_slow_write(fs: MemFs, write_delay: Duration) -> Peer {
    connect_with_delays(fs, Duration::ZERO, write_delay, FilesConfig::default()).await
}

async fn connect_with_delays(
    fs: MemFs,
    read_delay: Duration,
    write_delay: Duration,
    config: FilesConfig,
) -> Peer {
    let fs = Arc::new(Mutex::new(fs));
    let harness = Harness::new(Arc::clone(&fs))
        .with_read_delay(read_delay)
        .with_write_delay(write_delay);
    let (client, relay) = spawn_peer(harness).await;
    let session = FilesSession::connect(client, config)
        .await
        .expect("sftp session starts over the duplex");
    let events = session.take_events().expect("events taken once");
    Peer {
        session,
        events,
        relay,
        fs,
    }
}

/// Whether any node in the server FS is a leftover `.transitpart` temp — the
/// atomic-transfer invariant is that none survives a completed OR aborted job.
fn any_transitpart(fs: &Arc<Mutex<MemFs>>) -> bool {
    fs.lock()
        .unwrap_or_else(|e| e.into_inner())
        .nodes
        .keys()
        .any(|p| p.ends_with(".transitpart"))
}

/// Drain events for `id` until a terminal state arrives. Bounded so a
/// stuck engine fails the test instead of hanging CI.
async fn await_terminal(events: &mut UnboundedReceiver<TransferEvent>, id: &str) -> TransferEvent {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ev = events.recv().await.expect("event stream stays open");
            if ev.id == id && ev.state.is_terminal() {
                return ev;
            }
        }
    })
    .await
    .expect("a terminal transfer event within 20s")
}

/// Snapshot a node out of the server's in-memory FS.
///
/// Returns a clone rather than a guard so no `MutexGuard` is ever alive
/// across an `.await` in a test body.
fn node(fs: &Arc<Mutex<MemFs>>, path: &str) -> Option<Node> {
    fs.lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(path)
        .cloned()
}

fn read_local(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Content equality by digest rather than by `assert_eq!` on megabytes, so
/// a failure prints something readable.
fn digest(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

// ---------------------------------------------------------------------
// Browse + mutate
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_canonical_path_with_parent_kinds_and_metadata() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/juniper.conf"), b"system {}", 1_700_000_000)
        .dir(&format!("{HOME}/configs"))
        .link(
            &format!("{HOME}/latest.conf"),
            &format!("{HOME}/juniper.conf"),
        );
    let peer = connect(fs).await;

    // A relative path is canonicalized by the SERVER and echoed back —
    // navigation must build on that answer, not on user input.
    let listing = peer.session.list_dir(".").await.expect("list home");
    assert_eq!(listing.path, HOME);
    assert_eq!(listing.parent.as_deref(), Some("/home"));
    assert!(!listing.truncated);

    let by_name = |n: &str| {
        listing
            .entries
            .iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("{n} listed"))
    };
    let conf = by_name("juniper.conf");
    assert_eq!(conf.kind, EntryKind::File);
    assert_eq!(conf.size, Some(9));
    assert_eq!(conf.mtime, Some(1_700_000_000));
    assert_eq!(conf.perms.as_deref(), Some("rw-r--r--"));
    assert_eq!(by_name("configs").kind, EntryKind::Dir);
    assert_eq!(by_name("latest.conf").kind, EntryKind::Symlink);

    // `stat` reports the link's own kind but the target's size, plus the
    // target — what a properties panel needs.
    let stat = peer
        .session
        .stat(&format!("{HOME}/latest.conf"))
        .await
        .expect("stat link");
    assert_eq!(stat.kind, EntryKind::Symlink);
    assert_eq!(stat.size, Some(9));
    assert_eq!(
        stat.symlink_target.as_deref(),
        Some("/home/alice/juniper.conf")
    );

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mkdir_rename_and_delete_round_trip() {
    let peer = connect(MemFs::new()).await;
    let made = format!("{HOME}/backups");
    peer.session.mkdir(&made).await.expect("mkdir");
    assert!(peer.session.remote().try_exists(&made).await.unwrap());

    let moved = format!("{HOME}/archive");
    peer.session.rename(&made, &moved).await.expect("rename");
    assert!(!peer.session.remote().try_exists(&made).await.unwrap());

    // A non-empty directory needs the recursive flag.
    peer.fs
        .lock()
        .unwrap()
        .file(&format!("{moved}/old.conf"), b"x", 1);
    assert!(peer.session.delete(&moved, false).await.is_err());
    peer.session.delete(&moved, true).await.expect("rmdir -r");
    assert!(!peer.session.remote().try_exists(&moved).await.unwrap());

    peer.session.close().await;
    peer.relay.abort();
}

/// A recursive delete must remove a symlinked directory as a LINK, never
/// descend into it — the deleted tree would otherwise be wherever the
/// device pointed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursive_delete_unlinks_symlinks_instead_of_descending() {
    let mut fs = MemFs::new();
    fs.dir(&format!("{HOME}/precious"))
        .file(&format!("{HOME}/precious/keep.conf"), b"keep", 1)
        .dir(&format!("{HOME}/doomed"))
        .link(
            &format!("{HOME}/doomed/shortcut"),
            &format!("{HOME}/precious"),
        );
    let peer = connect(fs).await;

    peer.session
        .delete(&format!("{HOME}/doomed"), true)
        .await
        .expect("recursive delete");

    assert!(node(&peer.fs, &format!("{HOME}/doomed")).is_none());
    assert!(
        node(&peer.fs, &format!("{HOME}/precious/keep.conf")).is_some(),
        "the symlink's target tree must survive"
    );
    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listing_truncates_past_the_cap_and_flags_it() {
    let mut fs = MemFs::new();
    fs.dir(&format!("{HOME}/many"));
    // One past the cap, so the flag can only come from the cap logic.
    let cap = 20_000usize;
    for i in 0..=cap {
        fs.file(&format!("{HOME}/many/f{i:06}"), b"x", 1);
    }
    let peer = connect(fs).await;

    let listing = peer
        .session
        .list_dir(&format!("{HOME}/many"))
        .await
        .expect("list huge dir");
    assert_eq!(listing.entries.len(), cap);
    assert!(listing.truncated, "over-cap listing must flag truncation");

    peer.session.close().await;
    peer.relay.abort();
}

/// Hostile `readdir` names (T43) never reach the UI and never influence a
/// local path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_readdir_names_are_dropped_and_cannot_escape_the_dest_dir() {
    let mut fs = MemFs::new();
    fs.dir(&format!("{HOME}/drop"))
        .file(&format!("{HOME}/drop/ok.conf"), b"fine", 1)
        .hostile(
            &format!("{HOME}/drop"),
            &["..", ".", "../evil", "a/b", "esc\u{1b}[2K", "back\\slash"],
        );
    let peer = connect(fs).await;

    let listing = peer
        .session
        .list_dir(&format!("{HOME}/drop"))
        .await
        .expect("list");
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["ok.conf"],
        "only the safe name survives the T43 gate"
    );

    // And a recursive download of that directory writes exactly one file,
    // strictly inside the destination.
    let dest = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/drop"),
                dest_dir: dest.path().join("into").display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);

    let landed: Vec<String> = std::fs::read_dir(dest.path().join("into").join("drop"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(landed, vec!["ok.conf"]);
    assert!(
        std::fs::read_dir(outside.path()).unwrap().next().is_none(),
        "nothing may land outside the chosen destination"
    );

    peer.session.close().await;
    peer.relay.abort();
}

// ---------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloads_a_file_byte_for_byte_and_preserves_mtime() {
    // Multi-chunk payload so the copy loop actually loops (CHUNK = 128 KiB).
    let body: Vec<u8> = (0..(300 * 1024)).map(|i| (i % 251) as u8).collect();
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/big.bin"), &body, 1_650_000_000);
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/big.bin"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);
    assert_eq!(done.bytes_done, body.len() as u64);
    assert_eq!(done.bytes_total, Some(body.len() as u64));
    assert_eq!(done.files_done, 1);
    assert_eq!(done.skipped, 0);
    // Shared frontend contract: a single-file job knows its total is one.
    assert_eq!(done.files_total, Some(1));

    let landed = dest.path().join("big.bin");
    assert_eq!(digest(&read_local(&landed)), digest(&body));
    assert!(
        !dest.path().join("big.bin.transitpart").exists(),
        "the part file must be renamed away"
    );

    let mtime = std::fs::metadata(&landed)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(mtime, 1_650_000_000, "download preserves mtime");

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_a_file_byte_for_byte_and_preserves_mtime() {
    let peer = connect(MemFs::new()).await;
    let src = tempfile::tempdir().unwrap();
    let body: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 97) as u8).collect();
    let local = src.path().join("upload.bin");
    std::fs::write(&local, &body).unwrap();
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_610_000_000);
    std::fs::File::options()
        .write(true)
        .open(&local)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Upload,
            vec![TransferItem {
                source_path: local.display().to_string(),
                dest_dir: HOME.to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);
    assert_eq!(done.bytes_done, body.len() as u64);

    let uploaded = node(&peer.fs, &format!("{HOME}/upload.bin")).expect("uploaded node exists");
    assert_eq!(digest(&uploaded.data), digest(&body));
    assert_eq!(uploaded.mtime, 1_610_000_000, "upload preserves mtime");

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overwrite_replaces_and_skip_preserves_the_existing_destination() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/conf.txt"), b"from-device", 1);
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();
    let landed = dest.path().join("conf.txt");
    std::fs::write(&landed, b"local-original").unwrap();
    let mut events = peer.events;

    // Skip: the local file is untouched and the skip is reported.
    let skipped = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/conf.txt"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Skip,
        )
        .expect("enqueue skip");
    let ev = await_terminal(&mut events, &skipped[0].id).await;
    assert_eq!(ev.state, TransferState::Done);
    assert_eq!(ev.skipped, 1);
    assert_eq!(ev.files_done, 0);
    assert_eq!(read_local(&landed), b"local-original");

    // The pre-flight check agrees with the engine.
    let conflicts = peer
        .session
        .check_conflicts(
            Direction::Download,
            &[TransferItem {
                source_path: format!("{HOME}/conf.txt"),
                dest_dir: dest.path().display().to_string(),
            }],
        )
        .await
        .expect("conflict check");
    assert_eq!(conflicts, vec![landed.display().to_string()]);

    // Overwrite: the device's bytes win.
    let overwritten = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/conf.txt"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue overwrite");
    let ev = await_terminal(&mut events, &overwritten[0].id).await;
    assert_eq!(ev.state, TransferState::Done);
    assert_eq!(ev.skipped, 0);
    assert_eq!(read_local(&landed), b"from-device");

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_skip_or_overwrite_an_existing_remote_file() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/conf.txt"), b"remote-original", 1);
    let peer = connect(fs).await;
    let src = tempfile::tempdir().unwrap();
    let local = src.path().join("conf.txt");
    std::fs::write(&local, b"from-laptop").unwrap();
    let mut events = peer.events;

    let item = TransferItem {
        source_path: local.display().to_string(),
        dest_dir: HOME.to_string(),
    };
    let conflicts = peer
        .session
        .check_conflicts(Direction::Upload, std::slice::from_ref(&item))
        .await
        .expect("conflict check");
    assert_eq!(conflicts, vec![format!("{HOME}/conf.txt")]);

    let skipped = peer
        .session
        .enqueue(Direction::Upload, vec![item.clone()], OverwritePolicy::Skip)
        .expect("enqueue skip");
    let ev = await_terminal(&mut events, &skipped[0].id).await;
    assert_eq!(ev.skipped, 1);
    assert_eq!(
        peer.fs
            .lock()
            .unwrap()
            .get(&format!("{HOME}/conf.txt"))
            .unwrap()
            .data,
        b"remote-original"
    );

    let written = peer
        .session
        .enqueue(Direction::Upload, vec![item], OverwritePolicy::Overwrite)
        .expect("enqueue overwrite");
    let ev = await_terminal(&mut events, &written[0].id).await;
    assert_eq!(ev.state, TransferState::Done, "error: {:?}", ev.error);
    assert_eq!(
        peer.fs
            .lock()
            .unwrap()
            .get(&format!("{HOME}/conf.txt"))
            .unwrap()
            .data,
        b"from-laptop"
    );

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursive_download_rebuilds_the_tree_and_skips_symlinked_dirs() {
    let mut fs = MemFs::new();
    fs.dir(&format!("{HOME}/tree"))
        .file(&format!("{HOME}/tree/top.conf"), b"top", 1)
        .dir(&format!("{HOME}/tree/nested"))
        .file(&format!("{HOME}/tree/nested/deep.conf"), b"deep", 2)
        .dir(&format!("{HOME}/elsewhere"))
        .file(&format!("{HOME}/elsewhere/secret.conf"), b"secret", 3)
        // A symlink to a directory OUTSIDE the tree: never followed.
        .link(
            &format!("{HOME}/tree/shortcut"),
            &format!("{HOME}/elsewhere"),
        )
        .link(
            &format!("{HOME}/tree/alias.conf"),
            &format!("{HOME}/tree/top.conf"),
        );
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/tree"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);
    assert_eq!(done.files_done, 2, "two regular files, no symlinks");
    assert_eq!(done.skipped, 2, "both symlinks reported as skipped");
    // Shared frontend contract: a recursive directory job has no pre-scanned
    // total, so `files_total` stays null and the pane shows a "file N" counter.
    assert_eq!(done.files_total, None);
    assert!(
        done.warnings.iter().any(|w| w.contains("shortcut")),
        "the skipped symlink is named: {:?}",
        done.warnings
    );

    let root = dest.path().join("tree");
    assert_eq!(read_local(&root.join("top.conf")), b"top");
    assert_eq!(read_local(&root.join("nested").join("deep.conf")), b"deep");
    assert!(
        !root.join("shortcut").exists(),
        "a symlinked directory is never materialized"
    );
    assert!(!root.join("alias.conf").exists());
    assert!(
        !dest.path().join("elsewhere").exists(),
        "the link target's tree is never copied"
    );

    peer.session.close().await;
    peer.relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursive_upload_rebuilds_the_tree_remotely() {
    let peer = connect(MemFs::new()).await;
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("bundle");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.conf"), b"aaa").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub").join("b.conf"), b"bbb").unwrap();
    #[cfg(unix)]
    {
        std::fs::create_dir(src.path().join("outside")).unwrap();
        std::fs::write(src.path().join("outside").join("keep.txt"), b"keep").unwrap();
        std::os::unix::fs::symlink(src.path().join("outside"), root.join("link")).unwrap();
    }

    let descriptors = peer
        .session
        .enqueue(
            Direction::Upload,
            vec![TransferItem {
                source_path: root.display().to_string(),
                dest_dir: HOME.to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);
    assert_eq!(done.files_done, 2);

    assert_eq!(
        node(&peer.fs, &format!("{HOME}/bundle/a.conf"))
            .unwrap()
            .data,
        b"aaa"
    );
    assert_eq!(
        node(&peer.fs, &format!("{HOME}/bundle/sub/b.conf"))
            .unwrap()
            .data,
        b"bbb"
    );
    #[cfg(unix)]
    {
        assert!(
            node(&peer.fs, &format!("{HOME}/bundle/link")).is_none(),
            "a local symlinked directory is never walked"
        );
        assert_eq!(done.skipped, 1);
    }

    peer.session.close().await;
    peer.relay.abort();
}

/// Cancel mid-flight: the transfer reports `Cancelled` and the partial
/// download is removed — no truncated file wearing the real name, no
/// `.transitpart` left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_mid_transfer_reports_cancelled_and_removes_the_partial() {
    let body: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/slow.bin"), &body, 1);
    // 120 ms per 128 KiB chunk → ~16 chunks → plenty of time to cancel.
    let peer = connect_with(fs, Duration::from_millis(120), FilesConfig::default()).await;
    let dest = tempfile::tempdir().unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/slow.bin"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let id = descriptors[0].id.clone();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(peer.session.cancel_transfer(&id), "the session owns the id");
    assert!(
        !peer.session.cancel_transfer("some-other-transfer"),
        "an unknown id is not ours"
    );

    let mut events = peer.events;
    let ev = await_terminal(&mut events, &id).await;
    assert_eq!(ev.state, TransferState::Cancelled);
    assert!(
        !dest.path().join("slow.bin").exists(),
        "no truncated file under the real name"
    );
    assert!(
        !dest.path().join("slow.bin.transitpart").exists(),
        "the partial must be cleaned up"
    );
    assert!(
        !peer.session.has_active_transfers(),
        "a finished transfer is deregistered (the quit guard's question)"
    );

    peer.session.close().await;
    peer.relay.abort();
}

/// Teardown cancels queued work rather than dropping it silently: every
/// queued transfer still reports a terminal state (§6 / plan §5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_session_cancels_queued_transfers() {
    let body: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/one.bin"), &body, 1)
        .file(&format!("{HOME}/two.bin"), &body, 1)
        .file(&format!("{HOME}/three.bin"), &body, 1);
    let peer = connect_with(fs, Duration::from_millis(120), FilesConfig::default()).await;
    let dest = tempfile::tempdir().unwrap();

    let items: Vec<TransferItem> = ["one.bin", "two.bin", "three.bin"]
        .iter()
        .map(|n| TransferItem {
            source_path: format!("{HOME}/{n}"),
            dest_dir: dest.path().display().to_string(),
        })
        .collect();
    let descriptors = peer
        .session
        .enqueue(Direction::Download, items, OverwritePolicy::Overwrite)
        .expect("enqueue");
    assert!(peer.session.has_active_transfers());

    let mut events = peer.events;
    tokio::time::sleep(Duration::from_millis(150)).await;
    peer.session.close().await;

    for descriptor in &descriptors {
        let ev = await_terminal(&mut events, &descriptor.id).await;
        assert_eq!(
            ev.state,
            TransferState::Cancelled,
            "queued + running transfers all report Cancelled on teardown"
        );
    }
    peer.relay.abort();
}

/// **Finding A1.** A cancelled upload must NOT destroy the file it was
/// replacing. The old path opened the destination `WRITE|CREATE|TRUNCATE`
/// (zeroing it at byte 0) and `remove_file`'d it on cancel; the atomic
/// temp+rename means the real file is never opened until the final rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_an_upload_preserves_the_existing_remote_file() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/conf.txt"), b"remote-original", 42);
    // Slow writes + a multi-chunk file so the copy loop is genuinely still
    // running (not in close()) when we cancel.
    let peer = connect_slow_write(fs, Duration::from_millis(100)).await;
    let src = tempfile::tempdir().unwrap();
    let local = src.path().join("conf.txt");
    let body: Vec<u8> = (0..(3 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &body).unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Upload,
            vec![TransferItem {
                source_path: local.display().to_string(),
                dest_dir: HOME.to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let id = descriptors[0].id.clone();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(peer.session.cancel_transfer(&id), "the session owns the id");

    let mut events = peer.events;
    let ev = await_terminal(&mut events, &id).await;
    assert_eq!(ev.state, TransferState::Cancelled);

    // The ORIGINAL remote file is byte-for-byte (and mtime) intact.
    let conf = node(&peer.fs, &format!("{HOME}/conf.txt")).expect("original still exists");
    assert_eq!(
        conf.data, b"remote-original",
        "a cancelled upload must not touch the destination it was replacing"
    );
    assert_eq!(conf.mtime, 42, "not even the mtime changed");
    // And no temp is left behind on the device.
    assert!(
        !any_transitpart(&peer.fs),
        "the upload temp (.transitpart) must be cleaned up on cancel"
    );

    peer.session.close().await;
    peer.relay.abort();
}

/// **Finding A2.** A pre-existing `<name>.transitpart` from a crashed prior
/// run (the OLD non-unique naming) must not be truncated or renamed away —
/// the new part carries the transfer id, so it is a different path — and the
/// download still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preexisting_stale_transitpart_is_left_untouched_by_a_download() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/conf.txt"), b"from-device", 1);
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();
    // A stale part at the OLD naming a previous crash could have left.
    let stale = dest.path().join("conf.txt.transitpart");
    std::fs::write(&stale, b"STALE").unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/conf.txt"),
                dest_dir: dest.path().display().to_string(),
            }],
            // Skip only checks the real dest (conf.txt), which does not exist
            // yet — so the download proceeds.
            OverwritePolicy::Skip,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);

    assert_eq!(read_local(&dest.path().join("conf.txt")), b"from-device");
    assert_eq!(
        read_local(&stale),
        b"STALE",
        "a pre-existing stale part must never be truncated or renamed away"
    );

    peer.session.close().await;
    peer.relay.abort();
}

/// **Finding A3.** A recursive download must never write THROUGH a
/// pre-existing local symlink at a destination directory — that would land
/// files outside the user's chosen destination.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursive_download_refuses_to_write_through_a_preexisting_local_symlink() {
    let mut fs = MemFs::new();
    fs.dir(&format!("{HOME}/tree"))
        .file(&format!("{HOME}/tree/top.conf"), b"top", 1)
        .dir(&format!("{HOME}/tree/sub"))
        .file(&format!("{HOME}/tree/sub/escaped.conf"), b"escaped!", 1);
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();
    // Pre-create the destination root and a hostile symlink where the walk
    // will want to descend (`tree/sub` → an unrelated directory).
    std::fs::create_dir(dest.path().join("tree")).unwrap();
    std::os::unix::fs::symlink(escape.path(), dest.path().join("tree").join("sub")).unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/tree"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;
    assert_eq!(done.state, TransferState::Done, "error: {:?}", done.error);

    // NOTHING was written through the link into the escape directory.
    assert!(
        std::fs::read_dir(escape.path()).unwrap().next().is_none(),
        "no file may be written through a pre-existing local symlink"
    );
    assert!(!escape.path().join("escaped.conf").exists());
    // A normal file at the root still downloads (the walk is not aborted).
    assert_eq!(
        read_local(&dest.path().join("tree").join("top.conf")),
        b"top"
    );
    // The symlinked child dir was skipped, with a warning naming it.
    assert!(done.skipped >= 1, "the symlinked dir is counted as skipped");
    assert!(
        done.warnings.iter().any(|w| w.contains("sub")),
        "the skipped symlink dir is named: {:?}",
        done.warnings
    );

    peer.session.close().await;
    peer.relay.abort();
}

/// **Finding A5.** The transfer-event forwarder self-terminates when the
/// session (and thus its event sender) drops — which is exactly why the
/// disconnect/reconnect paths must NOT abort it explicitly. A stand-in
/// forwarder loop must end on its own once the session is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_session_closes_the_event_stream_so_a_forwarder_ends() {
    let peer = connect(MemFs::new()).await;
    let Peer {
        session,
        events,
        relay,
        ..
    } = peer;
    let mut events = events;
    // Mirrors `transit_app::files`'s forwarder task, which we no longer abort.
    let forwarder = tokio::spawn(async move { while events.recv().await.is_some() {} });

    session.close().await; // drops the event senders (queue + worker)

    tokio::time::timeout(Duration::from_secs(5), forwarder)
        .await
        .expect("the forwarder self-terminates once the session drops")
        .expect("the forwarder task did not panic");
    relay.abort();
}

/// **Finding M6.** A `PermissionDenied` open drives the transfer to a
/// terminal `Error` carrying a message — the previously-untested Error path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permission_denied_open_drives_the_transfer_to_error() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/secret.conf"), b"top secret", 1);
    fs.deny_open(&format!("{HOME}/secret.conf"));
    let peer = connect(fs).await;
    let dest = tempfile::tempdir().unwrap();

    let descriptors = peer
        .session
        .enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: format!("{HOME}/secret.conf"),
                dest_dir: dest.path().display().to_string(),
            }],
            OverwritePolicy::Overwrite,
        )
        .expect("enqueue");
    let mut events = peer.events;
    let done = await_terminal(&mut events, &descriptors[0].id).await;

    assert_eq!(done.state, TransferState::Error);
    assert!(
        done.error.is_some(),
        "an errored transfer must carry an error message"
    );
    assert!(
        !dest.path().join("secret.conf").exists(),
        "nothing lands on a denied read"
    );
    // The session survives a per-operation error (only session-fatal errors
    // close it).
    assert!(!peer.session.is_closed(), "a PermissionDenied is not fatal");

    peer.session.close().await;
    peer.relay.abort();
}

// ---------------------------------------------------------------------
// Lifecycle — the plan §4 risk, pinned
// ---------------------------------------------------------------------

/// **The load-bearing lifecycle test.** `into_stream()` destroys the
/// `ChannelMsg::Eof` observation point and russh-sftp swallows EOF, so
/// without `WatchedStream` the pane would show a live browser over a dead
/// socket. Severing the link must flip `closed_rx` and make subsequent
/// operations fail as `SessionClosed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn severing_the_link_trips_closed_rx_and_fails_later_operations() {
    let mut fs = MemFs::new();
    fs.file(&format!("{HOME}/conf.txt"), b"x", 1);
    let peer = connect(fs).await;
    let mut closed = peer.session.closed_rx();

    assert!(!*closed.borrow(), "a healthy session reads open");
    peer.session.list_dir(HOME).await.expect("list while alive");

    // The relay is the "network": killing it drops both inner ends, so the
    // client's next read completes with 0 bytes.
    peer.relay.abort();

    tokio::time::timeout(Duration::from_secs(5), closed.changed())
        .await
        .expect("closed flag flips within 5s")
        .expect("watch channel stays alive");
    assert!(*closed.borrow());
    assert!(peer.session.is_closed());

    let err = peer.session.list_dir(HOME).await;
    assert!(
        matches!(err, Err(transit_files::FilesError::SessionClosed)),
        "operations after the close must report SessionClosed, got {err:?}"
    );
    // Queueing into a dead session is refused too, so no queue row is left
    // waiting forever.
    let refused = peer.session.enqueue(
        Direction::Download,
        vec![TransferItem {
            source_path: format!("{HOME}/conf.txt"),
            dest_dir: "/tmp".to_string(),
        }],
        OverwritePolicy::Overwrite,
    );
    assert!(refused.is_err());

    peer.session.close().await;
}

/// A session whose peer never speaks SFTP must fail to connect rather than
/// hang or half-initialize — the device-has-no-SFTP-server shape, once the
/// subsystem itself started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_fails_when_the_peer_is_not_an_sftp_server() {
    let (client, server) = tokio::io::duplex(1024);
    // Peer immediately hangs up instead of answering INIT.
    drop(server);
    let outcome = FilesSession::connect(
        client,
        FilesConfig {
            request_timeout_secs: 2,
            ..FilesConfig::default()
        },
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string());
    assert!(
        matches!(&outcome, Err(detail) if detail.contains("could not start an SFTP session")),
        "expected an Init error, got {outcome:?}"
    );
}
