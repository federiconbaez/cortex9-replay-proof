//! Snapshot, digest and restore of a working directory.
//!
//! The digest covers relative path, entry type, permission bits and content
//! (or symlink target). Timestamps are kept in the snapshot so a restore
//! looks like the original, but they are not part of the digest: files the
//! tool writes get the replay host's clock, which the tool never observes
//! through the replayed `stat` family.

use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Dir = 1,
    File = 2,
    Symlink = 3,
    Other = 4,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Dir,
            2 => Self::File,
            3 => Self::Symlink,
            4 => Self::Other,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Path relative to the root, `/`-separated, raw bytes.
    pub path: Vec<u8>,
    pub kind: EntryKind,
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
    /// File content or symlink target; empty for directories.
    pub data: Vec<u8>,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl Entry {
    /// Digest of one entry (what the manifest lists per path).
    pub fn digest(&self) -> String {
        let mut buf = Vec::with_capacity(self.data.len() + 16);
        buf.push(self.kind as u8);
        buf.extend_from_slice(&self.mode.to_le_bytes());
        buf.extend_from_slice(&self.data);
        crate::sha256_hex(&buf)
    }
}

/// Read the whole tree under `root` (not following symlinks), sorted by path.
pub fn snapshot(root: &Path) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    walk(root, Vec::new(), &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn walk(dir: &Path, prefix: Vec<u8>, out: &mut Vec<Entry>) -> io::Result<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let mut rel = prefix.clone();
        if !rel.is_empty() {
            rel.push(b'/');
        }
        rel.extend_from_slice(ent.file_name().as_bytes());
        let p = ent.path();
        let md = fs::symlink_metadata(&p)?;
        let ft = md.file_type();
        let (kind, data) = if ft.is_dir() {
            (EntryKind::Dir, Vec::new())
        } else if ft.is_file() {
            (EntryKind::File, fs::read(&p)?)
        } else if ft.is_symlink() {
            (
                EntryKind::Symlink,
                fs::read_link(&p)?.as_os_str().as_bytes().to_vec(),
            )
        } else {
            (EntryKind::Other, Vec::new())
        };
        out.push(Entry {
            path: rel.clone(),
            kind,
            mode: md.mode() & 0o7777,
            data,
            mtime_sec: md.mtime(),
            mtime_nsec: md.mtime_nsec(),
        });
        if kind == EntryKind::Dir {
            walk(&p, rel, out)?;
        }
    }
    Ok(())
}

/// Digest of a whole tree: SHA-256 over `(path, entry digest)` in path order.
pub fn digest(entries: &[Entry]) -> String {
    let mut buf = Vec::new();
    for e in entries {
        buf.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        buf.extend_from_slice(&e.path);
        buf.extend_from_slice(e.digest().as_bytes());
    }
    crate::sha256_hex(&buf)
}

/// Per-path digests, lossy UTF-8 paths, in path order.
pub fn manifest(entries: &[Entry]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|e| (String::from_utf8_lossy(&e.path).into_owned(), e.digest()))
        .collect()
}

/// Recreate `entries` under `root`, which must not exist yet.
pub fn restore(root: &Path, entries: &[Entry]) -> io::Result<()> {
    fs::create_dir_all(root.parent().unwrap_or(Path::new("/")))?;
    fs::create_dir(root)?;
    for e in entries {
        let p = root.join(OsStr::from_bytes(&e.path));
        match e.kind {
            EntryKind::Dir => fs::create_dir(&p)?,
            EntryKind::File => fs::write(&p, &e.data)?,
            EntryKind::Symlink => std::os::unix::fs::symlink(OsStr::from_bytes(&e.data), &p)?,
            EntryKind::Other => continue,
        }
        if e.kind == EntryKind::File {
            fs::set_permissions(&p, fs::Permissions::from_mode(e.mode))?;
        }
    }
    // Timestamps last (writing a child changes its directory's mtime), and
    // directory permissions after their content exists.
    for e in entries.iter().rev() {
        if e.kind == EntryKind::Other {
            continue;
        }
        let p = root.join(OsStr::from_bytes(&e.path));
        set_mtime(&p, e.mtime_sec, e.mtime_nsec)?;
        if e.kind == EntryKind::Dir {
            fs::set_permissions(&p, fs::Permissions::from_mode(e.mode))?;
        }
    }
    Ok(())
}

fn set_mtime(p: &Path, sec: i64, nsec: i64) -> io::Result<()> {
    let c = CString::new(p.as_os_str().as_bytes())?;
    let ts = [
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
    ];
    // SAFETY: valid NUL-terminated path and a two-element timespec array.
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            ts.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Paths whose entry differs between two trees (added, removed or changed).
pub fn diff(a: &[(String, String)], b: &[(String, String)]) -> Vec<String> {
    use std::collections::BTreeMap;
    let ma: BTreeMap<_, _> = a.iter().cloned().collect();
    let mb: BTreeMap<_, _> = b.iter().cloned().collect();
    let mut out = Vec::new();
    for (k, v) in &ma {
        match mb.get(k) {
            None => out.push(format!("-{k}")),
            Some(w) if w != v => out.push(format!("~{k}")),
            _ => {}
        }
    }
    for k in mb.keys() {
        if !ma.contains_key(k) {
            out.push(format!("+{k}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rp-tree-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn snapshot_restore_roundtrip_keeps_digest_and_mtime() {
        let a = tmp("a");
        fs::create_dir_all(a.join("sub/deeper")).unwrap();
        fs::write(a.join("f.txt"), b"hello").unwrap();
        fs::write(a.join("sub/deeper/x"), b"\x00\x01").unwrap();
        fs::set_permissions(a.join("f.txt"), fs::Permissions::from_mode(0o751)).unwrap();
        std::os::unix::fs::symlink("f.txt", a.join("link")).unwrap();
        set_mtime(&a.join("f.txt"), 1_000_000, 5).unwrap();
        let s = snapshot(&a).unwrap();
        assert_eq!(s.len(), 5);
        let b = tmp("b");
        restore(&b, &s).unwrap();
        let t = snapshot(&b).unwrap();
        assert_eq!(digest(&s), digest(&t));
        let f = t.iter().find(|e| e.path == b"f.txt").unwrap();
        assert_eq!((f.mtime_sec, f.mtime_nsec, f.mode), (1_000_000, 5, 0o751));
        fs::write(b.join("f.txt"), b"changed").unwrap();
        fs::write(b.join("new"), b"").unwrap();
        let u = snapshot(&b).unwrap();
        assert_ne!(digest(&s), digest(&u));
        assert_eq!(
            diff(&manifest(&s), &manifest(&u)),
            vec!["~f.txt".to_string(), "+new".to_string()]
        );
        fs::remove_dir_all(&a).unwrap();
        fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn digest_ignores_mtime_but_not_mode() {
        let a = tmp("c");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("f"), b"x").unwrap();
        let d1 = digest(&snapshot(&a).unwrap());
        set_mtime(&a.join("f"), 42, 0).unwrap();
        assert_eq!(d1, digest(&snapshot(&a).unwrap()));
        fs::set_permissions(a.join("f"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(d1, digest(&snapshot(&a).unwrap()));
        fs::remove_dir_all(&a).unwrap();
    }
}
