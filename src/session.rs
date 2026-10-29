//! High-level record and verify on top of the tracer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::bundle::{Bundle, ExitInfo, Header, Inputs, Sizes, FORMAT};
use crate::tracer::{self, Divergence, Mode, Spec};
use crate::tree;

/// Scratch directory for the redirected standard streams.
fn scratch(tag: &str) -> io::Result<PathBuf> {
    let base = std::env::var_os("REPLAY_PROOF_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!("replay-proof-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d)?;
    Ok(d)
}

pub struct RecordRequest {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub workdir: PathBuf,
    pub stdin: Option<PathBuf>,
}

pub struct Recorded {
    pub bundle: Bundle,
    pub bytes: Vec<u8>,
    pub sizes: Sizes,
}

/// Snapshot `workdir`, run the tool in it under the recorder, snapshot the
/// result and seal everything into a bundle.
pub fn record(req: &RecordRequest) -> io::Result<Recorded> {
    let workdir = fs::canonicalize(&req.workdir)?;
    let snapshot = tree::snapshot(&workdir)?;
    let stdin = match &req.stdin {
        Some(p) => fs::read(p)?,
        None => Vec::new(),
    };
    let tmp = scratch("rec")?;
    let stdin_path = tmp.join("stdin");
    fs::write(&stdin_path, &stdin)?;
    let spec = Spec {
        argv: req.argv.clone(),
        env: req.env.clone(),
        cwd: workdir.clone(),
        stdin: stdin_path,
        stdout: tmp.join("stdout"),
        stderr: tmp.join("stderr"),
    };
    let out = tracer::run(&spec, Mode::Record)?;
    let stdout = fs::read(&spec.stdout)?;
    let stderr = fs::read(&spec.stderr)?;
    let _ = fs::remove_dir_all(&tmp);
    let after = tree::snapshot(&workdir)?;
    let events = out.streams.values().map(|v| v.len()).sum();
    let header = Header {
        format: FORMAT.into(),
        arch: "x86_64".into(),
        argv: req.argv.clone(),
        env: req.env.clone(),
        workdir: workdir.to_string_lossy().into_owned(),
        stdin_sha256: crate::sha256_hex(&stdin),
        input_tree_sha256: tree::digest(&snapshot),
        stdout_sha256: crate::sha256_hex(&stdout),
        stderr_sha256: crate::sha256_hex(&stderr),
        exit: out.exit,
        output_tree_sha256: tree::digest(&after),
        output_manifest: tree::manifest(&after),
        root_pid: out.root_pid,
        processes: out.processes,
        events,
        multithreaded: out.multithreaded,
        executables: hash_executables(&out.executables),
        record_wall_ns: out.wall_ns,
        inputs_sha256: String::new(),
        events_sha256: String::new(),
    };
    let (bundle, bytes, sizes) = Bundle {
        header,
        inputs: Inputs {
            stdin,
            snapshot,
            stdout,
            stderr,
        },
        streams: out.streams,
    }
    .seal();
    Ok(Recorded {
        bundle,
        bytes,
        sizes,
    })
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub identical: bool,
    pub claim_digest: String,
    pub workdir: String,
    pub stdout_match: bool,
    pub stderr_match: bool,
    pub exit_match: bool,
    pub tree_match: bool,
    pub replay_exit: ExitInfo,
    /// Paths that differ: `~` changed, `+` only in replay, `-` only in claim.
    pub tree_diff: Vec<String>,
    pub divergence: Option<Divergence>,
    pub unconsumed: Vec<(String, usize)>,
    /// Executables whose content differs from the recording (or that the
    /// recording did not run). Reported, not fatal: the comparison of
    /// outputs decides.
    pub executable_mismatches: Vec<String>,
    pub replay_wall_ns: u64,
}

/// What to do when the bundle's workdir already exists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    Refuse,
    Replace,
}

/// Restore the input tree at the recorded absolute path, replay, and compare
/// stdout, stderr, exit status and the output tree with the claim.
pub fn verify(bundle: &Bundle, existing: Existing, keep: bool) -> io::Result<Report> {
    let h = &bundle.header;
    let workdir = PathBuf::from(&h.workdir);
    if !workdir.is_absolute() {
        return Err(io::Error::other("workdir in bundle is not absolute"));
    }
    if tree::digest(&bundle.inputs.snapshot) != h.input_tree_sha256 {
        return Err(io::Error::other("input snapshot does not match its digest"));
    }
    if crate::sha256_hex(&bundle.inputs.stdin) != h.stdin_sha256
        || crate::sha256_hex(&bundle.inputs.stdout) != h.stdout_sha256
        || crate::sha256_hex(&bundle.inputs.stderr) != h.stderr_sha256
    {
        return Err(io::Error::other(
            "stdin/stdout/stderr do not match their digests",
        ));
    }
    if workdir.symlink_metadata().is_ok() {
        match existing {
            Existing::Refuse => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists (use --replace)", workdir.display()),
                ))
            }
            Existing::Replace => remove_tree(&workdir)?,
        }
    }
    tree::restore(&workdir, &bundle.inputs.snapshot)?;
    let tmp = scratch("rep")?;
    let stdin_path = tmp.join("stdin");
    fs::write(&stdin_path, &bundle.inputs.stdin)?;
    let spec = Spec {
        argv: h.argv.clone(),
        env: h.env.clone(),
        cwd: workdir.clone(),
        stdin: stdin_path,
        stdout: tmp.join("stdout"),
        stderr: tmp.join("stderr"),
    };
    let out = tracer::run(
        &spec,
        Mode::Replay {
            streams: &bundle.streams,
            root_pid: h.root_pid,
        },
    )?;
    let stdout = fs::read(&spec.stdout)?;
    let stderr = fs::read(&spec.stderr)?;
    let _ = fs::remove_dir_all(&tmp);
    let after = tree::snapshot(&workdir)?;
    let manifest = tree::manifest(&after);
    let tree_match = tree::digest(&after) == h.output_tree_sha256;
    let report = Report {
        identical: false,
        claim_digest: bundle.claim_digest(),
        workdir: h.workdir.clone(),
        stdout_match: stdout == bundle.inputs.stdout,
        stderr_match: stderr == bundle.inputs.stderr,
        exit_match: out.exit == h.exit,
        tree_match,
        replay_exit: out.exit,
        tree_diff: if tree_match {
            Vec::new()
        } else {
            tree::diff(&h.output_manifest, &manifest)
        },
        divergence: out.divergence,
        unconsumed: out.unconsumed,
        executable_mismatches: hash_executables(&out.executables)
            .iter()
            .filter(|(k, v)| h.executables.get(*k) != Some(*v))
            .map(|(k, _)| k.clone())
            .collect(),
        replay_wall_ns: out.wall_ns,
    };
    if !keep {
        remove_tree(&workdir)?;
    }
    let identical = report.stdout_match
        && report.stderr_match
        && report.exit_match
        && report.tree_match
        && report.divergence.is_none();
    Ok(Report {
        identical,
        ..report
    })
}

/// SHA-256 of each executable (after the run, outside the timed region).
fn hash_executables(paths: &BTreeSet<String>) -> BTreeMap<String, String> {
    paths
        .iter()
        .map(|p| {
            let d = fs::read(p)
                .map(|b| crate::sha256_hex(&b))
                .unwrap_or_else(|e| format!("unreadable: {e}"));
            (p.clone(), d)
        })
        .collect()
}

/// Remove a tree even where the tool left read-only directories.
pub fn remove_tree(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn chmod_all(p: &Path) {
        if let Ok(md) = p.symlink_metadata() {
            if md.is_dir() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() {
                        chmod_all(&e.path());
                    }
                }
            }
        }
    }
    chmod_all(p);
    fs::remove_dir_all(p)
}
