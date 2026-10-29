//! End-to-end record/verify tests. They need ptrace and seccomp on the
//! host; if either is unavailable they fail (they are never skipped).
//!
//! The tracer waits with `waitpid(-1)`, so runs in one process must not
//! overlap: every test holds `LOCK`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use replay_proof::bundle::Bundle;
use replay_proof::session::{self, Existing, RecordRequest, Recorded, Report};
use replay_proof::syscalls;

static LOCK: Mutex<()> = Mutex::new(());

fn workdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("rp-it-{}", std::process::id()));
    let w = base.join(name);
    if w.exists() {
        session::remove_tree(&w).unwrap();
    }
    std::fs::create_dir_all(w.join("home")).unwrap();
    w
}

fn env(w: &Path) -> Vec<String> {
    vec![
        "PATH=/usr/local/bin:/usr/bin:/bin".into(),
        format!("HOME={}", w.join("home").display()),
        "LANG=C.UTF-8".into(),
        "GIT_CONFIG_NOSYSTEM=1".into(),
        "GIT_AUTHOR_NAME=T".into(),
        "GIT_AUTHOR_EMAIL=t@example.invalid".into(),
        "GIT_COMMITTER_NAME=T".into(),
        "GIT_COMMITTER_EMAIL=t@example.invalid".into(),
    ]
}

fn record_sh(w: &Path, script: &str) -> Recorded {
    session::record(&RecordRequest {
        argv: vec!["sh".into(), "-c".into(), script.into()],
        env: env(w),
        workdir: w.to_path_buf(),
        stdin: None,
    })
    .expect("record")
}

fn verify(b: &Bundle) -> Report {
    session::verify(b, Existing::Replace, false).expect("verify")
}

fn assert_identical(r: &Report) {
    assert!(r.identical, "replay differs: {r:?}");
}

const PY_NONDET: &str = "python3 -c 'import time, os, random, uuid; \
print(time.time(), os.getpid(), random.random(), uuid.uuid4(), hash(\"k\"), id(object()))'";

#[test]
fn python_nondeterminism_is_replayed_and_differs_without_replay() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("py");
    let a = record_sh(&w, PY_NONDET);
    let b = record_sh(&w, PY_NONDET);
    // Control: two plain recordings disagree, so the output really is
    // nondeterministic.
    assert_ne!(a.bundle.inputs.stdout, b.bundle.inputs.stdout);
    assert_eq!(a.bundle.header.exit.code, Some(0));
    assert_identical(&verify(&a.bundle));
    assert_identical(&verify(&b.bundle));
}

#[test]
fn vdso_is_hidden_so_time_reads_are_system_calls() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("vdso");
    let r = record_sh(&w, "date +%s%N");
    let clock = r
        .bundle
        .streams
        .values()
        .flatten()
        .filter(|e| e.nr as u64 == syscalls::CLOCK_GETTIME)
        .count();
    assert!(clock > 0, "no clock_gettime reached the tracer");
    let execs = r
        .bundle
        .streams
        .values()
        .flatten()
        .filter(|e| e.nr == syscalls::EV_EXEC)
        .count();
    assert_eq!(execs, 2, "sh and date each exec once");
    let exes = &r.bundle.header.executables;
    assert!(exes.keys().any(|k| k.ends_with("/date")), "{exes:?}");
    assert!(exes.values().all(|d| d.len() == 64), "{exes:?}");
    assert_identical(&verify(&r.bundle));
}

#[test]
fn git_commit_is_reproduced_byte_for_byte() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("git");
    let r = record_sh(
        &w,
        "git init -q -b main . && date > f && git add f && git commit -qm m && git log --format='%H %ad' && git status --porcelain",
    );
    assert_eq!(
        r.bundle.header.exit.code,
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&r.bundle.inputs.stderr)
    );
    assert_identical(&verify(&r.bundle));
}

#[test]
fn forks_pids_and_waits_are_virtualized() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("fork");
    let r = record_sh(
        &w,
        "echo $$; sh -c 'echo $$ $PPID'; (sleep 0.01; echo sub) & (echo other) & wait; \
         python3 -c 'import os; print(os.getpid(), os.getppid())'",
    );
    assert!(r.bundle.header.processes >= 4);
    assert_identical(&verify(&r.bundle));
}

#[test]
fn urandom_and_proc_reads_are_replayed() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("urandom");
    let r = record_sh(
        &w,
        "head -c 16 /dev/urandom | od -An -tx1; cat /proc/uptime; head -c 8 /dev/urandom > r.bin",
    );
    assert!(r
        .bundle
        .streams
        .values()
        .flatten()
        .any(|e| e.nr as u64 == syscalls::READ));
    assert_identical(&verify(&r.bundle));
}

#[test]
fn tampered_clock_value_changes_the_replay() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("tamper");
    let r = record_sh(&w, "python3 -c 'import time; print(int(time.time()))'");
    let mut b = r.bundle.clone();
    let mut touched = 0;
    for e in b.streams.values_mut().flatten() {
        if e.nr as u64 == syscalls::CLOCK_GETTIME && e.ret == 0 {
            let sec = i64::from_le_bytes(e.bufs[0][..8].try_into().unwrap()) + 1_000_000;
            e.bufs[0][..8].copy_from_slice(&sec.to_le_bytes());
            touched += 1;
        }
    }
    assert!(touched > 0);
    // Re-seal so the bundle is internally consistent: the claim (stdout)
    // no longer matches what the edited log produces.
    let (b, _, _) = b.seal();
    assert_ne!(b.claim_digest(), r.bundle.claim_digest());
    let rep = verify(&b);
    assert!(!rep.identical);
    assert!(!rep.stdout_match);
}

#[test]
fn editing_the_command_is_detected() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("edit");
    let r = record_sh(&w, "python3 -c 'import os; print(os.urandom(8).hex())'");
    let mut b = r.bundle.clone();
    b.header.argv[2] =
        "python3 -c 'import os; print(os.urandom(8).hex(), os.urandom(8).hex())'".into();
    let (b, _, _) = b.seal();
    let rep = verify(&b);
    assert!(!rep.identical);
    assert!(rep.divergence.is_some() || !rep.stdout_match, "{rep:?}");
}

#[test]
fn threads_are_flagged_as_out_of_scope() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("threads");
    let r = record_sh(
        &w,
        "python3 -c 'import threading; t = threading.Thread(target=print, args=(1,)); t.start(); t.join()'",
    );
    assert!(r.bundle.header.multithreaded);
}

#[test]
fn verify_refuses_an_existing_workdir_without_replace() {
    let _g = LOCK.lock().unwrap();
    let w = workdir("exists");
    let r = record_sh(&w, "true");
    let err = session::verify(&r.bundle, Existing::Refuse, false).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_identical(&verify(&r.bundle));
}

#[test]
fn cli_record_verify_inspect_and_exit_codes() {
    let _g = LOCK.lock().unwrap();
    let bin = env!("CARGO_BIN_EXE_replay-proof");
    let w = workdir("cli");
    std::fs::write(w.join("in.txt"), "a\nb\n").unwrap();
    let envfile = w.with_extension("env");
    std::fs::write(&envfile, env(&w).join("\n")).unwrap();
    let out = w.with_extension("rpl");
    let rec = Command::new(bin)
        .args(["record", "--workdir"])
        .arg(&w)
        .arg("--out")
        .arg(&out)
        .arg("--env-file")
        .arg(&envfile)
        .args(["--", "sh", "-c", "sort -R in.txt; date +%N > stamp"])
        .output()
        .unwrap();
    assert!(
        rec.status.success(),
        "{}",
        String::from_utf8_lossy(&rec.stderr)
    );
    let v = Command::new(bin)
        .arg("verify")
        .arg(&out)
        .arg("--replace")
        .output()
        .unwrap();
    assert_eq!(
        v.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&v.stdout)
    );
    let i = Command::new(bin).arg("inspect").arg(&out).output().unwrap();
    assert!(i.status.success());
    assert!(String::from_utf8_lossy(&i.stdout).contains("events_per_syscall"));
    std::fs::write(&out, b"garbage").unwrap();
    let bad = Command::new(bin).arg("verify").arg(&out).output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&envfile);
}
