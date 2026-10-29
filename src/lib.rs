//! replay-proof: deterministic record/replay of single-threaded tool
//! executions on Linux x86_64.
//!
//! A seccomp-bpf filter sends only the nondeterministic system calls to a
//! ptrace supervisor (`SECCOMP_RET_TRACE`). While recording, the supervisor
//! saves their results; while replaying it either skips the real call and
//! injects the saved result, or lets it run and overwrites what the program
//! sees. The vDSO is hidden from every exec'd image so time calls become
//! real system calls, ASLR is disabled and `AT_RANDOM` is replayed.
//!
//! The result is a self-contained bundle (input tree, stdin, argv, env,
//! event log and the claimed stdout/stderr/exit/output tree) that a third
//! party verifies by replaying it on the same absolute path.

pub mod seccomp;
pub mod syscalls;

/// Hex-encoded SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
