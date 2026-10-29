//! Classic BPF program that sends the traced system calls to the ptrace
//! supervisor and lets every other call through untouched.

use crate::syscalls::TRACED;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_TRACE: u32 = 0x7ff0_0000;
const RET_ALLOW: u32 = 0x7fff_0000;

const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build the filter: other architectures are killed (their calls would not
/// be recorded), traced numbers return `SECCOMP_RET_TRACE`, the rest
/// `SECCOMP_RET_ALLOW`.
pub fn build() -> Vec<libc::sock_filter> {
    let n = TRACED.len();
    let mut f = vec![
        stmt(LD_W_ABS, 4), // seccomp_data.arch
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, 0), // seccomp_data.nr
    ];
    for (i, &nr) in TRACED.iter().enumerate() {
        // Skip the remaining comparisons and the ALLOW to land on TRACE.
        let to_trace = (n - 1 - i) + 1;
        f.push(jump(JEQ_K, nr as u32, to_trace as u8, 0));
    }
    f.push(stmt(RET_K, RET_ALLOW));
    f.push(stmt(RET_K, RET_TRACE));
    f
}

/// Interpret the filter for one `(arch, nr)` pair. Used by the tests to
/// check the jump offsets without loading anything into the kernel.
pub fn evaluate(prog: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
    let mut acc = 0u32;
    let mut pc = 0usize;
    loop {
        let ins = prog[pc];
        match ins.code {
            LD_W_ABS => {
                acc = if ins.k == 4 { arch } else { nr };
                pc += 1;
            }
            JEQ_K => {
                pc += 1 + if acc == ins.k {
                    ins.jt as usize
                } else {
                    ins.jf as usize
                };
            }
            RET_K => return ins.k,
            c => panic!("unexpected opcode {c:#x}"),
        }
    }
}

pub const TRACE: u32 = RET_TRACE;
pub const ALLOW: u32 = RET_ALLOW;
pub const KILL_PROCESS: u32 = RET_KILL_PROCESS;
pub const ARCH_X86_64: u32 = AUDIT_ARCH_X86_64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traced_numbers_trace_and_others_pass() {
        let p = build();
        assert!(p.len() < 255);
        for nr in 0..500u32 {
            let want = if TRACED.contains(&(nr as u64)) {
                TRACE
            } else {
                ALLOW
            };
            assert_eq!(evaluate(&p, ARCH_X86_64, nr), want, "nr {nr}");
        }
    }

    #[test]
    fn foreign_arch_is_killed() {
        let p = build();
        assert_eq!(evaluate(&p, 0x4000_0003, 0), KILL_PROCESS);
    }
}
