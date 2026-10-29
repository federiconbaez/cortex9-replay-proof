//! The system calls replay-proof intercepts on x86_64, how each one is
//! replayed, and which user-memory buffers carry its result.

/// How a system call is handled during replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The real call is skipped and the recorded return value and output
    /// buffers are injected (time, randomness, ids, host information).
    Emulate,
    /// The real call runs (it changes kernel state the program relies on),
    /// then the return value and output buffers are overwritten with the
    /// recorded ones (stat family, getdents64, set_tid_address).
    Overwrite,
    /// `read`/`pread64`: recorded only when the descriptor points to a
    /// nondeterministic source (`/dev/urandom`, `/dev/random`, `/proc`,
    /// `/sys`); then handled like [`Kind::Overwrite`].
    ReadLike,
    /// `clone`/`fork`/`vfork`/`clone3`: the child pid returned to the parent
    /// is replaced with the recorded one and the pair is added to the pid map.
    Fork,
    /// `wait4`/`waitid`: forced to reap the same child as in the recording.
    Wait,
    /// `kill`/`tgkill`/`tkill`/`setpgid`: pid arguments are translated from
    /// recorded to real pids; nothing is recorded.
    PidArgs,
}

pub const READ: u64 = 0;
pub const STAT: u64 = 4;
pub const FSTAT: u64 = 5;
pub const LSTAT: u64 = 6;
pub const PREAD64: u64 = 17;
pub const GETPID: u64 = 39;
pub const CLONE: u64 = 56;
pub const FORK: u64 = 57;
pub const VFORK: u64 = 58;
pub const WAIT4: u64 = 61;
pub const KILL: u64 = 62;
pub const UNAME: u64 = 63;
pub const GETTIMEOFDAY: u64 = 96;
pub const GETRUSAGE: u64 = 98;
pub const SYSINFO: u64 = 99;
pub const TIMES: u64 = 100;
pub const GETUID: u64 = 102;
pub const GETGID: u64 = 104;
pub const GETEUID: u64 = 107;
pub const GETEGID: u64 = 108;
pub const SETPGID: u64 = 109;
pub const GETPPID: u64 = 110;
pub const GETPGRP: u64 = 111;
pub const GETRESUID: u64 = 118;
pub const GETRESGID: u64 = 120;
pub const GETPGID: u64 = 121;
pub const GETSID: u64 = 124;
pub const GETTID: u64 = 186;
pub const TKILL: u64 = 200;
pub const TIME: u64 = 201;
pub const SCHED_GETAFFINITY: u64 = 204;
pub const GETDENTS64: u64 = 217;
pub const SET_TID_ADDRESS: u64 = 218;
pub const CLOCK_GETTIME: u64 = 228;
pub const TGKILL: u64 = 234;
pub const WAITID: u64 = 247;
pub const NEWFSTATAT: u64 = 262;
pub const GETCPU: u64 = 309;
pub const GETRANDOM: u64 = 318;
pub const STATX: u64 = 332;
pub const CLONE3: u64 = 435;

/// Every system call number the seccomp filter sends to the supervisor.
pub const TRACED: &[u64] = &[
    READ,
    STAT,
    FSTAT,
    LSTAT,
    PREAD64,
    GETPID,
    CLONE,
    FORK,
    VFORK,
    WAIT4,
    KILL,
    UNAME,
    GETTIMEOFDAY,
    GETRUSAGE,
    SYSINFO,
    TIMES,
    GETUID,
    GETGID,
    GETEUID,
    GETEGID,
    SETPGID,
    GETPPID,
    GETPGRP,
    GETRESUID,
    GETRESGID,
    GETPGID,
    GETSID,
    GETTID,
    TKILL,
    TIME,
    SCHED_GETAFFINITY,
    GETDENTS64,
    SET_TID_ADDRESS,
    CLOCK_GETTIME,
    TGKILL,
    WAITID,
    NEWFSTATAT,
    GETCPU,
    GETRANDOM,
    STATX,
    CLONE3,
];

/// Pseudo system call number used for the `AT_RANDOM` bytes of an exec.
pub const EV_EXEC: u32 = 0xFFFF_0001;

pub fn kind(nr: u64) -> Option<Kind> {
    use Kind::*;
    Some(match nr {
        READ | PREAD64 => ReadLike,
        STAT | FSTAT | LSTAT | NEWFSTATAT | STATX | GETDENTS64 | SET_TID_ADDRESS => Overwrite,
        CLONE | FORK | VFORK | CLONE3 => Fork,
        WAIT4 | WAITID => Wait,
        KILL | TGKILL | TKILL | SETPGID => PidArgs,
        GETPID | GETPPID | GETTID | GETPGRP | GETPGID | GETSID | UNAME | GETTIMEOFDAY
        | GETRUSAGE | SYSINFO | TIMES | GETUID | GETGID | GETEUID | GETEGID | GETRESUID
        | GETRESGID | TIME | SCHED_GETAFFINITY | CLOCK_GETTIME | GETCPU | GETRANDOM => Emulate,
        _ => return None,
    })
}

pub fn name(nr: u32) -> &'static str {
    if nr == EV_EXEC {
        return "exec(AT_RANDOM)";
    }
    match nr as u64 {
        READ => "read",
        STAT => "stat",
        FSTAT => "fstat",
        LSTAT => "lstat",
        PREAD64 => "pread64",
        GETPID => "getpid",
        CLONE => "clone",
        FORK => "fork",
        VFORK => "vfork",
        WAIT4 => "wait4",
        KILL => "kill",
        UNAME => "uname",
        GETTIMEOFDAY => "gettimeofday",
        GETRUSAGE => "getrusage",
        SYSINFO => "sysinfo",
        TIMES => "times",
        GETUID => "getuid",
        GETGID => "getgid",
        GETEUID => "geteuid",
        GETEGID => "getegid",
        SETPGID => "setpgid",
        GETPPID => "getppid",
        GETPGRP => "getpgrp",
        GETRESUID => "getresuid",
        GETRESGID => "getresgid",
        GETPGID => "getpgid",
        GETSID => "getsid",
        GETTID => "gettid",
        TKILL => "tkill",
        TIME => "time",
        SCHED_GETAFFINITY => "sched_getaffinity",
        GETDENTS64 => "getdents64",
        SET_TID_ADDRESS => "set_tid_address",
        CLOCK_GETTIME => "clock_gettime",
        TGKILL => "tgkill",
        WAITID => "waitid",
        NEWFSTATAT => "newfstatat",
        GETCPU => "getcpu",
        GETRANDOM => "getrandom",
        STATX => "statx",
        CLONE3 => "clone3",
        _ => "?",
    }
}

/// True for a raw return value in the kernel's error range.
pub fn is_err(ret: i64) -> bool {
    (-4095..0).contains(&ret)
}

/// Internal restart codes (`ERESTARTSYS` .. `ERESTART_RESTARTBLOCK`): the
/// kernel restarts the call, so it is not an observable result.
pub fn is_restart(ret: i64) -> bool {
    (-516..=-512).contains(&ret)
}

const STAT_SIZE: usize = 144;
const STATX_SIZE: usize = 256;
const RUSAGE_SIZE: usize = 144;
const UTSNAME_SIZE: usize = 390;
const SYSINFO_SIZE: usize = 112;
const SIGINFO_SIZE: usize = 128;

/// User-memory output buffers `(address, length)` written by a call with
/// these arguments and this return value.
pub fn outputs(nr: u64, a: &[u64; 6], ret: i64) -> Vec<(u64, usize)> {
    let mut v = Vec::new();
    let ok = !is_err(ret);
    let mut push = |addr: u64, len: usize| {
        if addr != 0 && len > 0 {
            v.push((addr, len));
        }
    };
    match nr {
        READ | PREAD64 | GETDENTS64 if ret > 0 => push(a[1], ret as usize),
        GETRANDOM if ret > 0 => push(a[0], ret as usize),
        SCHED_GETAFFINITY if ret > 0 => push(a[2], ret as usize),
        STAT | FSTAT | LSTAT if ok => push(a[1], STAT_SIZE),
        NEWFSTATAT if ok => push(a[2], STAT_SIZE),
        STATX if ok => push(a[4], STATX_SIZE),
        CLOCK_GETTIME if ok => push(a[1], 16),
        GETTIMEOFDAY if ok => {
            push(a[0], 16);
            push(a[1], 8);
        }
        TIME if ok => push(a[0], 8),
        UNAME if ok => push(a[0], UTSNAME_SIZE),
        SYSINFO if ok => push(a[0], SYSINFO_SIZE),
        GETRUSAGE if ok => push(a[1], RUSAGE_SIZE),
        TIMES if ok => push(a[0], 32),
        GETCPU if ok => {
            push(a[0], 4);
            push(a[1], 4);
        }
        GETRESUID | GETRESGID if ok => {
            push(a[0], 4);
            push(a[1], 4);
            push(a[2], 4);
        }
        WAIT4 if ret > 0 => {
            push(a[1], 4);
            push(a[3], RUSAGE_SIZE);
        }
        WAITID if ok => {
            push(a[2], SIGINFO_SIZE);
            push(a[4], RUSAGE_SIZE);
        }
        _ => {}
    }
    v
}

/// Whether a descriptor target (as shown by `/proc/<pid>/fd/<n>`) is a
/// nondeterministic source whose reads must be recorded.
pub fn nondeterministic_target(target: &str) -> bool {
    target.starts_with("/dev/urandom")
        || target.starts_with("/dev/random")
        || target.starts_with("/proc/")
        || target.starts_with("/sys/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_traced_call_has_a_kind_and_a_name() {
        for &nr in TRACED {
            assert!(kind(nr).is_some(), "nr {nr}");
            assert_ne!(name(nr as u32), "?", "nr {nr}");
        }
        assert_eq!(TRACED.len(), 41);
    }

    #[test]
    fn outputs_follow_return_value() {
        let a = [10, 20, 30, 40, 50, 60];
        assert_eq!(outputs(READ, &a, 7), vec![(20, 7)]);
        assert!(outputs(READ, &a, 0).is_empty());
        assert!(outputs(READ, &a, -11).is_empty());
        assert_eq!(outputs(NEWFSTATAT, &a, 0), vec![(30, 144)]);
        assert!(outputs(NEWFSTATAT, &a, -2).is_empty());
        assert_eq!(outputs(STATX, &a, 0), vec![(50, 256)]);
        assert_eq!(outputs(GETRANDOM, &a, 16), vec![(10, 16)]);
        assert_eq!(outputs(WAIT4, &a, 1234), vec![(20, 4), (40, 144)]);
        let null = [0, 0, 0, 0, 0, 0];
        assert!(outputs(GETTIMEOFDAY, &null, 0).is_empty());
        assert!(outputs(TIME, &null, 1_700_000_000).is_empty());
    }

    #[test]
    fn error_and_restart_ranges() {
        assert!(is_err(-1));
        assert!(is_err(-4095));
        assert!(!is_err(-4096));
        assert!(!is_err(0));
        assert!(is_restart(-512));
        assert!(is_restart(-516));
        assert!(!is_restart(-4));
    }

    #[test]
    fn nondeterministic_targets() {
        assert!(nondeterministic_target("/dev/urandom"));
        assert!(nondeterministic_target("/dev/random"));
        assert!(nondeterministic_target("/proc/123/stat"));
        assert!(nondeterministic_target("/sys/devices/system/cpu/online"));
        assert!(!nondeterministic_target("/etc/passwd"));
        assert!(!nondeterministic_target("pipe:[1234]"));
    }
}
