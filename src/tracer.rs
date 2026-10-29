//! The ptrace supervisor. One loop serves both modes: in record mode it
//! saves the result of every traced call; in replay mode it feeds the
//! recorded results back and reports the first divergence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::bundle::{Event, ExitInfo, Streams};
use crate::syscalls::{self as sc, Kind};

/// What to run and where its standard streams go.
pub struct Spec {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: PathBuf,
    pub stdin: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

pub enum Mode<'a> {
    Record,
    Replay { streams: &'a Streams, root_pid: i32 },
}

/// First point where the replayed program asked for something the log
/// does not have.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Divergence {
    pub process: String,
    pub index: usize,
    pub expected: String,
    pub got: String,
}

#[derive(Debug)]
pub struct Outcome {
    pub exit: ExitInfo,
    pub streams: Streams,
    pub root_pid: i32,
    pub processes: usize,
    pub multithreaded: bool,
    pub wall_ns: u64,
    pub divergence: Option<Divergence>,
    /// Processes that exited with recorded events left over (replay only).
    pub unconsumed: Vec<(String, usize)>,
    /// Path of every executable image the run exec'd.
    pub executables: BTreeSet<String>,
}

struct Pending {
    nr: u64,
    args: [u64; 6],
    ev: Option<Event>,
}

struct Proc {
    key: String,
    cursor: usize,
    forks: usize,
    pending: Option<Pending>,
    started: bool,
    /// (address, recorded tid) to write into a new child's memory where
    /// `CLONE_CHILD_SETTID` made the kernel store its real tid.
    ctid_patch: Option<(u64, i32)>,
    /// Recorded pid of the child being created by the pending fork.
    child_rec_pid: Option<i64>,
}

const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const WNOHANG: u64 = 1;
const P_PID: u64 = 1;
const AT_IGNORE: u64 = 1;
const AT_RANDOM: u64 = 25;
const AT_SYSINFO_EHDR: u64 = 33;
const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0004_0000;

fn errno() -> io::Error {
    io::Error::last_os_error()
}

fn ptrace(req: libc::c_uint, pid: i32, addr: u64, data: u64) -> io::Result<i64> {
    // SAFETY: plain ptrace request on a traced child; pointers passed as
    // integers are only dereferenced by the kernel.
    let r = unsafe {
        libc::ptrace(
            req,
            pid,
            addr as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if r == -1 {
        let e = errno();
        if e.raw_os_error() != Some(0) {
            return Err(e);
        }
    }
    Ok(r)
}

fn getregs(pid: i32) -> io::Result<libc::user_regs_struct> {
    // SAFETY: user_regs_struct is plain old data.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs as *mut _ as u64)?;
    Ok(regs)
}

fn setregs(pid: i32, regs: &libc::user_regs_struct) -> io::Result<()> {
    ptrace(libc::PTRACE_SETREGS, pid, 0, regs as *const _ as u64)?;
    Ok(())
}

fn args_of(r: &libc::user_regs_struct) -> [u64; 6] {
    [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]
}

fn set_arg(r: &mut libc::user_regs_struct, i: usize, v: u64) {
    match i {
        0 => r.rdi = v,
        1 => r.rsi = v,
        2 => r.rdx = v,
        3 => r.r10 = v,
        4 => r.r8 = v,
        _ => r.r9 = v,
    }
}

/// Read tracee memory (process_vm_readv, falling back to PEEKDATA).
pub fn read_mem(pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if len == 0 {
        return Ok(buf);
    }
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: local iovec points to our own buffer of `len` bytes.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n == len as isize {
        return Ok(buf);
    }
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let w = ptrace(libc::PTRACE_PEEKDATA, pid, addr + 8 * i as u64, 0)?;
        chunk.copy_from_slice(&w.to_le_bytes()[..chunk.len()]);
    }
    Ok(buf)
}

/// Write tracee memory (process_vm_writev, falling back to POKEDATA, which
/// also works on pages the tracee mapped read-only).
pub fn write_mem(pid: i32, addr: u64, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: local iovec points to `data`, which the kernel only reads.
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if n == data.len() as isize {
        return Ok(());
    }
    let mut off = 0usize;
    while off < data.len() {
        let a = addr + off as u64;
        let take = (data.len() - off).min(8);
        let mut word = if take < 8 {
            ptrace(libc::PTRACE_PEEKDATA, pid, a, 0)?.to_le_bytes()
        } else {
            [0u8; 8]
        };
        word[..take].copy_from_slice(&data[off..off + take]);
        ptrace(libc::PTRACE_POKEDATA, pid, a, u64::from_le_bytes(word))?;
        off += take;
    }
    Ok(())
}

fn read_word(pid: i32, addr: u64) -> io::Result<u64> {
    let b = read_mem(pid, addr, 8)?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

/// After an exec: hide the vDSO (`AT_SYSINFO_EHDR` becomes `AT_IGNORE`, so
/// libc falls back to real time system calls) and return the address of the
/// 16 `AT_RANDOM` bytes.
fn patch_auxv(pid: i32) -> io::Result<Option<u64>> {
    let regs = getregs(pid)?;
    let sp = regs.rsp;
    let argc = read_word(pid, sp)?;
    let mut p = sp + 8 * (argc + 2);
    while read_word(pid, p)? != 0 {
        p += 8;
    }
    p += 8;
    let mut random = None;
    for _ in 0..256 {
        let t = read_word(pid, p)?;
        if t == 0 {
            break;
        }
        if t == AT_SYSINFO_EHDR {
            write_mem(pid, p, &AT_IGNORE.to_le_bytes())?;
        } else if t == AT_RANDOM {
            random = Some(read_word(pid, p + 8)?);
        }
        p += 16;
    }
    Ok(random)
}

fn fd_target(pid: i32, fd: u64) -> String {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn resolve(prog: &str, env: &[String]) -> io::Result<PathBuf> {
    if prog.contains('/') {
        return Ok(PathBuf::from(prog));
    }
    let path = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or("/usr/local/bin:/usr/bin:/bin");
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let cand = Path::new(dir).join(prog);
        if let Ok(md) = std::fs::metadata(&cand) {
            use std::os::unix::fs::PermissionsExt;
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return Ok(cand);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{prog}: not found in PATH"),
    ))
}

fn cstr(s: &[u8]) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in argument"))
}

/// Fork the tool with ASLR off, stopped for the tracer, and with the
/// seccomp filter installed right before `execve`.
fn spawn(spec: &Spec) -> io::Result<i32> {
    let exe = cstr(resolve(&spec.argv[0], &spec.env)?.as_os_str().as_bytes())?;
    let argv: Vec<CString> = spec
        .argv
        .iter()
        .map(|a| cstr(a.as_bytes()))
        .collect::<io::Result<_>>()?;
    let envv: Vec<CString> = spec
        .env
        .iter()
        .map(|a| cstr(a.as_bytes()))
        .collect::<io::Result<_>>()?;
    let mut argp: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argp.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = envv.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());
    let cwd = cstr(spec.cwd.as_os_str().as_bytes())?;
    let fin = std::fs::File::open(&spec.stdin)?;
    let fout = std::fs::File::create(&spec.stdout)?;
    let ferr = std::fs::File::create(&spec.stderr)?;
    let filter = crate::seccomp::build();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: after fork the child only calls async-signal-safe functions
    // on memory prepared before the fork, then execs or _exits.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(errno());
        }
        if pid == 0 {
            if libc::dup2(fin.as_raw_fd(), 0) < 0
                || libc::dup2(fout.as_raw_fd(), 1) < 0
                || libc::dup2(ferr.as_raw_fd(), 2) < 0
                || libc::chdir(cwd.as_ptr()) != 0
            {
                libc::_exit(126);
            }
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            let pers = libc::personality(0xffff_ffff);
            libc::personality(pers as libc::c_ulong | ADDR_NO_RANDOMIZE);
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                libc::_exit(125);
            }
            libc::kill(libc::getpid(), libc::SIGSTOP);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const libc::sock_fprog,
                ) != 0
            {
                libc::_exit(124);
            }
            libc::execve(exe.as_ptr(), argp.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
        Ok(pid)
    }
}

fn wait_any() -> io::Result<(i32, i32)> {
    let mut status = 0;
    // SAFETY: plain waitpid on our own children.
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
    if pid < 0 {
        return Err(errno());
    }
    Ok((pid, status))
}

struct Tracer<'a> {
    replay: Option<&'a Streams>,
    procs: HashMap<i32, Proc>,
    /// Children that stopped before their parent's fork event named them.
    early: HashSet<i32>,
    /// Recorded pid -> real pid (identity while recording).
    pidmap: HashMap<i64, i64>,
    out: Streams,
    multithreaded: bool,
    root: i32,
    exit: ExitInfo,
    divergence: Option<Divergence>,
    unconsumed: Vec<(String, usize)>,
    processes: usize,
    executables: BTreeSet<String>,
}

impl<'a> Tracer<'a> {
    fn resume(&self, pid: i32, sig: i32) {
        let req = match self.procs.get(&pid) {
            Some(p) if p.pending.is_some() => libc::PTRACE_SYSCALL,
            _ => libc::PTRACE_CONT,
        };
        let _ = ptrace(req, pid, 0, sig as u64);
    }

    fn register(&mut self, pid: i32, key: String) {
        if self.replay.is_none() {
            self.out.entry(key.clone()).or_default();
        }
        self.processes += 1;
        self.procs.insert(
            pid,
            Proc {
                key,
                cursor: 0,
                forks: 0,
                pending: None,
                started: false,
                ctid_patch: None,
                child_rec_pid: None,
            },
        );
    }

    fn map_pid(&self, v: u64) -> u64 {
        let x = v as i64 as i32 as i64;
        if x > 0 {
            self.pidmap.get(&x).map(|r| *r as u64).unwrap_or(v)
        } else if x < -1 {
            self.pidmap.get(&-x).map(|r| (-*r) as u64).unwrap_or(v)
        } else {
            v
        }
    }

    fn diverge(&mut self, pid: i32, expected: String, got: String) {
        let p = &self.procs[&pid];
        self.divergence = Some(Divergence {
            process: p.key.clone(),
            index: p.cursor,
            expected,
            got,
        });
    }

    /// Next recorded event of this process; it must be for `nr`.
    fn take(&mut self, pid: i32, nr: u32) -> Option<Event> {
        let streams = self.replay?;
        let p = self.procs.get(&pid)?;
        let ev = streams.get(&p.key).and_then(|v| v.get(p.cursor)).cloned();
        match ev {
            Some(ev) if ev.nr == nr => {
                self.procs.get_mut(&pid).unwrap().cursor += 1;
                Some(ev)
            }
            Some(ev) => {
                self.diverge(pid, sc::name(ev.nr).into(), sc::name(nr).into());
                None
            }
            None => {
                self.diverge(pid, "end of log".into(), sc::name(nr).into());
                None
            }
        }
    }

    fn on_seccomp(&mut self, pid: i32) -> io::Result<()> {
        let mut regs = getregs(pid)?;
        let nr = regs.orig_rax;
        let args = args_of(&regs);
        let Some(kind) = sc::kind(nr) else {
            self.resume(pid, 0);
            return Ok(());
        };
        if kind == Kind::Fork {
            let flags = if nr == sc::CLONE3 {
                read_word(pid, args[0]).unwrap_or(0)
            } else if nr == sc::CLONE {
                args[0]
            } else {
                0
            };
            if flags & CLONE_THREAD != 0 {
                self.multithreaded = true;
            }
        }
        if kind == Kind::ReadLike && !sc::nondeterministic_target(&fd_target(pid, args[0])) {
            self.resume(pid, 0);
            return Ok(());
        }
        if self.replay.is_none() {
            if kind != Kind::PidArgs {
                self.procs.get_mut(&pid).unwrap().pending = Some(Pending { nr, args, ev: None });
            }
            self.resume(pid, 0);
            return Ok(());
        }
        // Replay.
        if kind == Kind::PidArgs {
            let idx: &[usize] = match nr {
                sc::KILL | sc::TKILL => &[0],
                _ => &[0, 1],
            };
            for &i in idx {
                let v = self.map_pid(args[i]);
                set_arg(&mut regs, i, v);
            }
            setregs(pid, &regs)?;
            self.resume(pid, 0);
            return Ok(());
        }
        let Some(ev) = self.take(pid, nr as u32) else {
            return Ok(());
        };
        let mut skip = kind == Kind::Emulate;
        match kind {
            Kind::Wait => {
                let child = if nr == sc::WAIT4 {
                    ev.ret
                } else if ev.ret == 0 && ev.bufs.first().map(|b| b.len() >= 20) == Some(true) {
                    i32::from_le_bytes(ev.bufs[0][16..20].try_into().unwrap()) as i64
                } else {
                    0
                };
                if child > 0 {
                    let Some(&real) = self.pidmap.get(&child) else {
                        self.diverge(pid, format!("child {child}"), "unknown child".into());
                        return Ok(());
                    };
                    if nr == sc::WAIT4 {
                        set_arg(&mut regs, 0, real as u64);
                        set_arg(&mut regs, 2, args[2] & !WNOHANG);
                    } else {
                        set_arg(&mut regs, 0, P_PID);
                        set_arg(&mut regs, 1, real as u64);
                        set_arg(&mut regs, 3, args[3] & !WNOHANG);
                    }
                } else {
                    skip = true;
                }
            }
            Kind::Fork => {
                let p = self.procs.get_mut(&pid).unwrap();
                p.child_rec_pid = Some(ev.ret);
            }
            _ => {}
        }
        if skip {
            regs.orig_rax = u64::MAX;
        }
        setregs(pid, &regs)?;
        self.procs.get_mut(&pid).unwrap().pending = Some(Pending {
            nr,
            args,
            ev: Some(ev),
        });
        self.resume(pid, 0);
        Ok(())
    }

    fn on_syscall_exit(&mut self, pid: i32) -> io::Result<()> {
        let Some(pend) = self.procs.get_mut(&pid).and_then(|p| p.pending.take()) else {
            self.resume(pid, 0);
            return Ok(());
        };
        let mut regs = getregs(pid)?;
        let ret = regs.rax as i64;
        match pend.ev {
            None => {
                // Record.
                if !sc::is_restart(ret) {
                    let mut bufs = Vec::new();
                    for (addr, len) in sc::outputs(pend.nr, &pend.args, ret) {
                        bufs.push(read_mem(pid, addr, len)?);
                    }
                    let key = self.procs[&pid].key.clone();
                    self.out.entry(key).or_default().push(Event {
                        nr: pend.nr as u32,
                        ret,
                        bufs,
                    });
                }
            }
            Some(ev) => {
                if sc::is_restart(ret) {
                    // Interrupted by a signal: the kernel will restart the
                    // call, which will ask for this event again.
                    self.procs.get_mut(&pid).unwrap().cursor -= 1;
                } else {
                    if sc::kind(pend.nr) == Some(Kind::Fork) && ret > 0 && ev.ret > 0 {
                        self.pidmap.insert(ev.ret, ret);
                    }
                    let outs = sc::outputs(pend.nr, &pend.args, ev.ret);
                    if outs.len() != ev.bufs.len() {
                        self.diverge(
                            pid,
                            format!("{} buffers", ev.bufs.len()),
                            format!("{} buffers", outs.len()),
                        );
                        return Ok(());
                    }
                    for ((addr, _), data) in outs.iter().zip(ev.bufs.iter()) {
                        write_mem(pid, *addr, data)?;
                    }
                    regs.rax = ev.ret as u64;
                    setregs(pid, &regs)?;
                }
            }
        }
        self.resume(pid, 0);
        Ok(())
    }

    fn on_new_child(&mut self, parent: i32) -> io::Result<()> {
        let mut msg: libc::c_ulong = 0;
        ptrace(
            libc::PTRACE_GETEVENTMSG,
            parent,
            0,
            &mut msg as *mut _ as u64,
        )?;
        let child = msg as i32;
        let (key, rec, regs) = {
            let p = self.procs.get_mut(&parent).unwrap();
            let key = format!("{}.{}", p.key, p.forks);
            p.forks += 1;
            (key, p.child_rec_pid.take(), getregs(parent)?)
        };
        self.register(child, key);
        if self.replay.is_some() {
            if let Some(rec) = rec.filter(|r| *r > 0) {
                self.pidmap.insert(rec, child as i64);
                if regs.orig_rax == sc::CLONE && regs.rdi & CLONE_CHILD_SETTID != 0 {
                    self.procs.get_mut(&child).unwrap().ctid_patch = Some((regs.r10, rec as i32));
                }
            }
        } else {
            self.pidmap.insert(child as i64, child as i64);
        }
        if self.early.remove(&child) {
            self.start_child(child)?;
        }
        self.resume(parent, 0);
        Ok(())
    }

    fn start_child(&mut self, pid: i32) -> io::Result<()> {
        let p = self.procs.get_mut(&pid).unwrap();
        p.started = true;
        if let Some((addr, tid)) = p.ctid_patch.take() {
            write_mem(pid, addr, &tid.to_le_bytes())?;
        }
        self.resume(pid, 0);
        Ok(())
    }

    fn on_exec(&mut self, pid: i32) -> io::Result<()> {
        if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            self.executables.insert(exe.to_string_lossy().into_owned());
        }
        let random = patch_auxv(pid)?;
        if let Some(addr) = random {
            if self.replay.is_none() {
                let bytes = read_mem(pid, addr, 16)?;
                let key = self.procs[&pid].key.clone();
                self.out.entry(key).or_default().push(Event {
                    nr: sc::EV_EXEC,
                    ret: 0,
                    bufs: vec![bytes],
                });
            } else {
                let Some(ev) = self.take(pid, sc::EV_EXEC) else {
                    return Ok(());
                };
                if let Some(b) = ev.bufs.first() {
                    write_mem(pid, addr, b)?;
                }
            }
        }
        self.resume(pid, 0);
        Ok(())
    }

    fn on_gone(&mut self, pid: i32, status: i32) {
        if let Some(p) = self.procs.remove(&pid) {
            if let Some(streams) = self.replay {
                let len = streams.get(&p.key).map(|v| v.len()).unwrap_or(0);
                if p.cursor < len {
                    self.unconsumed.push((p.key.clone(), len - p.cursor));
                }
            }
        }
        if pid == self.root {
            self.exit = if libc::WIFEXITED(status) {
                ExitInfo {
                    code: Some(libc::WEXITSTATUS(status)),
                    signal: None,
                }
            } else {
                ExitInfo {
                    code: None,
                    signal: Some(libc::WTERMSIG(status)),
                }
            };
        }
    }

    fn kill_all(&mut self) {
        for &pid in self.procs.keys() {
            // SAFETY: signalling our own traced children.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        while wait_any().is_ok() {}
    }

    fn run(&mut self) -> io::Result<()> {
        loop {
            if self.divergence.is_some() {
                self.kill_all();
                return Ok(());
            }
            let (pid, status) = match wait_any() {
                Ok(x) => x,
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            };
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.on_gone(pid, status);
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let event = (status >> 16) & 0xffff;
            if !self.procs.contains_key(&pid) {
                // A new child stopped before its parent's fork event.
                self.early.insert(pid);
                continue;
            }
            let res = if sig == (libc::SIGTRAP | 0x80) {
                self.on_syscall_exit(pid)
            } else if sig == libc::SIGTRAP && event != 0 {
                match event {
                    libc::PTRACE_EVENT_SECCOMP => self.on_seccomp(pid),
                    libc::PTRACE_EVENT_FORK
                    | libc::PTRACE_EVENT_VFORK
                    | libc::PTRACE_EVENT_CLONE => self.on_new_child(pid),
                    libc::PTRACE_EVENT_EXEC => self.on_exec(pid),
                    _ => {
                        self.resume(pid, 0);
                        Ok(())
                    }
                }
            } else if sig == libc::SIGSTOP && !self.procs[&pid].started {
                self.start_child(pid)
            } else {
                self.resume(pid, sig);
                Ok(())
            };
            if let Err(e) = res {
                // ESRCH: the tracee died between stops (e.g. SIGKILL); its
                // exit status arrives on a later wait.
                if e.raw_os_error() != Some(libc::ESRCH) {
                    self.kill_all();
                    return Err(e);
                }
            }
        }
    }
}

/// Run `spec` under the supervisor in the given mode.
pub fn run(spec: &Spec, mode: Mode<'_>) -> io::Result<Outcome> {
    let t0 = Instant::now();
    let pid = spawn(spec)?;
    let mut status = 0;
    // SAFETY: waiting for the child we just forked.
    if unsafe { libc::waitpid(pid, &mut status, libc::__WALL) } != pid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGSTOP
    {
        return Err(io::Error::other(format!(
            "child did not stop for the tracer (status {status:#x})"
        )));
    }
    let opts = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACESECCOMP
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_EXITKILL;
    ptrace(libc::PTRACE_SETOPTIONS, pid, 0, opts as u64)?;
    let (replay, root_pid) = match mode {
        Mode::Record => (None, pid),
        Mode::Replay { streams, root_pid } => (Some(streams), root_pid),
    };
    let mut t = Tracer {
        replay,
        procs: HashMap::new(),
        early: HashSet::new(),
        pidmap: HashMap::new(),
        out: Streams::new(),
        multithreaded: false,
        root: pid,
        exit: ExitInfo::default(),
        divergence: None,
        unconsumed: Vec::new(),
        processes: 0,
        executables: BTreeSet::new(),
    };
    t.pidmap.insert(root_pid as i64, pid as i64);
    t.register(pid, "0".into());
    t.procs.get_mut(&pid).unwrap().started = true;
    ptrace(libc::PTRACE_CONT, pid, 0, 0)?;
    t.run()?;
    Ok(Outcome {
        exit: t.exit,
        streams: t.out,
        root_pid,
        processes: t.processes,
        multithreaded: t.multithreaded,
        wall_ns: t0.elapsed().as_nanos() as u64,
        divergence: t.divergence,
        unconsumed: t.unconsumed,
        executables: t.executables,
    })
}
