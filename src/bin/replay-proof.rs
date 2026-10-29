//! Command-line front end: `record`, `verify`, `inspect`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use replay_proof::bundle::Bundle;
use replay_proof::session::{self, Existing, RecordRequest};
use replay_proof::syscalls;

const USAGE: &str = "\
replay-proof: deterministic record/replay of tool executions (Linux x86_64)

USAGE:
  replay-proof record --workdir DIR --out BUNDLE [--stdin FILE] [--env-file FILE] -- CMD [ARGS...]
  replay-proof verify BUNDLE [--replace] [--keep]
  replay-proof inspect BUNDLE

record   runs CMD in DIR with the environment of this process (or exactly the
         KEY=VALUE lines of --env-file), records its nondeterministic inputs
         and writes a bundle. Prints a JSON summary.
verify   recreates the input tree at the recorded absolute path, replays the
         log and compares stdout, stderr, exit status and the output tree.
         --replace removes an existing directory at that path first;
         --keep leaves the replayed tree in place.
         Exit status: 0 identical, 1 different, 2 error.
inspect  prints the header and the number of events per system call.
";

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("replay-proof: {msg}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("record") => record(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("inspect") => inspect(&args[1..]),
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn record(args: &[String]) -> ExitCode {
    let mut workdir = None;
    let mut out = None;
    let mut stdin = None;
    let mut env_file = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        let val = args.get(i + 1).cloned();
        match (a, val) {
            ("--workdir", Some(v)) => workdir = Some(PathBuf::from(v)),
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            ("--stdin", Some(v)) => stdin = Some(PathBuf::from(v)),
            ("--env-file", Some(v)) => env_file = Some(PathBuf::from(v)),
            _ => return fail(format!("bad argument {a}\n{USAGE}")),
        }
        i += 2;
    }
    let argv: Vec<String> = args[i..].to_vec();
    let (Some(workdir), Some(out)) = (workdir, out) else {
        return fail("record needs --workdir and --out");
    };
    if argv.is_empty() {
        return fail("record needs a command after --");
    }
    let env = match env_file {
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(s) => s
                .lines()
                .filter(|l| l.contains('='))
                .map(str::to_string)
                .collect(),
            Err(e) => return fail(format!("{}: {e}", p.display())),
        },
        None => std::env::vars().map(|(k, v)| format!("{k}={v}")).collect(),
    };
    let req = RecordRequest {
        argv,
        env,
        workdir,
        stdin,
    };
    let rec = match session::record(&req) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    if let Err(e) = std::fs::write(&out, &rec.bytes) {
        return fail(format!("{}: {e}", out.display()));
    }
    let h = &rec.bundle.header;
    let summary = serde_json::json!({
        "bundle": out,
        "claim_digest": rec.bundle.claim_digest(),
        "bundle_sha256": replay_proof::sha256_hex(&rec.bytes),
        "exit": h.exit,
        "events": h.events,
        "processes": h.processes,
        "multithreaded": h.multithreaded,
        "record_wall_ns": h.record_wall_ns,
        "sizes": rec.sizes,
    });
    println!("{summary}");
    ExitCode::SUCCESS
}

fn open(path: &str) -> Result<Bundle, ExitCode> {
    let bytes = std::fs::read(path).map_err(|e| fail(format!("{path}: {e}")))?;
    Bundle::open(&bytes)
        .map(|(b, _)| b)
        .map_err(|e| fail(format!("{path}: {e}")))
}

fn verify(args: &[String]) -> ExitCode {
    let mut path = None;
    let mut existing = Existing::Refuse;
    let mut keep = false;
    for a in args {
        match a.as_str() {
            "--replace" => existing = Existing::Replace,
            "--keep" => keep = true,
            p if path.is_none() && !p.starts_with("--") => path = Some(p.to_string()),
            _ => return fail(format!("bad argument {a}")),
        }
    }
    let Some(path) = path else {
        return fail("verify needs a bundle");
    };
    let bundle = match open(&path) {
        Ok(b) => b,
        Err(c) => return c,
    };
    match session::verify(&bundle, existing, keep) {
        Ok(rep) => {
            println!(
                "{}",
                serde_json::to_string(&rep).expect("report serializes")
            );
            if rep.identical {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => fail(e),
    }
}

fn inspect(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        return fail("inspect needs a bundle");
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return fail(format!("{path}: {e}")),
    };
    let (b, sizes) = match Bundle::open(&bytes) {
        Ok(x) => x,
        Err(e) => return fail(format!("{path}: {e}")),
    };
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for evs in b.streams.values() {
        for e in evs {
            *per.entry(syscalls::name(e.nr)).or_default() += 1;
        }
    }
    let out = serde_json::json!({
        "claim_digest": b.claim_digest(),
        "header": b.header,
        "sizes": sizes,
        "events_per_syscall": per,
        "processes": b.streams.keys().collect::<Vec<_>>(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serializes")
    );
    ExitCode::SUCCESS
}
