#!/usr/bin/env python3
"""Overhead and log size on longer workloads (the corpus runs last a few
milliseconds, so process start-up dominates there).

Each workload runs N times natively, N times under `replay-proof record`
and N times under `replay-proof verify` in a fresh copy of its fixture at
the same path; medians are reported. If a working `rr` or `hermit` is on
PATH, `rr record` / `hermit run` are timed the same way; otherwise the
reason is printed.
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

WORKLOADS = [
    ("time-syscalls-200k", "python3 -c 'import time\nfor _ in range(200000): time.time()'"),
    ("cpu-bound-python", "python3 -c 'print(sum(i * i for i in range(3000000)))'"),
    ("git-log-p-300", "git log -p --stat > log.txt && wc -l log.txt"),
    ("jq-5mb", "jq -c '[.[] | select(.n % 3 == 0) | .name] | length' big.json"),
    ("tar-gz-500-files", "tar czf files.tgz many && sha256sum files.tgz"),
]


def env_for(w):
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": os.path.join(w, "home"),
            "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1"}


def build_fixture(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(os.path.join(path, "home"))
    os.makedirs(os.path.join(path, "many"))
    with open(os.path.join(path, "home", ".gitconfig"), "w") as f:
        f.write("[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n"
                "[init]\n\tdefaultBranch = main\n")
    env = env_for(path)
    subprocess.run(["sh", "-c",
                    "git init -q . && printf 'home/\\nmany/\\nbig.json\\n' >> .git/info/exclude && "
                    "for i in $(seq 1 300); do echo \"line $i\" >> f.txt; "
                    "git add f.txt; git commit -qm \"c$i\"; done"],
                   cwd=path, env=env, check=True)
    json.dump([{"name": f"item-{i}", "n": i, "tags": ["a", "b", "c"]} for i in range(90000)],
              open(os.path.join(path, "big.json"), "w"))
    for i in range(500):
        with open(os.path.join(path, "many", f"f{i:03d}.txt"), "w") as f:
            f.write(("data %d\n" % i) * 50)


def fresh(fx, w):
    if os.path.lexists(w):
        shutil.rmtree(w)
    shutil.copytree(fx, w, symlinks=True)


def probe(cmd):
    if shutil.which(cmd[0]) is None:
        return f"{cmd[0]} is not installed on this host"
    tmp = "/tmp/replay-proof-probe"
    shutil.rmtree(tmp, ignore_errors=True)
    p = subprocess.run(cmd, capture_output=True, text=True, cwd="/tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    if p.returncode != 0:
        lines = (p.stderr or p.stdout).strip().splitlines() or ["?"]
        return f"{cmd[0]} does not run here: {lines[-1][:200]}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/replay-proof")
    ap.add_argument("--base", default="/tmp/replay-proof-overhead")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default="work/overhead")
    a = ap.parse_args()
    rp = os.path.abspath(a.bin)
    os.makedirs(a.out, exist_ok=True)
    fx = os.path.join(a.base, "fixture")
    w = os.path.join(a.base, "w")
    build_fixture(fx)
    env = env_for(w)
    envfile = os.path.join(a.base, "env")
    with open(envfile, "w") as f:
        f.write("".join(f"{k}={v}\n" for k, v in env.items()))
    rr_why = probe(["rr", "record", "-n", "-o", "/tmp/replay-proof-probe", "true"])
    hermit_why = probe(["hermit", "run", "--", "/bin/true"])
    rows = []
    for name, cmd in WORKLOADS:
        nat, rec, rep, rrs, hms, logs, ident = [], [], [], [], [], [], []
        for _ in range(a.runs):
            fresh(fx, w)
            t0 = time.perf_counter()
            subprocess.run(["sh", "-c", cmd], cwd=w, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, check=True)
            nat.append(time.perf_counter() - t0)
            fresh(fx, w)
            b = os.path.join(a.base, "b.rpl")
            p = subprocess.run([rp, "record", "--workdir", w, "--out", b, "--env-file", envfile,
                                "--", "sh", "-c", cmd], capture_output=True, text=True, check=True)
            s = json.loads(p.stdout)
            rec.append(s["record_wall_ns"] / 1e9)
            logs.append(s["sizes"]["events"])
            v = subprocess.run([rp, "verify", b, "--replace"], capture_output=True, text=True)
            r = json.loads(v.stdout)
            ident.append(r["identical"])
            rep.append(r["replay_wall_ns"] / 1e9)
            if rr_why is None:
                fresh(fx, w)
                tr = os.path.join(a.base, "rr-trace")
                shutil.rmtree(tr, ignore_errors=True)
                t0 = time.perf_counter()
                q = subprocess.run(["rr", "record", "-n", "-o", tr, "sh", "-c", cmd], cwd=w,
                                   env=env, stdin=subprocess.DEVNULL, capture_output=True)
                if q.returncode == 0:
                    rrs.append(time.perf_counter() - t0)
                else:
                    print(f"rr record failed on {name}: {q.stderr[-200:]!r}", flush=True)
            if hermit_why is None:
                fresh(fx, w)
                t0 = time.perf_counter()
                q = subprocess.run(["hermit", "run", "--", "/bin/sh", "-c", cmd], cwd=w,
                                   env=env, stdin=subprocess.DEVNULL, capture_output=True)
                if q.returncode == 0:
                    hms.append(time.perf_counter() - t0)
                else:
                    print(f"hermit run failed on {name}: {q.stderr[-200:]!r}", flush=True)
        med = statistics.median
        row = {"workload": name, "cmd": cmd, "native_s": med(nat), "record_s": med(rec),
               "replay_s": med(rep), "record_x": med(rec) / med(nat), "replay_x": med(rep) / med(nat),
               "event_log_bytes": med(logs), "log_bytes_per_s": med(logs) / med(rec),
               "identical": f"{sum(ident)}/{len(ident)}"}
        if rrs:
            row["rr_record_x"] = med(rrs) / med(nat)
        if hms:
            row["hermit_run_x"] = med(hms) / med(nat)
        rows.append(row)
        print(json.dumps(row), flush=True)
    if os.path.lexists(w):
        shutil.rmtree(w)
    res = {"runs": a.runs, "rr": rr_why or "ok", "hermit": hermit_why or "ok", "rows": rows}
    json.dump(res, open(os.path.join(a.out, "overhead.json"), "w"), indent=1)
    lines = [f"rr: {res['rr']}", f"hermit: {res['hermit']}",
             "| workload | native | record | replay | record x | replay x | log B/s | identical |"
             + (" rr x |" if rr_why is None else "") + (" hermit x |" if hermit_why is None else ""),
             "|---|---|---|---|---|---|---|---|" + ("---|" if rr_why is None else "")
             + ("---|" if hermit_why is None else "")]
    for r in rows:
        line = (f"| {r['workload']} | {r['native_s']*1e3:.0f} ms | {r['record_s']*1e3:.0f} ms | "
                f"{r['replay_s']*1e3:.0f} ms | {r['record_x']:.2f} | {r['replay_x']:.2f} | "
                f"{r['log_bytes_per_s']:.0f} | {r['identical']} |")
        if "rr_record_x" in r:
            line += f" {r['rr_record_x']:.2f} |"
        if "hermit_run_x" in r:
            line += f" {r['hermit_run_x']:.2f} |"
        lines.append(line)
    md = "\n".join(lines) + "\n"
    open(os.path.join(a.out, "overhead.md"), "w").write(md)
    print(md)
    return 0 if all(r["identical"].split("/")[0] == r["identical"].split("/")[1] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
