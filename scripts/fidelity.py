#!/usr/bin/env python3
"""Fidelity, overhead and log-size measurement over the 100-run corpus.

For every case in scripts/corpus.py, in a fresh copy of its fixture at the
same absolute path:
  native x2  plain `sh -c CMD` twice (control: does naive re-execution
             reproduce the output?), timed;
  record     `replay-proof record`, timed by the recorder itself;
  verify     `replay-proof verify` (replay + compare stdout, stderr,
             exit status and output tree);
  rr         `rr record` of the same command, only if rr is installed and
             works on this host (otherwise the reason is reported).

Writes OUT/fidelity.json and OUT/fidelity.md. Exits 1 if fewer than
--min-identical cases replay identically.
"""
import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import CASES  # noqa: E402

GITCONFIG = """[user]
\tname = Fixture
\temail = fixture@example.invalid
[init]
\tdefaultBranch = main
[advice]
\tdetachedHead = false
"""


def env_for(w):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.path.join(w, "home"),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def sh(cmd, cwd, env):
    subprocess.run(["sh", "-c", cmd], cwd=cwd, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build_fixtures(base):
    fx = os.path.join(base, "fixtures")
    if os.path.exists(fx):
        shutil.rmtree(fx)
    for name in ("empty", "repo", "files", "py"):
        d = os.path.join(fx, name)
        os.makedirs(os.path.join(d, "home"))
        with open(os.path.join(d, "home", ".gitconfig"), "w") as f:
            f.write(GITCONFIG)
    env = env_for(os.path.join(fx, "repo"))
    r = os.path.join(fx, "repo")
    sh("git init -q . && printf 'home/\\n' >> .git/info/exclude"
       " && printf 'line 1\\nline 2\\nline 3\\n' > README.md && git add README.md"
       " && git commit -qm 'readme'"
       " && mkdir src && echo a > src/a.txt && git add src && git commit -qm 'a'"
       " && echo b > src/b.txt && git add src && git commit -qm 'b'", r, env)
    f = os.path.join(fx, "files")
    items = [{"name": n, "n": i} for i, n in enumerate("delta alpha echo bravo charlie".split())]
    json.dump({"items": items, "x": 1}, open(os.path.join(f, "data.json"), "w"))
    json.dump(items, open(os.path.join(f, "items.json"), "w"))
    json.dump({"a": 1, "b": "x", "c": [1, 2]}, open(os.path.join(f, "flat.json"), "w"))
    with open(os.path.join(f, "lines.txt"), "w") as fh:
        fh.write("".join(f"line {i}\n" for i in range(20)))
    p = os.path.join(fx, "py")
    os.makedirs(os.path.join(p, "many"))
    for i in range(40):
        with open(os.path.join(p, "many", f"file-{i:02d}-{(i * 7919) % 97}.txt"), "w") as fh:
            fh.write(str(i))
    with open(os.path.join(p, "mymod.py"), "w") as fh:
        fh.write("def f():\n    return 42\n")
    return fx


def fresh(fixture, w):
    if os.path.lexists(w):
        subprocess.run(["chmod", "-R", "u+rwx", w], check=False)
        shutil.rmtree(w)
    shutil.copytree(fixture, w, symlinks=True)


def manifest(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            if os.path.islink(p):
                out[rel] = "l:" + os.readlink(p)
            elif os.path.isdir(p):
                out[rel] = "d:%o" % (st.st_mode & 0o7777)
            else:
                out[rel] = "f:%o:%s" % (st.st_mode & 0o7777,
                                        hashlib.sha256(open(p, "rb").read()).hexdigest())
    return out


def native(cmd, w, env, timeout):
    t0 = time.perf_counter()
    try:
        p = subprocess.run(["sh", "-c", cmd], cwd=w, env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = "timeout", b"", b""
    dt = time.perf_counter() - t0
    return {"rc": rc, "stdout": out, "stderr": err, "tree": manifest(w), "secs": dt}


def rr_status():
    if shutil.which("rr") is None:
        return False, "rr is not installed on this host"
    tmp = "/tmp/replay-proof-rr-probe"
    shutil.rmtree(tmp, ignore_errors=True)
    p = subprocess.run(["rr", "record", "-n", "-o", tmp, "true"], capture_output=True, text=True)
    shutil.rmtree(tmp, ignore_errors=True)
    if p.returncode != 0:
        return False, "rr record failed: " + (p.stderr.strip().splitlines() or ["?"])[-1]
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/replay-proof")
    ap.add_argument("--base", default="/tmp/replay-proof-corpus")
    ap.add_argument("--out", default="work/fidelity")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--min-identical", type=int, default=95)
    ap.add_argument("--only", default=None, help="comma-separated case ids")
    a = ap.parse_args()
    rp = os.path.abspath(a.bin)
    os.makedirs(a.out, exist_ok=True)
    bundles = os.path.join(os.path.abspath(a.out), "bundles")
    os.makedirs(bundles, exist_ok=True)
    fx = build_fixtures(a.base)
    w = os.path.join(a.base, "w")
    env = env_for(w)
    envfile = os.path.join(a.base, "env")
    with open(envfile, "w") as f:
        f.write("".join(f"{k}={v}\n" for k, v in env.items()))
    rr_ok, rr_why = rr_status()
    cases = CASES
    if a.only:
        keep = set(a.only.split(","))
        cases = [c for c in CASES if c[0] in keep]
    results = []
    for cid, fixture, cmd in cases:
        r = {"id": cid, "fixture": fixture, "cmd": cmd}
        fresh(os.path.join(fx, fixture), w)
        n1 = native(cmd, w, env, a.timeout)
        fresh(os.path.join(fx, fixture), w)
        n2 = native(cmd, w, env, a.timeout)
        r["native_secs"] = min(n1["secs"], n2["secs"])
        r["native_rc"] = n1["rc"]
        r["naive_rerun_identical"] = all(n1[k] == n2[k] for k in ("rc", "stdout", "stderr", "tree"))
        fresh(os.path.join(fx, fixture), w)
        b = os.path.join(bundles, cid + ".rpl")
        t_cli = time.perf_counter()
        try:
            p = subprocess.run([rp, "record", "--workdir", w, "--out", b, "--env-file", envfile,
                                "--", "sh", "-c", cmd], capture_output=True, text=True,
                               timeout=a.timeout)
        except subprocess.TimeoutExpired:
            p = subprocess.CompletedProcess([], 2, "", f"timeout after {a.timeout}s")
        if p.returncode != 0:
            r.update(identical=False, error="record failed: " + p.stderr.strip())
            results.append(r)
            print(f"{cid:28} RECORD-ERROR {p.stderr.strip()[:120]}", flush=True)
            continue
        r["record_cli_secs"] = time.perf_counter() - t_cli
        s = json.loads(p.stdout)
        r["record_secs"] = s["record_wall_ns"] / 1e9
        r["events"] = s["events"]
        r["processes"] = s["processes"]
        r["multithreaded"] = s["multithreaded"]
        r["sizes"] = s["sizes"]
        r["record_exit"] = s["exit"]
        r["record_matches_native_rc"] = s["exit"].get("code") == n1["rc"]
        try:
            v = subprocess.run([rp, "verify", b, "--replace"], capture_output=True, text=True,
                               timeout=a.timeout)
        except subprocess.TimeoutExpired:
            v = subprocess.CompletedProcess([], 2, "", f"timeout after {a.timeout}s")
        if v.returncode == 2:
            r.update(identical=False, error="verify error: " + v.stderr.strip())
        else:
            rep = json.loads(v.stdout)
            r["identical"] = rep["identical"]
            r["replay_secs"] = rep["replay_wall_ns"] / 1e9
            r["report"] = {k: rep[k] for k in ("stdout_match", "stderr_match", "exit_match",
                                               "tree_match", "tree_diff", "divergence",
                                               "unconsumed")}
        if rr_ok:
            fresh(os.path.join(fx, fixture), w)
            trace = os.path.join(a.base, "rr-trace")
            shutil.rmtree(trace, ignore_errors=True)
            t0 = time.perf_counter()
            try:
                q = subprocess.run(["rr", "record", "-n", "-o", trace, "sh", "-c", cmd], cwd=w,
                                   env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=a.timeout)
            except subprocess.TimeoutExpired:
                q = subprocess.CompletedProcess([], "timeout", b"", b"")
            r["rr_secs"] = time.perf_counter() - t0
            r["rr_rc"] = q.returncode
            shutil.rmtree(trace, ignore_errors=True)
        results.append(r)
        status = "IDENTICAL" if r.get("identical") else "DIFFERENT"
        print(f"{cid:28} {status:9} naive_rerun_identical={r['naive_rerun_identical']!s:5} "
              f"native={r['native_secs']*1e3:7.1f}ms record={r.get('record_secs', 0)*1e3:7.1f}ms "
              f"events={r.get('events')} log={r.get('sizes', {}).get('events')}B", flush=True)
    if os.path.lexists(w):
        subprocess.run(["chmod", "-R", "u+rwx", w], check=False)
        shutil.rmtree(w)

    ok = [r for r in results if r.get("identical")]
    timed = [r for r in results if "record_secs" in r]
    ratios = [r["record_secs"] / r["native_secs"] for r in timed]
    rep_ratios = [r["replay_secs"] / r["native_secs"] for r in timed if "replay_secs" in r]
    cli_ratios = [r["record_cli_secs"] / r["native_secs"] for r in timed]
    ev_bytes = sum(r["sizes"]["events"] for r in timed)
    rec_secs = sum(r["record_secs"] for r in timed)
    nat_secs = sum(r["native_secs"] for r in timed)
    geo = lambda xs: (statistics.geometric_mean(xs) if xs else None)  # noqa: E731
    summary = {
        "cases": len(results),
        "identical": len(ok),
        "naive_rerun_identical": sum(1 for r in results if r["naive_rerun_identical"]),
        "failures": [{"id": r["id"], "multithreaded": r.get("multithreaded"),
                  "why": r.get("error") or r.get("report")}
                     for r in results if not r.get("identical")],
        "record_overhead_geomean": geo(ratios),
        "record_overhead_median": statistics.median(ratios) if ratios else None,
        "replay_overhead_geomean": geo(rep_ratios),
        "record_cli_overhead_geomean": geo(cli_ratios),
        "native_total_secs": nat_secs,
        "record_total_secs": rec_secs,
        "event_log_bytes_total": ev_bytes,
        "event_log_bytes_per_record_sec": ev_bytes / rec_secs if rec_secs else None,
        "event_log_bytes_per_native_sec": ev_bytes / nat_secs if nat_secs else None,
        "event_log_bytes_per_sec_median": statistics.median(
            [r["sizes"]["events"] / r["record_secs"] for r in timed]) if timed else None,
        "bundle_bytes_total": sum(r["sizes"]["total"] for r in timed),
        "rr": rr_why,
    }
    if rr_ok:
        rr_ratios = [r["rr_secs"] / r["native_secs"] for r in timed if r.get("rr_rc") == 0]
        summary["rr_record_overhead_geomean"] = geo(rr_ratios)
        summary["rr_cases_ok"] = len(rr_ratios)
    with open(os.path.join(a.out, "fidelity.json"), "w") as f:
        json.dump({"summary": summary, "results": results}, f, indent=1, default=str)
    lines = [
        f"identical on replay: {len(ok)}/{len(results)}",
        f"naive re-execution identical (control): {summary['naive_rerun_identical']}/{len(results)}",
        f"record overhead vs native: geomean x{summary['record_overhead_geomean']:.2f}, "
        f"median x{summary['record_overhead_median']:.2f}" if ratios else "record overhead: n/a",
        f"replay overhead vs native: geomean x{summary['replay_overhead_geomean']:.2f}"
        if rep_ratios else "replay overhead: n/a",
        f"whole `record` command (snapshot, trace, hash, seal, write) vs native: geomean "
        f"x{summary['record_cli_overhead_geomean']:.2f}" if cli_ratios else "",
        f"event log: {ev_bytes} bytes compressed over {rec_secs:.2f} s recorded = "
        f"{summary['event_log_bytes_per_record_sec']:.0f} B/s "
        f"(median per run {summary['event_log_bytes_per_sec_median']:.0f} B/s)" if timed else "",
        f"rr: {rr_why}" + (f", record overhead geomean x{summary['rr_record_overhead_geomean']:.2f} "
                           f"over {summary['rr_cases_ok']} runs" if rr_ok and summary.get("rr_record_overhead_geomean") else ""),
        "failures:",
    ] + [f"- {x['id']} (multithreaded={x['multithreaded']}): {json.dumps(x['why'])[:400]}"
         for x in summary["failures"]]
    md = "\n".join(lines) + "\n"
    open(os.path.join(a.out, "fidelity.md"), "w").write(md)
    print(md)
    return 0 if len(ok) >= a.min_identical or a.only else 1


if __name__ == "__main__":
    sys.exit(main())
