# cortex9-replay-proof

[![CI](https://github.com/federiconbaez/cortex9-replay-proof/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-replay-proof/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Grabación y reproducción **determinista** de ejecuciones de herramientas (un comando, su árbol de procesos) en Linux x86_64, con un **bundle autocontenido** que un tercero verifica volviendo a ejecutar: misma salida, mismo exit status y mismos efectos en el filesystem, byte a byte.

**Deterministic** record/replay of tool executions (a command and its process tree) on Linux x86_64, producing a **self-contained bundle** a third party verifies by re-running it: same output, same exit status and same filesystem effects, byte for byte.

> **ES** primero · **EN** below

---

## Español

### Cómo funciona

```text
 record:  snapshot(workdir) ─▶ fork ─▶ personality(ADDR_NO_RANDOMIZE)
                                  └─▶ PTRACE_TRACEME ─▶ seccomp(RET_TRACE sólo para 41 syscalls) ─▶ execve
          supervisor ptrace:  en cada exec  → AT_SYSINFO_EHDR := AT_IGNORE (sin vDSO) y guarda AT_RANDOM
                              en cada syscall interceptada → guarda retorno + buffers de salida
          snapshot(workdir) ─▶ bundle = header JSON (la afirmación) + entradas + log de eventos

 verify:  restaura el árbol de entrada en la MISMA ruta absoluta ─▶ mismo fork/seccomp/ptrace
          cada syscall interceptada ─▶ se saltea y se inyecta el resultado grabado, o corre y se sobrescribe
          compara stdout, stderr, exit status y el digest del árbol de salida con el header
```

- **Sólo las syscalls no deterministas paran al tracer.** El filtro seccomp devuelve `SECCOMP_RET_TRACE` para 41 números y `SECCOMP_RET_ALLOW` para el resto, así que `write`, `openat`, `mmap`, etc. corren sin supervisor.
- **El vDSO se oculta** en cada imagen exec'd reescribiendo la entrada `AT_SYSINFO_EHDR` del auxv a `AT_IGNORE` en la parada `PTRACE_EVENT_EXEC`. Sin vDSO, libc cae a las syscalls reales de `clock_gettime`/`gettimeofday`/`time`/`getcpu`, que se pueden grabar.
- **ASLR apagado** (`ADDR_NO_RANDOMIZE`, se hereda) y los 16 bytes de `AT_RANDOM` se graban y se reinyectan: direcciones como `id()` de Python o el canario de pila salen iguales.
- **Procesos hijos**: cada proceso tiene su propio stream de eventos con una clave por posición en el árbol (`0`, `0.0`, `0.1`, ...), que no depende de pids reales ni del scheduling entre procesos. Los pids se **virtualizan**: `getpid`/`fork`/`wait4` devuelven los grabados y `kill`/`tgkill`/`setpgid` traducen pid grabado → real. `wait4(-1)`/`waitid(P_ALL)` se fuerzan a cosechar el mismo hijo que en la grabación.

| Tratamiento en replay | Syscalls |
|---|---|
| **Emular** (se saltea con `orig_rax = -1` y se inyecta retorno + buffers) | `clock_gettime`, `gettimeofday`, `time`, `getrandom`, `getpid`, `getppid`, `gettid`, `getpgrp`, `getpgid`, `getsid`, `uname`, `sysinfo`, `getrusage`, `times`, `sched_getaffinity`, `getcpu`, `getuid`, `getgid`, `geteuid`, `getegid`, `getresuid`, `getresgid` |
| **Correr y sobrescribir** (cambian estado del kernel que el programa usa después) | `stat`, `fstat`, `lstat`, `newfstatat`, `statx` (inodos, timestamps, dispositivo), `getdents64` (orden de directorio), `set_tid_address` |
| **Lecturas no deterministas** (sólo si el fd apunta a `/dev/urandom`, `/dev/random`, `/proc/*`, `/sys/*`) | `read`, `pread64` |
| **Fork** (retorno = pid grabado del hijo, se agrega al mapa de pids) | `clone`, `fork`, `vfork`, `clone3` |
| **Wait** (forzado al mismo hijo) | `wait4`, `waitid` |
| **Traducción de argumentos** (nada se graba) | `kill`, `tgkill`, `tkill`, `setpgid` |

Si el programa pide en replay una syscall distinta de la siguiente grabada para ese proceso, el replay se corta y el reporte dice **dónde** divergió (proceso, índice, esperado vs. obtenido).

### El bundle y qué verifica un tercero

`MAGIC | header JSON | deflate(entradas) | deflate(eventos)`. El header es la **afirmación**: argv, env, ruta del workdir, SHA-256 del árbol de entrada, de stdin, de stdout, de stderr, exit status, digest del árbol de salida con un manifiesto por archivo, SHA-256 de cada ejecutable que corrió, y los SHA-256 de las dos secciones. El **claim digest** es el SHA-256 del header: identifica toda la afirmación (sirve para ligarla a un `tools/call` o a una atestación). Un bit cambiado en cualquier byte hace que el bundle no abra o que cambie el claim digest, salvo los bits de relleno al final de un stream deflate, que no cambian el contenido (test `tampering_is_detected`).

`replay-proof verify` restaura el árbol, reproduce y compara. Lo que **demuestra**: que la salida y los efectos afirmados son exactamente lo que produce ese comando con esas entradas y **esos valores no deterministas** (los del log, que quedan a la vista: qué hora vio, qué bytes aleatorios recibió, qué pids). Lo que **no demuestra**: que esos valores fueran genuinos (quien grabó podría haber inventado la hora; eso requiere firmar/atestar la grabación, no implementado acá), ni que los archivos fuera del workdir (`/usr`, `/etc`, librerías compartidas) sean iguales en el host del verificador: sólo se fijan los ejecutables por hash y una diferencia se reporta en `executable_mismatches`.

El árbol de salida se compara por ruta, tipo, permisos y contenido; **no** por timestamps (los archivos escritos en el replay tienen la hora del host, pero el programa nunca la ve: las llamadas `stat` devuelven las grabadas).

### Resultados medidos

Todos los números salen de los scripts del repo; el CI los vuelve a medir en cada push (job `fidelity`).

**(a) Fidelidad sobre 100 corridas** (`scripts/corpus.py`: 36 de git, 18 de jq, 32 de Python, 14 de shell/coreutils; cada una en una copia nueva de su fixture):

| Medición (box, kernel 6.12, 5 corridas seguidas del corpus) | Resultado |
|---|---|
| Idénticas en replay (stdout, stderr, exit y árbol de salida) | **97/100** en 4 corridas, 98/100 en 1 — criterio ≥ 95: **cumplido** |
| Comando | `cargo build --release && python3 scripts/fidelity.py` |

Control: re-ejecutar dos veces **sin** replay-proof da salida o efectos idénticos sólo en 48–49/100 casos; los otros 51–52 son genuinamente no deterministas (commits de git con hora, `jq now`, `uuid4`, `/dev/urandom`, orden de `set` en Python, `mkstemp`, pyc con mtime, pids...).

Las corridas que no se reproducen son **todas multihilo**, que está fuera de alcance (ver límites):

| Caso | Por qué |
|---|---|
| `git-grep` | `git grep` reparte el trabajo en hilos; en replay otro hilo hace las `newfstatat` y el log de ese hilo no las tiene. Falla en las 5 corridas. |
| `py-multiprocessing` | `multiprocessing.Pool` usa hilos de manejo en el padre; diverge en el orden de `clock_gettime`/`gettid`/`clone3`. Falla en las 5. |
| `py-threading` | Un hilo que llama `time.time()`; según quién toma el GIL primero, el `clock_gettime` cae en otro hilo. Falla en 4 de 5 (pasó una vez por suerte de scheduling). |

**(b) Overhead.** En el corpus (corridas de 1–40 ms, domina el arranque de procesos): grabar cuesta **×1.84–2.02** (media geométrica de tiempo grabado / nativo, según la corrida) y reproducir **×1.87–1.98**. El comando `record` completo (snapshot de entrada y salida, hash de ejecutables, sellado y escritura del bundle) cuesta ×3.01–3.20.

En cargas más largas (5 corridas, mediana; `python3 scripts/overhead.py --runs 5`):

| workload | native | record | replay | record x | replay x | log B/s | identical | hermit x |
|---|---|---|---|---|---|---|---|---|
| time-syscalls-200k | 26 ms | 3271 ms | 2919 ms | 127.47 | 113.78 | 228581 | 5/5 | 368.37 |
| cpu-bound-python | 100 ms | 108 ms | 108 ms | 1.09 | 1.09 | 106296 | 5/5 | 1.62 |
| git-log-p-300 | 39 ms | 102 ms | 107 ms | 2.61 | 2.74 | 490788 | 5/5 | 28.44 |
| jq-5mb | 221 ms | 244 ms | 250 ms | 1.10 | 1.13 | 2729 | 5/5 | 1.65 |
| tar-gz-500-files | 8 ms | 39 ms | 42 ms | 4.73 | 5.02 | 342014 | 5/5 | 37.23 |

La box es compartida con otros trabajos y el tiempo varía: la misma carga `time-syscalls-200k` midió 1376 ms grabando (×35) en una corrida anterior de 3 repeticiones.

El peor caso es un programa que sólo pide la hora: sin vDSO cada `time.time()` es una syscall más dos paradas de ptrace. El caso CPU-bound casi no paga nada porque el filtro seccomp deja pasar todo lo demás.

**Baselines rr y Hermit.** **rr 5.9.0** (`.deb` oficial) se instaló pero **no puede grabar en la box**: `Unable to open performance counter with 'perf_event_open'`, también como root y con `perf_event_paranoid=1`; la VM no expone una PMU de CPU (`/sys/bus/event_source/devices` no tiene `cpu`). El job `fidelity` del CI instala rr y reporta si en el runner puede. **Hermit 0.5.4**, compilado del fork mantenido [rrnewton/hermit](https://github.com/rrnewton/hermit) en `0e7fd4b` (el HEAD de facebookexperimental/hermit no compiló: `detcore-dbt` sin fuente), **sí corre** en la box sin contadores (avisa `--max-timeslice=disabled`). `hermit run --tmp=/tmp` sobre el mismo corpus: **×15.4** de media geométrica sobre los 98 casos con el mismo exit que el nativo (los dos `git gc` salen con 128 bajo Hermit, no lo investigué); en las cargas largas, la columna `hermit x` de la tabla. Ojo con la comparación: `hermit run` hace determinista la ejecución entera (incluido el scheduling de hilos, que acá está fuera de alcance), no es lo mismo que grabar. No medí `hermit record`. Hermit no está en el CI (compilarlo lleva un nightly fijado y varios minutos).

**(c) Tamaño del log** (eventos comprimidos con deflate): las 100 corridas suman **≈544 KB** (≈5.4 KB por corrida; de 0.4 a 28 KB). Por segundo: **430–704 KB/s** de ejecución nativa y 226–361 KB/s de ejecución grabada (total del log / tiempo total, según la corrida); en las cargas largas, la columna `log B/s`: de 2.7 KB/s (jq, casi sin syscalls interceptadas) a 491 KB/s (`git log -p`, muchos `stat`). Cada corrida de Python pesa ≈11 KB o más sólo por el arranque: cientos de `newfstatat`/`fstat` al importar módulos y de `clock_gettime`.

### Uso

```sh
cargo build --release
B=target/release/replay-proof

# grabar (usa el entorno de este proceso, o exactamente las líneas KEY=VALUE de --env-file)
$B record --workdir /tmp/job --out job.rpl -- sh -c 'git commit -qam wip && git log -1 --format=%H'

# verificar (en otra máquina con los mismos binarios, o en la misma)
$B verify job.rpl            # se niega si /tmp/job existe
$B verify job.rpl --replace  # lo borra y lo recrea desde el bundle
$B inspect job.rpl           # header, tamaños, eventos por syscall
```

`verify` sale con 0 si todo coincide, 1 si algo difiere (el JSON dice qué) y 2 por error. Ojo: **el env completo queda en el bundle**; no grabes con secretos en el entorno.

### Tests

```sh
cargo test --release
```

- 10 unitarios: tabla de syscalls y buffers de salida, filtro seccomp interpretado para los números 0–499 y otra arquitectura, snapshot/restore/digest del árbol, ida y vuelta del bundle y detección de un bit cambiado en cada byte.
- 10 de integración con ptrace + seccomp reales (fallan, no se saltean, si el host no los permite): Python con hora/pid/random/uuid/hash/id (con control: dos grabaciones difieren), vDSO oculto (llegan `clock_gettime` al tracer) y ejecutables con hash, commit de git byte a byte, fork/pids/wait virtualizados, `/dev/urandom` y `/proc`, **un valor de reloj manipulado cambia la salida** y el verify lo rechaza, un comando editado se detecta, hilos marcados como fuera de alcance, verify no pisa un directorio existente, y la CLI con sus códigos de salida.

### Límites y lo que no está probado

- **Multihilo: fuera de alcance.** Los hilos se detectan (`multithreaded: true` en el header) pero no se serializan; las 3 fallas del corpus son esto. Hermit sí ataca este problema.
- **Misma ruta absoluta** en grabación y replay (el programa puede imprimir su cwd o guardar rutas absolutas). Los archivos fuera del workdir tienen que ser los mismos en el host del verificador; sólo los ejecutables se fijan por hash. Probado sólo en el mismo host (box) y en runners de GitHub `ubuntu-latest`, nunca grabando en uno y verificando en otro.
- **No se graba**: red (lecturas de sockets), `rdtsc`/`rdrand` en espacio de usuario, `CPUID`, señales asíncronas y su momento de entrega, disponibilidad en `poll`/`select`/`epoll`, memoria compartida entre procesos, `io_uring`. Las lecturas de pipes entre procesos tampoco: su contenido es determinista si los procesos lo son, pero el tamaño de cada `read` puede variar.
- Sólo x86_64 (otra arquitectura en el mismo proceso, p. ej. `int 0x80`, se mata con `SECCOMP_RET_KILL_PROCESS` en lugar de quedar sin grabar).
- `syscalls::outputs` asume el layout x86_64 de cada struct (`stat` 144 bytes, `statx` 256, `rusage` 144, ...).
- La biblioteca espera con `waitpid(-1, __WALL)`: un proceso no debe correr dos grabaciones a la vez ni tener otros hijos propios mientras graba.
- El overhead se mide contra la ejecución nativa en el mismo host; rr y Hermit, ver arriba.

### Arte previo (leído)

- [rr README](https://github.com/rr-debugger/rr): record/replay para debugging de árboles de procesos e hilos; requiere contadores de rendimiento de hardware (en VMs, sólo si la VM los virtualiza).
- [rr wiki: Will rr work on my system](https://github.com/rr-debugger/rr/wiki/Will-rr-work-on-my-system): cómo comprobar los contadores con `perf stat`.
- [Hermit README](https://github.com/facebookexperimental/hermit) (y su fork mantenido [rrnewton/hermit](https://github.com/rrnewton/hermit)): ejecución determinista sobre el backend ptrace de Reverie, controla scheduling de hilos, tiempo, random, CPUID y metadata de archivos; `hermit record`/`replay` figuran como experimentales; requiere Rust nightly y namespaces de usuario, PID y mount.
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html): `SECCOMP_RET_TRACE`, `PTRACE_EVENT_SECCOMP` y cómo el tracer saltea una syscall cambiando el número a −1 y poniendo el valor de retorno.
- [vdso(7)](https://man7.org/linux/man-pages/man7/vdso.7.html): el vDSO se encuentra por `AT_SYSINFO_EHDR` y libc lo usa para las llamadas frecuentes.

Lo que este repo agrega frente a rr y Hermit: un artefacto portable y chico (KB, no una traza de rr) ligado por hash a una afirmación concreta (comando, entradas, salida, efectos), que no necesita contadores de hardware ni namespaces, y un `verify` que responde sí/no con el motivo.

### Licencia

Apache-2.0. Ver [LICENSE](LICENSE).

---

## English

### How it works

The recorder snapshots the working directory, forks the tool with ASLR disabled, makes it a ptrace tracee and installs a seccomp filter right before `execve` that returns `SECCOMP_RET_TRACE` for 41 nondeterministic system calls and `SECCOMP_RET_ALLOW` for everything else. At every `PTRACE_EVENT_EXEC` stop the supervisor rewrites the `AT_SYSINFO_EHDR` auxv entry to `AT_IGNORE`, so libc has no vDSO and time calls become real, recordable system calls, and it records (or, on replay, re-injects) the 16 `AT_RANDOM` bytes. Each intercepted call's return value and output buffers are saved per process, keyed by the process's position in the tree (`0`, `0.0`, ...), not by pid.

On replay the input tree is restored at the **same absolute path**. Pure sources (time, randomness, ids, host info: see the table above) are skipped by setting the syscall number to −1 and injecting the recorded result; calls that change kernel state the program relies on (`stat` family, `getdents64`, `set_tid_address`, `fork`/`clone`) run for real and their results are overwritten; reads are recorded only when the descriptor points to `/dev/urandom`, `/dev/random`, `/proc` or `/sys`. Pids are virtualized (fork/getpid/wait return the recorded values; kill/tgkill/setpgid arguments are translated) and `wait4(-1)` is forced to reap the same child as in the recording. A request that does not match the next recorded event stops the replay and is reported as a divergence (process, index, expected vs. got).

### The bundle and what a third party verifies

`MAGIC | header JSON | deflate(inputs) | deflate(events)`. The header is the **claim**: argv, env, workdir, SHA-256 of the input tree, stdin, stdout, stderr, the exit status, the output-tree digest with a per-file manifest, the SHA-256 of every executable that ran, and the SHA-256 of both sections. The **claim digest** (SHA-256 of the header) identifies the whole claim, so it can be bound to a `tools/call` or an attestation. Flipping a bit anywhere makes the bundle fail to open or changes the claim digest, except padding bits at the end of a deflate stream, which do not change the content.

`verify` proves that the claimed output and effects are exactly what that command produces with those inputs and **those nondeterministic values**, which are in the log for anyone to read (the time it saw, the random bytes, the pids). It does **not** prove the values were genuine (that needs the recording to be signed/attested, not implemented here), nor that files outside the workdir (`/usr`, `/etc`, shared libraries) match on the verifier's host: only executables are pinned by hash, and a mismatch is reported in `executable_mismatches`. Output trees are compared by path, type, permissions and content, not timestamps (the program never observes the replay host's timestamps, because `stat` returns the recorded ones).

### Measured results

All numbers come from the scripts in this repo, and CI measures them again on every push (`fidelity` job).

**(a) Fidelity over 100 runs** (`scripts/corpus.py`: 36 git, 18 jq, 32 Python, 14 shell/coreutils; each in a fresh copy of its fixture):

| Measurement (box, kernel 6.12, 5 consecutive corpus runs) | Result |
|---|---|
| Identical on replay (stdout, stderr, exit and output tree) | **97/100** in 4 runs, 98/100 in 1 — target ≥ 95: **met** |
| Command | `cargo build --release && python3 scripts/fidelity.py` |

Control: running twice **without** replay-proof gives identical output and effects in only 48–49/100 cases; the other 51–52 are genuinely nondeterministic. Every run that does not reproduce is **multithreaded**, which is out of scope (failure list above).

**(b) Overhead.** On the corpus (1–40 ms runs, dominated by process start-up): recording costs **×1.84–2.02** (geometric mean of recorded/native time, depending on the run) and replaying **×1.87–1.98**; the whole `record` command (input and output snapshots, executable hashes, sealing and writing the bundle) costs ×3.01–3.20. On longer workloads see the table above (5 runs, median). The worst case is a program that only asks for the time: without a vDSO every `time.time()` is a system call plus two ptrace stops. CPU-bound code pays almost nothing because the seccomp filter lets everything else through.

**rr and Hermit baselines.** **rr 5.9.0** (official `.deb`) installs but **cannot record on the box**: `Unable to open performance counter with 'perf_event_open'`, also as root with `perf_event_paranoid=1`; the VM exposes no CPU PMU. The CI `fidelity` job installs rr and reports whether it works on the runner. **Hermit 0.5.4**, built from the maintained fork rrnewton/hermit at `0e7fd4b` (facebookexperimental/hermit's HEAD did not build), **does run** on the box without counters. `hermit run --tmp=/tmp` on the same corpus: **×15.4** geometric mean over the 98 cases with the native exit code (both `git gc` cases exit 128 under Hermit; not investigated); for the long workloads see the `hermit x` column. Caveat: `hermit run` determinizes the whole execution, thread scheduling included (out of scope here); it is not the same job as recording. `hermit record` was not measured, and Hermit is not in CI (it needs a pinned nightly and several minutes to build).

**(c) Log size** (deflate-compressed events): the 100 runs add up to **≈544 KB** (≈5.4 KB per run; 0.4 to 28 KB). Per second: **430–704 KB/s** of native execution and 226–361 KB/s of recorded execution (total log / total time, depending on the run); for the long workloads see the `log B/s` column, from 2.7 KB/s (jq, almost no intercepted calls) to 491 KB/s (`git log -p`, many `stat` calls).

### Usage and tests

See the Spanish section for the commands; `verify` exits 0 if everything matches, 1 if something differs (the JSON says what), 2 on error. **The whole environment is stored in the bundle**: do not record with secrets in it. `cargo test --release` runs 10 unit tests and 10 integration tests that use real ptrace and seccomp and fail (never skip) if the host does not allow them, including a test where a tampered clock value makes the replay disagree with the claim.

### Limitations and what is not tested

- **Multithreading is out of scope**: threads are detected (`multithreaded: true`) but not serialized; all 3 corpus failures are this. Hermit addresses it.
- Same absolute path for record and replay; files outside the workdir must match on the verifier's host (only executables are pinned). Only tested on the same host and on GitHub `ubuntu-latest` runners, never recording on one host and verifying on another.
- Not recorded: network (socket reads), user-space `rdtsc`/`rdrand`, `CPUID`, asynchronous signals and their timing, `poll`/`select`/`epoll` readiness, shared memory between processes, `io_uring`; pipe reads between processes are not recorded either (content is deterministic if the processes are, chunk sizes may vary).
- x86_64 only (a foreign-arch syscall such as `int 0x80` kills the process instead of going unrecorded); struct sizes in `syscalls::outputs` are x86_64's.
- The library waits with `waitpid(-1, __WALL)`: one recording per process at a time, and no other children of its own meanwhile.

### Prior art (read)

The rr README and its "Will rr work on my system" wiki page, the Hermit README (and its maintained fork), seccomp(2) and vdso(7); links in the Spanish section. What this adds: a small portable artifact (KB, not an rr trace) bound by hash to a concrete claim (command, inputs, output, effects), needing neither hardware counters nor namespaces, and a `verify` that answers yes/no with the reason.

### License

Apache-2.0. See [LICENSE](LICENSE).
