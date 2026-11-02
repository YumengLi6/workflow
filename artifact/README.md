# Seven Bits of PAC — artifact

This artifact reproduces the **canary + PAC two-stage oracle** on an
Armv8.3 forking server and packages the GitHub Actions workflows and raw
logs for the paper's other experiments.

## What this artifact reproduces

- `artifact/reproduce-canary.sh`: builds `server_canary.c` with
  `-fstack-protector-strong -mbranch-protection=pac-ret+bti`, runs the
  forking server, and executes `attack_canary.py`. The attack
  1. recovers the stack canary byte-by-byte (1 + 7*256 = 1,793 queries),
     then
  2. brute-forces the 7-bit saved-LR PAC (128 guesses),
  for **1,921 queries per trial**. Expected: `success=10/10`,
  ~8 s/trial on Neoverse-N2.
- `artifact/results/canary-trials.log`: the GHA **10/10** run
  (run `41404728441`).
- `artifact/results/fault-limit.log`: the fault-limit matrix (run
  `41406558423`): all-signal limit 0/10 at N=1/4/16/64; SIGILL-only
  2/10, 2/10, 5/10, 9/10.
- `artifact/results/apache-*.log`: stock Apache `2.4.58-1ubuntu8`
  CVE-2026-63292 canary crash (run `41383608690`).
- `artifact/results/proftpd-*`: ProFTPD CVE-2010-4221 GHA oracle
  (run `41377059189`).
- `artifact/docs/`: E2a stock-hardening, E2b CVE candidates, E5
  crash-free scan, and the real-CVE canary negative results.

## Requirements

- Ubuntu 24.04 arm64 (GitHub Actions `ubuntu-24.04-arm` or native),
  GCC 13 with `-mbranch-protection`, Python 3, `nm`.
- The synthetic reproduction needs no network access.
- The GHA workflows need a GitHub repository with Actions enabled.

## Quick start

```bash
cd artifact
bash reproduce-canary.sh
```

Expected output ends with `success=10/10`. Per-trial logs are written to
`artifact/results/repro-*.log`.

## Layout

```
artifact/
  reproduce-canary.sh      one-click 10-trial synthetic reproduction
  server_canary.c          forking server: canary [x29-8], saved LR [x29+8]
  attack_canary.py         canary prefix oracle + PAC brute force
  server_canary_limit.c    canary server with a global child-fault limit
  run_limit_trials.sh      2 filters x N=1/4/16/64 x 10 trials
  workflows/               copies of the four GHA workflow files
  results/                 raw logs from the GHA runs
  docs/                    measurement notes and negative results
  MANIFEST.md              SHA-256 of every file
  NOTICE                   third-party attribution
  LICENSE                  MIT
```

## GHA workflows

| branch | workflow | run | experiment |
|---|---|---|---|
| `canary` | `canary.yml` | 41404728441 | synthetic canary + PAC, 10 trials |
| `canary-limit` | `canary-limit.yml` | 41406558423 | fault-limit matrix |
| `apache-cve` | `apache-cve.yml` | 41383608690 | stock Apache CVE-2026-63292 canary crash |
| `main` | `cve-arm64.yml` | 41377059189 | ProFTPD CVE-2010-4221 PAC oracle |

## Notes

- `handle_client` has a 64-byte local buffer, a stack canary at
  `[x29-8]`, the saved LR at `[x29+8]`, and an epilogue `ldp x29,x30;
  retaa`.
- The client writes a canary prefix to `[x29-8]`; child survival
  (`SURVIVED`) reveals prefix correctness. After the canary is known,
  the client writes `win | (guess<<48)` to `[x29+8]`; a correct PAC
  jumps to `win` and writes `PWNED`.
- The canary is glibc's `__stack_chk_guard` (low byte 0x00).
- GHA runs use Neoverse-N2 (`paca`/`pacg`); QEMU runs use
  `-cpu max,pauth=on`.

## Caveats

- The write primitive is synthetic (direct writes to the canary and LR
  slots). The real-CVE canary composition is negative: glibc has live
  locals between the buffer and the canary; ProFTPD has a mandatory line
  terminator (see `docs/REAL-CVE-CANARY-NEGATIVE.md`).
- The crash-free oracle is prototype/runtime-API only. The stock scan of
  814 Ubuntu 24.04 arm64 ELF files found 51,094 AUT sites, all
  `autiasp`; zero `autia`/`autda` and zero aut+compare patterns
  (`docs/E5-CRASH-FREE-SCAN.md`).
- No real-world target; lab only.

## License

MIT for this artifact's code. Third-party components (QEMU, GCC, Ubuntu
packages, PACTight, PACStack) are cited, not redistributed. See
`NOTICE`.
