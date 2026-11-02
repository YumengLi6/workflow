# E5 — crash-free oracle deployed-pattern scan (2026-11-02)

## Method

- Scope: 814 ELF aarch64 files extracted from the stock Ubuntu 24.04
  daemon packages already used in E2a (apache2-bin, nginx, proftpd,
  exim4, openssh, postfix, samba, lighttpd, vsftpd, cups, dovecot, ...).
- Each file disassembled with `aarch64-linux-gnu-objdump -d`.
- Every `AUT*` site is classified by the first use of the authenticated
  register within the next 12 instructions:
  - `direct`: `ret`/`retaa`/`br`/`blr` on it (return or direct branch);
  - `deref`: load/store with it as the base (dereference);
  - `compare`: `cmp`/`subs`/`cbz`/`cbnz`/`tbz`/`tbnz`/`b.cond` on it
    (crash-free-oracle candidate).
- Files: `e2a-stock/scan-aut-sites.py`, `summarize-aut.py`,
  `aut-scan.tsv`.

## Result

- Files scanned: **814**.
- `AUT*` sites: **51,094**.
- Mnemonics: **all 51,094 are `autiasp`** (return-address
  authentication). There are **zero** `autia`/`autib`/`autda`/`autdb`/
  `autiza`/`autizb`/`autdza`/`autdzb` sites.
- First-use classes: `direct` 42,168; `unknown` (shared epilogue / plain
  `b`) 8,926; **`compare` 0**; `deref` 0.

## Interpretation

- Stock Ubuntu 24.04 network daemons use PAC **only** for return
  addresses (`autiasp` + `ret`/`retaa`). They do not authenticate data
  pointers and compare/branch on the result.
- The crash-free oracle class is therefore **prototype/runtime-API
  only**: our synthetic pointer check and PACTight's dvipac runtime
  (`-DPACINST`) expose `aut` + compare; no deployed stock service in the
  scanned set does.
- Claim convergence: do not imply deployed prevalence of the crash-free
  oracle. Present it as a new oracle class + prototype measurement, with
  this scan as the deployed-pattern negative result.

## Caveats

- 814 files from 37 daemon packages, not the full distro.
- The scanner looks for a compare within 12 instructions of the `aut`.
  An `aut` in a callee that returns the pointer to a comparing caller
  would be missed; however, such a pattern requires `autia`/`autda`, of
  which the stock scan found zero. The `autiasp` sites are return
  authentication, where the register is consumed by `ret`/`retaa`.
- The PACTight runtime is a prototype, not a distro package; it was
  measured separately (10/10 crash-free oracle).
