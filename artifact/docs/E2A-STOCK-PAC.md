# E2a — Ubuntu 24.04 arm64 stock hardening probe (2026-11-02)

## Method

- Index: `https://ports.ubuntu.com/ubuntu-ports/dists/noble/{main,universe}/binary-arm64/Packages.gz`
- Packages: extracted with `dpkg-deb -x`; instructions counted from
  `aarch64-linux-gnu-objdump -d` (`paciasp|autiasp|retaa|retab`, `bti`);
  canary from `readelf -sW | grep __stack_chk_fail`.
- Workdir: WSL `~/.codex/pac-attack/e2a-stock/`
  (scripts `probe-stock-pac.sh`, `verify-pac.sh`, `scan-exceptions.sh`).
- Windows mirror: `C:\Users\liyum\.codex\pac-attack\e2a-stock\`.

## Measurements (noble release packages, arm64)

| package | version | binary | pac insns | bti insns | canary ref |
|---|---|---|---|---|---|
| apache2-bin | 2.4.58-1ubuntu8 | usr/sbin/apache2 | 3139 | 316 | 1 |
| cups-daemon | 2.4.7-1.2ubuntu7 | usr/sbin/cupsd | 632 | 73 | n/t |
| dovecot-core | 1:2.3.21+dfsg1-2ubuntu5 | usr/sbin/dovecot | **0** | 81 | n/t |
| dovecot-core | same | usr/lib/dovecot/* (all) | **0** | — | n/t |
| exim4-daemon-heavy | 4.97-4ubuntu4 | usr/sbin/exim4 | 2189 | 526 | 1 |
| lighttpd | 1.4.74-1ubuntu3 | usr/sbin/lighttpd | 1711 | 235 | 1 |
| nginx (real pkg) | 1.24.0-2ubuntu7 | usr/sbin/nginx | 4144 | 308 | n/t |
| openssh-server | 1:9.6p1-3ubuntu13 | usr/sbin/sshd | 1812 | 308 | 1 |
| postfix | 3.8.6-1build2 | usr/lib/postfix/sbin/smtpd | 447 | n/t | n/t |
| postfix | same | usr/lib/postfix/sbin/master | 58 | n/t | n/t |
| proftpd-core | 1.3.8.b+dfsg-1build3 | usr/sbin/proftpd | 4767 | 464 | 1 |
| samba | 2:4.19.5+dfsg-4ubuntu9 | usr/sbin/nmbd | 614 | 21 | n/t |
| samba | same | usr/sbin/smbd | 99 | 3 | n/t |
| samba-common-bin | same | usr/bin/net | 2517 | 71 | n/t |
| vsftpd | 3.0.5-0ubuntu3 | usr/sbin/vsftpd | 386 | 21 | 1 |
| libc6 | 2.39-0ubuntu8 | libc.so.6 | n/t | n/t | n/t |

n/t = not tested.

## Findings

1. **Stock Ubuntu 24.04 arm64 daemons are pac-ret.** Instruction-level
   confirmation: `d503233f paciasp` at function prologues in apache2
   (`main`, `ap_get_server_built`, `ap_pool_cleanup_set_null`). Counts span
   unrelated packages (Apache, nginx, Exim, OpenSSH, Postfix, ProFTPD,
   lighttpd, vsftpd, Samba, CUPS) → distro-wide default, not per-package
   opt-in.
2. **GNU property note is absent** in the shipped (stripped) packages: only
   `.note.gnu.build-id` and `.note.ABI-tag`. Do not use "AArch64 feature:
   PAC/BTI" notes as evidence; use instruction counts.
3. **Canary is on**: every checked daemon references `__stack_chk_fail`.
   Stock targets therefore have BOTH pac-ret and stack protector. This is
   the E2c problem, not a surprise.
4. **Exceptions**:
   - `dovecot-core`: all binaries 0 `paciasp` (some `bti`); built without
     pac-ret. Candidate negative example / control.
   - `pure-ftpd`: `usr/sbin/pure-ftpd` absent from the `pure-ftpd` package
     (likely metapackage; binary in `pure-ftpd-common`/flavor package) —
     unresolved.
   - `postfix` main wrapper has only 3; real daemons live in
     `usr/lib/postfix/sbin/` (smtpd 447).
   - `nginx-core` is an `all` metapackage; real arm64 binary is in `nginx`.

## Implications for E2

- "Self-built pac-ret" is not a lab-only configuration: it matches Ubuntu
  24.04 arm64 distro defaults. But the **stock-binary** claim still needs a
  CVE present in a stock package version.
- Canary is deployed by default → E2c must choose: canary-free function/path,
  info leak, or explicit threat-model assumption. Measure, do not hide.
- Next: E2b find 2019+ app-level positive-length stack overflow in a
  stock/current package; then E2d on a stock pac-ret binary.
