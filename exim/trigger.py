import socket
import ssl
import time

HOST = "127.0.0.1"
PORT = 2525


def recv_line_raw(sock):
    data = b""
    while b"\n" not in data:
        b = sock.recv(4096)
        if not b:
            break
        data += b
    return data


sock = socket.create_connection((HOST, PORT), timeout=5)
print("banner:", recv_line_raw(sock)[:160])
sock.sendall(b"EHLO test\r\n")
print("ehlo:", recv_line_raw(sock)[:300])
sock.sendall(b"STARTTLS\r\n")
print("starttls:", recv_line_raw(sock)[:120])

inc = ssl.MemoryBIO()
out = ssl.MemoryBIO()
ctx = ssl._create_unverified_context()
obj = ctx.wrap_bio(inc, out, server_side=False, server_hostname="test.local")


def flush():
    data = out.read()
    if data:
        sock.sendall(data)


def fill():
    data = sock.recv(4096)
    if not data:
        raise EOFError("raw EOF")
    inc.write(data)


while True:
    try:
        obj.do_handshake()
        break
    except ssl.SSLWantReadError:
        flush()
        fill()
flush()
print("tls handshake ok")


def tls_send(b):
    obj.write(b)
    flush()


def tls_recv_line():
    buf = b""
    while b"\n" not in buf:
        try:
            buf += obj.read(4096)
            flush()
        except ssl.SSLWantReadError:
            flush()
            fill()
        except ssl.SSLZeroReturnError:
            break
    return buf


tls_send(b"EHLO test\r\n")
print("ehlo2:", tls_recv_line()[:400])
tls_send(b"MAIL FROM:<a@b>\r\n")
print("mail:", tls_recv_line()[:120])
tls_send(b"RCPT TO:<c@d>\r\n")
print("rcpt:", tls_recv_line()[:120])

tls_send(b"BDAT 89 LAST\r\n")
time.sleep(0.1)
tls_send(b"To: Susan@random.com\r\n"
         b"From: Sam@random.com\r\n"
         b"Subject: This is a bodyless TEST message\r\n\r\n")
time.sleep(0.1)

try:
    obj.unwrap()
except ssl.SSLWantReadError:
    pass
except Exception as e:
    print("unwrap err", repr(e))
close_bytes = out.read()
print("close_notify bytes", len(close_bytes))
try:
    sock.sendall(close_bytes + b"x")
    print("sent close_notify+x")
except Exception as e:
    print("raw send err", repr(e))
time.sleep(0.6)
