#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int g_fd = -1;

__attribute__((noinline)) void win(void) {
    if (g_fd >= 0) write(g_fd, "PWNED\n", 6);
    _exit(0);
}

/* Synthetic canary + PAC oracle.
 * Protocol: 2-byte header: nc (canary bytes to write, 0..8), nl (0 or 8).
 * Then nc bytes are written to [x29-8] (canary slot), and if nl==8,
 * 8 bytes are written to [x29+8] (saved LR).  After handle_client returns
 * the child writes SURVIVED; a canary mismatch aborts before that.
 */
__attribute__((noinline)) void handle_client(int fd) {
    unsigned char tmp[64];
    unsigned char hdr[2];
    volatile unsigned char *fp =
        (volatile unsigned char *)__builtin_frame_address(0);

    tmp[0] = 0; /* keep a stack buffer for -fstack-protector-strong */
    g_fd = fd;
    if (read(fd, hdr, 2) != 2) return;
    unsigned int nc = hdr[0];
    unsigned int nl = hdr[1];
    if (nc > 8) nc = 8;

    if (nc > 0) {
        volatile unsigned char *canary = fp - 8;
        size_t got = 0;
        while (got < nc) {
            ssize_t r = read(fd, (void *)(canary + got), nc - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
    }

    if (nl == 8) {
        unsigned char lr[8];
        size_t got = 0;
        while (got < 8) {
            ssize_t r = read(fd, lr + got, 8 - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        if (got == 8) {
            volatile unsigned long *slot =
                (volatile unsigned long *)(fp + 8);
            *slot = *(unsigned long *)lr;
        }
    }

    write(fd, "OK\n", 3);
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9999;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(s, (void *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(s, 256);
    fprintf(stderr, "listening %d\n", port);
    for (;;) {
        int c = accept(s, 0, 0);
        if (c < 0) continue;
        pid_t p = fork();
        if (p == 0) {
            close(s);
            handle_client(c);
            write(c, "SURVIVED\n", 9);
            close(c);
            _exit(0);
        }
        close(c);
        int st;
        while (waitpid(-1, &st, WNOHANG) > 0) {
            if (WIFSIGNALED(st)) fprintf(stderr, "child signaled %d\n", WTERMSIG(st));
        }
    }
}
