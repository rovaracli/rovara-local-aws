/*
 * Network-silence recorder for the Rovara local AWS release gate.
 *
 * Loaded into the emulator process (LD_PRELOAD on Linux, DYLD_INSERT_LIBRARIES on macOS), it wraps
 * connect, sendto and sendmsg and appends one line to $ROVARA_NETGUARD_LOG for every attempt to reach an
 * address that is not loopback (IPv4 127.0.0.0/8 or 0.0.0.0, IPv6 ::1 and ::, or a Unix socket). The gate
 * fails when the log is not empty after the compatibility suite. With ROVARA_NETGUARD_BLOCK=1 the call
 * also fails with ENETUNREACH, so a run cannot reach the network while it is being checked.
 *
 * Written for Rovara; it holds no code from any other project.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#ifndef __APPLE__
#include <dlfcn.h>
#endif

static int is_loopback(const struct sockaddr *sa) {
    if (sa == NULL) return 1;
    if (sa->sa_family == AF_UNIX) return 1;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        uint32_t a = ntohl(in->sin_addr.s_addr);
        return (a >> 24) == 127 || a == 0;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        static const unsigned char zero[16] = {0};
        static const unsigned char loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        if (memcmp(&in6->sin6_addr, zero, 16) == 0 || memcmp(&in6->sin6_addr, loop, 16) == 0) return 1;
        const unsigned char *b = (const unsigned char *)&in6->sin6_addr;
        static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        return memcmp(b, mapped, 12) == 0 && b[12] == 127;
    }
    return 1;   /* other families (netlink, route sockets) never leave the machine */
}

static void record(const char *call, const struct sockaddr *sa) {
    const char *path = getenv("ROVARA_NETGUARD_LOG");
    if (path == NULL) return;
    char host[INET6_ADDRSTRLEN] = "?";
    int port = 0;
    if (sa->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, host, sizeof host);
        port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, host, sizeof host);
        port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    }
    char line[256];
    int n = snprintf(line, sizeof line, "%s %s:%d\n", call, host, port);
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
        (void)!write(fd, line, (size_t)n);
        close(fd);
    }
}

static int blocking(void) {
    const char *v = getenv("ROVARA_NETGUARD_BLOCK");
    return v != NULL && v[0] == '1';
}

#ifdef __APPLE__
static int guarded_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    if (!is_loopback(sa)) {
        record("connect", sa);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return connect(fd, sa, len);
}
static ssize_t guarded_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *sa, socklen_t len) {
    if (sa != NULL && !is_loopback(sa)) {
        record("sendto", sa);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return sendto(fd, buf, n, flags, sa, len);
}
static ssize_t guarded_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (msg != NULL && msg->msg_name != NULL && !is_loopback((const struct sockaddr *)msg->msg_name)) {
        record("sendmsg", (const struct sockaddr *)msg->msg_name);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return sendmsg(fd, msg, flags);
}
#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { const void *r; const void *o; } _interpose_##original \
    __attribute__((section("__DATA,__interpose"))) = { (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&original }
INTERPOSE(guarded_connect, connect);
INTERPOSE(guarded_sendto, sendto);
INTERPOSE(guarded_sendmsg, sendmsg);
#else
int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "connect");
    if (!is_loopback(sa)) {
        record("connect", sa);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return real(fd, sa, len);
}
ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *sa, socklen_t len) {
    static ssize_t (*real)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "sendto");
    if (sa != NULL && !is_loopback(sa)) {
        record("sendto", sa);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return real(fd, buf, n, flags, sa, len);
}
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    static ssize_t (*real)(int, const struct msghdr *, int);
    if (!real) real = dlsym(RTLD_NEXT, "sendmsg");
    if (msg != NULL && msg->msg_name != NULL && !is_loopback((const struct sockaddr *)msg->msg_name)) {
        record("sendmsg", (const struct sockaddr *)msg->msg_name);
        if (blocking()) { errno = ENETUNREACH; return -1; }
    }
    return real(fd, msg, flags);
}
#endif
