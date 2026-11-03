#include "tlsio.h"

#include "telegram.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

const char *tls_err(void) {
    static __thread char buf[256];
    unsigned long e = ERR_get_error();
    if (e == 0) return "no openssl error";
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

static SSL_CTX *make_ctx(const SSL_METHOD *method, const char *cert, const char *key, const char *ca) {
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1 ||
        SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

SSL_CTX *tls_server_ctx(const char *cert, const char *key, const char *ca) {
    return make_ctx(TLS_server_method(), cert, key, ca);
}

SSL_CTX *tls_client_ctx(const char *cert, const char *key, const char *ca) {
    return make_ctx(TLS_client_method(), cert, key, ca);
}

void sock_timeouts(int fd, int timeout_ms) {
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

SSL *tls_connect(SSL_CTX *ctx, const char *host, int port, int timeout_ms, int *fd_out) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return NULL;
    }
    sock_timeouts(fd, timeout_ms);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close(fd);
        return NULL;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set1_host(ssl, host);   /* the server certificate must name this host */
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    *fd_out = fd;
    return ssl;
}

static int read_exact(SSL *ssl, char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = SSL_read(ssl, buf + got, (int)(n - got));
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) return got == 0 ? 0 : -1;
        if (e == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
        if ((e == SSL_ERROR_WANT_READ) && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
        if (e == SSL_ERROR_SYSCALL && r == 0) return got == 0 ? 0 : -1;
        return -1;
    }
    return (int)n;
}

int tls_read_frame(SSL *ssl, char *buf, size_t cap) {
    int r = read_exact(ssl, buf, TG_LEN_DIGITS);
    if (r <= 0) return r;
    size_t frame_len;
    if (tg_frame_length(buf, TG_LEN_DIGITS, &frame_len) != TG_OK || frame_len > cap) return -3;
    r = read_exact(ssl, buf + TG_LEN_DIGITS, frame_len - TG_LEN_DIGITS);
    if (r <= 0) return r == 0 ? -1 : r;
    return (int)frame_len;
}

int tls_write_all(SSL *ssl, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int w = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}
