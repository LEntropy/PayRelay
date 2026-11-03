/*
 * Mutual TLS between the PG gateway and the VAN. Both sides present a certificate signed
 * by the same private CA and refuse peers without one, the way dedicated PG-VAN links are
 * authenticated in practice.
 */
#ifndef PAYRELAY_TLSIO_H
#define PAYRELAY_TLSIO_H

#include <stddef.h>
#include <openssl/ssl.h>

SSL_CTX *tls_server_ctx(const char *cert, const char *key, const char *ca);
SSL_CTX *tls_client_ctx(const char *cert, const char *key, const char *ca);

/* Connects and completes the handshake, verifying the server name. NULL on failure. */
SSL *tls_connect(SSL_CTX *ctx, const char *host, int port, int timeout_ms, int *fd_out);

/* Sets SO_RCVTIMEO/SO_SNDTIMEO on a socket (0 = no timeout). */
void sock_timeouts(int fd, int timeout_ms);

/*
 * Reads one complete telegram frame. Returns its length, 0 on orderly close, -1 on error,
 * -2 on timeout, -3 if the peer sent something that is not a valid frame length.
 */
int tls_read_frame(SSL *ssl, char *buf, size_t cap);
int tls_write_all(SSL *ssl, const char *buf, size_t len);

/* Last OpenSSL error as text, for logs. */
const char *tls_err(void);

#endif
