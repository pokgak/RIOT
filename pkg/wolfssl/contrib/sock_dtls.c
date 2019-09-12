#include "net/sock/dtls.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

void sock_dtls_init(void)
{
    /* nothing to do */
}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    (void)sock;
    (void)udp_sock;
    (void)tag;
    (void)version;
    (void)role;

    if (!sock || !udp_sock) {
        return -EINVAL;
    }

    XMEMSET(sock, 0, sizeof(sock_dtls_t));

    // FIXME: use version and role instead of hardcode
    sock->wolfssl.ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    if (!sock->wolfssl.ctx) {
        return -ENOMEM;
    }

    memcpy(&sock->wolfssl.conn.udp, udp_sock, sizeof(*udp_sock));
    return 0;
}

int sock_dtls_session_create(sock_dtls_t *sock, const sock_udp_ep_t *ep,
                             sock_dtls_session_t *remote)
{
    (void)sock;
    (void)ep;
    (void)remote;

    if (sock->wolfssl.ctx) {
        return -EINVAL;
    }
    sock->wolfssl.ssl = wolfSSL_new(sock->wolfssl.ctx);
    if (sock->wolfssl.ssl == NULL) {
        DEBUG("Error allocatin ssl session\n");
        return -ENOMEM;
    }
    else {
        wolfSSL_SetIOReadCtx(sock->wolfssl.ssl, &sock->wolfssl);
        wolfSSL_SetIOWriteCtx(sock->wolfssl.ssl, &sock->wolfssl);
        sock->wolfssl.ssl->gnrcCtx = &sock->wolfssl;
        return 0;
    }
}

void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    (void)sock;
    (void)remote;
    wolfSSL_free(sock->wolfssl.ssl);
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    (void)sock;
    (void)remote;
    (void)data;
    (void)maxlen;
    (void)timeout;

    wolfSSL_dtls_set_timeout_init(sock->wolfssl.ssl, timeout / US_PER_SEC);
    return wolfSSL_read(sock->wolfssl.ssl, data, maxlen);
}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{
    (void)sock;
    (void)remote;
    (void)data;
    (void)len;

    XMEMCPY(&sock->wolfssl.peer_addr, &remote->ep, sizeof(sock_udp_ep_t));
    return wolfSSL_write(sock->wolfssl.ssl, data, len);
}

void sock_dtls_close(sock_dtls_t *sock)
{
    (void)sock;
    /* nothing to do */
}