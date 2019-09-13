#include "net/sock/dtls.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

void sock_dtls_init(void)
{
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    (void)sock;
    (void)udp_sock;
    (void)tag;
    (void)version;
    (void)role;

    XMEMSET(sock, 0, sizeof(sock_dtls_t));

    // FIXME: use version and role instead of hardcode
    void *method = NULL;
    switch (role) {
        case SOCK_DTLS_CLIENT: method = wolfDTLSv1_2_client_method(); break;
        case SOCK_DTLS_SERVER: method = wolfDTLSv1_2_server_method(); break;
        default:
            DEBUG("sock_dtls: unknown method\n");
            return -1;
    }
    sock->wolfssl.ctx = wolfSSL_CTX_new(method);
    if (!sock->wolfssl.ctx) {
        DEBUG("sock_dtls: failed to create new ctx\n");
        return -ENOMEM;
    }

    memcpy(&sock->wolfssl.conn.udp, udp_sock, sizeof(sock_udp_t));
    return 0;
}

int sock_dtls_session_create(sock_dtls_t *sock, const sock_udp_ep_t *ep,
                             sock_dtls_session_t *remote)
{
    (void)sock;
    (void)ep;
    (void)remote;

    int ret;

    if (sock->wolfssl.ctx) {
        return -EINVAL;
    }

    XMEMCPY(&sock->wolfssl.peer_addr, remote, sizeof(sock_udp_ep_t));
    sock->wolfssl.ssl = wolfSSL_new(sock->wolfssl.ctx);
    if (sock->wolfssl.ssl == NULL) {
        DEBUG("Error allocatin ssl session\n");
        return -ENOMEM;
    }
    wolfSSL_SetIOReadCtx(sock->wolfssl.ssl, &sock->wolfssl);
    wolfSSL_SetIOWriteCtx(sock->wolfssl.ssl, &sock->wolfssl);
    sock->wolfssl.ssl->gnrcCtx = &sock->wolfssl;
    if (wolfSSL_get_using_nonblock(sock->wolfssl.ssl) != 0) {
        DEBUG("sock_dtls: set to use blocking IO\n");
        wolfSSL_set_using_nonblock(sock->wolfssl.ssl, 0);
    }

    ret = wolfSSL_connect(sock->wolfssl.ssl);
    if (ret != SSL_SUCCESS) {
        printf("sock_dtls: failed to connect\n");
        return -1;
    }
    return 0;
}

void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    (void)sock;
    (void)remote;
    int ret = wolfSSL_shutdown(sock->wolfssl.ssl);
    if (ret != SSL_SUCCESS) {
        printf("sock_dtls: session destroy failed\n");
        int errcode = wolfSSL_get_error(sock->wolfssl.ssl, ret);
        char errstr[30];
        wolfSSL_ERR_error_string(errcode, errstr);
        DEBUG("sock_dtls: %s: %d\n", errstr, errcode);
    }
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    (void)sock;
    (void)remote;
    (void)data;
    (void)maxlen;
    (void)timeout;

    int ret;
    sock->wolfssl.ssl = wolfSSL_new(sock->wolfssl.ctx);
    if (sock->wolfssl.ssl == NULL) {
        printf("sock_dtls: failed to create session\n");
        return -1;
    }
    wolfSSL_SetIOReadCtx(sock->wolfssl.ssl, &sock->wolfssl);
    wolfSSL_SetIOWriteCtx(sock->wolfssl.ssl, &sock->wolfssl);
    sock->wolfssl.ssl->gnrcCtx = &sock->wolfssl;

    ret = wolfSSL_accept(sock->wolfssl.ssl);
    if (ret != SSL_SUCCESS) {
        DEBUG("sock_dtls: failed to accept new connection\n");
        int errcode = wolfSSL_get_error(sock->wolfssl.ssl, ret);
        char errstr[30];
        wolfSSL_ERR_error_string(errcode, errstr);
        DEBUG("sock_dtls: %s: %d\n", errstr, errcode);
    }
    // wolfSSL_dtls_set_timeout_init(sock->wolfssl.ssl, timeout / US_PER_SEC);
    ret = wolfSSL_read(sock->wolfssl.ssl, data, maxlen);
    if (ret < 0) {
        DEBUG("sock_dtls: read failed %d\n", ret);
    }
    return 0;
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