#include "net/sock/dtls.h"
#include "net/credman.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#ifdef MODULE_WOLFSSL_PSK
/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

static unsigned psk_client_cb(WOLFSSL* ssl, const char* hint, char* identity,
                              unsigned int id_max_len, unsigned char* key,
                              unsigned int key_max_len)
{
    sock_dtls_t *ctx = (sock_dtls_t *)ssl->IOCB_ReadCtx;

    credman_credential_t c;
    credman_get(&c, ctx->tag, CREDMAN_TYPE_PSK);
    /* FIXME: ignore id for now */
    // if (id_max_len < c.params.psk.id.len) {
    //     return 0;   /* FIXME: how to signal error? */
    // }
    // strncpy(identity, c.params.psk.id.s, c.params.psk.id.len);

    if (key_max_len < c.params.psk.key.len) {
        return 0;   /* FIXME: how to signal error? */
    }
    memcpy(key, c.params.psk.key.s, c.params.psk.key.len);

    return c.params.psk.key.len;   /* length of key in octets or 0 for error */
}

static unsigned psk_server_cb(WOLFSSL* ssl, const char* identity,
                              unsigned char* key, unsigned int key_max_len)
{
    sock_dtls_t *ctx = (sock_dtls_t *)ssl->IOCB_ReadCtx;

    credman_credential_t c;
    credman_get(&c, ctx->tag, CREDMAN_TYPE_PSK);
    /* FIXME: ignore id for now */
    // if (strncmp(identity, c.params.psk.id.s, c.params.psk.id.len) != 0)
    //     return 0;

    if (key_max_len < c.params.psk.key.len) {
        return 0;   /* FIXME: how to signal error? */
    }
    memcpy(key, c.params.psk.key.s, c.params.psk.key.len);

    return c.params.psk.key.len;   /* length of key in octets or 0 for error */
}
#endif

static int _send(WOLFSSL* ssl, char* buf, int sz, void* _ctx)
{
    (void)ssl;

    sock_dtls_t *ctx = (sock_dtls_t *)_ctx;
    int ret = 0;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    ret = sock_udp_send(ctx->udp_sock, (unsigned char *)buf, sz, &ctx->remote->ep);
    if (ret < 0) {
        DEBUG("sock_dtls: send packet failed %d\n", ret);
        return -1;
    }
    else if (ret == 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return ret;
}

/* The GNRC TCP/IP receive callback
 *  return : nb bytes read, or error
 */
static int _recv(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    (void)ssl;

    int ret;
    sock_dtls_t *ctx = (sock_dtls_t *)_ctx;
    if (!ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    uint32_t timeout = ctx->timeout;
    if ((timeout != SOCK_NO_TIMEOUT) &&
        (timeout != 0)) {
        timeout = wolfSSL_dtls_get_current_timeout(ssl) * US_PER_SEC;
    }
    DEBUG("timeout: %u\n", timeout);
    ret = sock_udp_recv(ctx->udp_sock, buf, sz, timeout, &ctx->remote->ep);
    if (ret == 0) {
        /* assume connection close if 0 bytes */
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    else if (ret == -ETIMEDOUT) {
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    else if (ret < 0) {
        DEBUG("sock_dtls: recv failed %d\n", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    /* no error */
    return ret;
}

void sock_dtls_init(void)
{
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    (void)version;

    assert(sock && udp_sock);
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
    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx) {
        DEBUG("sock_dtls: failed to create new ctx\n");
        return -ENOMEM;
    }

    wolfSSL_CTX_SetIORecv(sock->ctx, _recv);
    wolfSSL_CTX_SetIOSend(sock->ctx, _send);

    switch (role) {
        case SOCK_DTLS_CLIENT:
            wolfSSL_CTX_set_psk_client_callback(sock->ctx, psk_client_cb);
            break;
        case SOCK_DTLS_SERVER:
            wolfSSL_CTX_set_psk_server_callback(sock->ctx, psk_server_cb);
            wolfSSL_CTX_use_psk_identity_hint(sock->ctx, "hint");
            break;
        default:
            DEBUG("sock_dtls: unknown method\n");
            return -1;
    }

    sock->tag = tag;
    sock->udp_sock = udp_sock;
    return 0;
}

/* ep can be NULL for recv */
static int create_remote(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    remote->ssl = wolfSSL_new(sock->ctx);
    if (remote->ssl == NULL) {
        DEBUG("sock_dtls: create new ssl remote failed\n");
        return -ENOMEM;
    }
    wolfSSL_SetIOReadCtx(remote->ssl, sock);
    wolfSSL_SetIOWriteCtx(remote->ssl, sock);
    /* just default to blocking for now */
    wolfSSL_set_using_nonblock(remote->ssl, 0);
    sock->remote = remote;
    return 0;
}

int sock_dtls_session_create(sock_dtls_t *sock, const sock_udp_ep_t *ep,
                             sock_dtls_session_t *remote)
{
    (void)sock;
    (void)ep;
    (void)remote;

    int ret;

    if (!sock->ctx || !remote) {
        return -EINVAL;
    }

    XMEMCPY(&remote->ep, ep, sizeof(sock_udp_ep_t));
    if (create_remote(sock, remote) < 0) {
        DEBUG("sock_dtls: failed to create remote\n");
    }

    /* no timeout for handshake */
    sock->timeout = SOCK_NO_TIMEOUT;
    
    ret = wolfSSL_connect(sock->remote->ssl);
    if (ret != SSL_SUCCESS) {
        DEBUG("sock_dtls: failed to connect\n");
        return -1;
    }

    /* FIXME: may need to block here */
    return 0;
}

void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    (void)sock;
    int ret;

    /* sends a "close notify" to remote */
    ret = wolfSSL_shutdown(remote->ssl);
    DEBUG("wolfSSL shutdown return: %d\n", ret);
    if (ret != SSL_SUCCESS) {
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
            /* do a bidirectional shutdown */
            wolfSSL_shutdown(remote->ssl);
        }
        else {
            DEBUG("sock_dtls: closing session failed\n");
        }
    }

    /* frees the allocated memory */
    wolfSSL_free(remote->ssl);
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    int ret;

    /* only create new remote if no existing session exists */
    if ((remote->ssl == NULL) && (create_remote(sock, remote) < 0)) {
        DEBUG("sock_dtls: failed to create remote\n");
    }

    if (timeout == 0) {
        wolfSSL_set_using_nonblock(remote->ssl, 1);
        sock->timeout = 0;
    }
    else {
        wolfSSL_set_using_nonblock(remote->ssl, 0);
        sock->timeout = timeout;
        wolfSSL_dtls_set_timeout_init(remote->ssl, timeout * US_PER_SEC);
    }

    DEBUG("sock_dtls_recv: timeout: %u\n", sock->timeout);
    ret = wolfSSL_read(remote->ssl, data, maxlen);
    if (ret < 0) {
        DEBUG("sock_dtls: read failed %d\n", ret);

        char buffer[WOLFSSL_MAX_ERROR_SZ];
        int err = wolfSSL_get_error(remote->ssl, ret);
        wolfSSL_ERR_error_string(err, buffer);
        DEBUG("wolfSSL error: %d: %s\n", err, buffer);
        return ret;
    }
    // FIXME: adjust return value to API given values
    return ret;
}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{
    DEBUG("sock_dtls: entered sock_dtls_send()\n");

    if (!remote->ssl) {
        if (create_remote(sock, remote) < 0) {
            DEBUG("sock_dtls: failed to create remote\n");
            return -1;
        }
    }
    return wolfSSL_write(remote->ssl, data, len);
}

void sock_dtls_close(sock_dtls_t *sock)
{
    wolfSSL_CTX_free(sock->ctx);
}