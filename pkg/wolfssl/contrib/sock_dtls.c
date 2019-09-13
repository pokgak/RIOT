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
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    // if (wolfSSL_get_using_nonblock(ssl)) {
    //     ctx->timeout = 0;
    // }
    ret = sock_udp_recv(ctx->udp_sock, buf, sz, SOCK_NO_TIMEOUT, &ctx->remote->ep);
    if (ret < 0) {
        printf("sock_dtls: recv failed %d\n", ret);
    }
    // if (ret == -ETIMEDOUT) {
    //     return WOLFSSL_CBIO_ERR_WANT_READ;
    // }
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
        printf("sock_dtls: failed to create remote\n");
    }

    ret = wolfSSL_connect(sock->remote->ssl);
    if (ret != SSL_SUCCESS) {
        printf("sock_dtls: failed to connect\n");
        char buffer[80];
        ret = wolfSSL_get_error(sock->remote->ssl, ret);
        printf("error = %d, %s\n", ret, wolfSSL_ERR_error_string(ret, buffer));
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
    while (ret == SSL_SHUTDOWN_NOT_DONE) {
        xtimer_sleep(1);
        ret = wolfSSL_shutdown(remote->ssl);
    }

    if (ret == SSL_FATAL_ERROR) {
        printf("sock_dtls: session shutdown failed\n");
        int errcode = wolfSSL_get_error(remote->ssl, ret);
        char errstr[30];
        wolfSSL_ERR_error_string(errcode, errstr);
        DEBUG("sock_dtls: %s: %d\n", errstr, errcode);
    }

    /* frees the allocated memory */
    wolfSSL_free(remote->ssl);
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    int ret;

    sock->timeout = timeout;

    if (create_remote(sock, remote) < 0) {
        printf("sock_dtls: failed to create remote\n");
    }

    /* this is done by wolfSSL_read() already */
    // ret = wolfSSL_accept(sock->remote->ssl);
    // if (ret != SSL_SUCCESS) {
    //     DEBUG("sock_dtls: failed to accept new connection\n");
    //     int errcode = wolfSSL_get_error(sock->remote->ssl, ret);
    //     char errstr[30];
    //     wolfSSL_ERR_error_string(errcode, errstr);
    //     DEBUG("sock_dtls: %s: %d\n", errstr, errcode);
    // }

    ret = wolfSSL_read(sock->remote->ssl, data, maxlen);
    if (ret < 0) {
        DEBUG("sock_dtls: read failed %d\n", ret);
    }
    return 0;
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