#include "msg.h"
#include "thread.h"

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

typedef struct {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    sock_udp_t udp_sock;
    uint32_t timeout;
} wolfinfo_t;

static wolfinfo_t info = {0};
static sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
static sock_udp_ep_t local = SOCK_IPV6_EP_ANY;

/* exp values */
#define INCREMENT (25)
uint16_t packets[(DTLS_MAX_BUF - 100) / INCREMENT];

static const char psk_key_0[] = "secretPSK";
static const char psk_id_0[] = "Client_identity";

static unsigned psk_client_cb(WOLFSSL* ssl, const char* hint, char* identity,
                              unsigned int id_max_len, unsigned char* key,
                              unsigned int key_max_len)
{
    strncpy(identity, psk_id_0, sizeof(psk_id_0) - 1);
    memcpy(key, psk_key_0, sizeof(psk_key_0) - 1);

    return sizeof(psk_key_0) - 1;   /* length of key in octets or 0 for error */
}

static int _send(WOLFSSL* ssl, char* buf, int sz, void* _ctx)
{
    (void)ssl;

    wolfinfo_t *ctx = (wolfinfo_t *)_ctx;
    int res = 0;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    res = sock_udp_send(&ctx->udp_sock, (unsigned char *)buf, sz, NULL);
    if (res < 0) {
        printf("sock_dtls: send packet failed %d\n", res);
        return -1;
    }
    else if (res == 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return res;
}

/* The GNRC TCP/IP receive callback
 *  return : nb bytes read, or error
 */
static int _recv(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    (void)ssl;

    int res;
    wolfinfo_t *ctx = (wolfinfo_t *)_ctx;
    if (!ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    uint32_t timeout = ctx->timeout;
    if ((timeout != SOCK_NO_TIMEOUT) &&
        (timeout != 0)) {
        timeout = wolfSSL_dtls_get_current_timeout(ssl) * US_PER_SEC;
    }
    // printf("wolfssl timeout: %u\n", timeout);
    res = sock_udp_recv(&ctx->udp_sock, buf, sz, timeout, NULL);
    if (res == 0) {
        /* assume connection close if 0 bytes */
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    else if (res == -ETIMEDOUT) {
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    else if (res < 0) {
        printf("sock_dtls: recv failed %d\n", res);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    /* no error */
    return res;
}

int client_init(const char *addr)
{
    ssize_t res;

    XMEMSET(&info, 0, sizeof(wolfinfo_t));
    info.ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    if (info.ctx == NULL) {
        printf("failed to create new CTX\n");
        return -1;
    }

    wolfSSL_CTX_SetIORecv(info.ctx, _recv);
    wolfSSL_CTX_SetIOSend(info.ctx, _send);

    wolfSSL_CTX_set_psk_client_callback(info.ctx, psk_client_cb);

    ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, addr);
    remote.port = DTLS_DEFAULT_PORT;

    res = sock_udp_create(&info.udp_sock, &local, &remote, 0);
    if (res < 0) {
        puts("Error creating UDP sock");
        return -1;
    }

    info.ssl = NULL;
    info.ssl = wolfSSL_new(info.ctx);
    if (info.ssl == NULL) {
        printf("cannot create new SSL session\n");
        return -1;
    }

    wolfSSL_SetIOReadCtx(info.ssl, &info);
    wolfSSL_SetIOWriteCtx(info.ssl, &info);
    info.timeout = SOCK_NO_TIMEOUT;

    wolfSSL_set_using_nonblock(info.ssl, 0);
    res = wolfSSL_connect(info.ssl);
    if (res != SSL_SUCCESS) {
        printf("sock_dtls: failed to connect\n");
        return -1;
    }

    return 0;
}

int client_send(const char *data, size_t len)
{
    return wolfSSL_write(info.ssl, data, len);
}

void client_close(void)
{
    int res = wolfSSL_shutdown(info.ssl);
    printf("wolfSSL shutdown return: %d\n", res);
    if (res != SSL_SUCCESS) {
        if (res == WOLFSSL_SHUTDOWN_NOT_DONE) {
            /* do a bidirectional shutdown */
            wolfSSL_shutdown(info.ssl);
        }
        else {
            printf("sock_dtls: closing session failed\n");
        }
    }
}
