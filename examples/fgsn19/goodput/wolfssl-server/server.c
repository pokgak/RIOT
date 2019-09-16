/*
 * Copyright (C) 2015 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Demonstrating the server side of TinyDTLS (Simple echo)
 *
 * @author      Raul A. Fuentes Samaniego <ra.fuentes.sam+RIOT@gmail.com>
 * @author      Olaf Bergmann <bergmann@tzi.org>
 * @author      Hauke Mehrtens <hauke@hauke-m.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "net/sock/udp.h"
#include "msg.h"
// #include "tinydtls_keys.h"
#include <wolfssl/ssl.h>

#define ENABLE_DEBUG (1)
#include "debug.h"

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

#define DTLS_STOP_SERVER_MSG 0x4001 /* Custom IPC type msg. */


#define READER_QUEUE_SIZE (8U)

typedef struct {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    sock_udp_t *udp_sock;
    sock_udp_ep_t remote_ep; /* used in send callback */
    uint32_t timeout;
} wolfinfo_t;

/* exp values */
#define INCREMENT (25)
uint16_t packets[(DTLS_MAX_BUF - 100) / INCREMENT];

static uint8_t psk_key_0[] = "secretPSK";

static inline unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;
    (void)key;
    (void)identity;

    key = (unsigned char*)psk_key_0;
    return sizeof(psk_key_0) - 1;
}

static int _send(WOLFSSL* ssl, char* buf, int sz, void* _ctx)
{
    (void)ssl;

    wolfinfo_t *ctx = (wolfinfo_t *)_ctx;
    int ret = 0;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    ret = sock_udp_send(ctx->udp_sock, (unsigned char *)buf, sz, &ctx->remote_ep);
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
    wolfinfo_t *ctx = (wolfinfo_t *)_ctx;
    if (!ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    uint32_t timeout = ctx->timeout;
    if ((timeout != SOCK_NO_TIMEOUT) &&
        (timeout != 0)) {
        timeout = wolfSSL_dtls_get_current_timeout(ssl) * US_PER_SEC;
    }
    // DEBUG("wolfssl timeout: %u\n", timeout);
    ret = sock_udp_recv(ctx->udp_sock, buf, sz, timeout, &ctx->remote_ep);
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

void *start_server(void *arg)
{
    (void)arg;

    static uint8_t buf[DTLS_MAX_BUF];
    wolfinfo_t info;
    XMEMSET(&info, 0, sizeof(wolfinfo_t));
    sock_udp_t udp_socket;
    sock_udp_ep_t remote_ep = SOCK_IPV6_EP_ANY;
    memcpy(&info.remote_ep, &remote_ep, sizeof(sock_udp_ep_t));
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = DTLS_DEFAULT_PORT;

    ssize_t res = sock_udp_create(&udp_socket, &local, NULL, 0);
    if (res == -1) {
        puts("ERROR: Unable create sock.");
        return (void*)NULL;
    }

    void *method = wolfDTLSv1_2_server_method();
    info.ctx = wolfSSL_CTX_new(method);
    if (!info.ctx) {
        printf("failed to create new ctx\n");
        return (void*)NULL;
    }

    info.udp_sock = &udp_socket;


    wolfSSL_CTX_SetIORecv(info.ctx, _recv);
    wolfSSL_CTX_SetIOSend(info.ctx, _send);

    wolfSSL_CTX_set_psk_server_callback(info.ctx, psk_server_cb);
    wolfSSL_CTX_use_psk_identity_hint(info.ctx, "hint");

    info.ssl = NULL;
    info.ssl = wolfSSL_new(info.ctx);
    if (info.ssl == NULL) {
        printf("cannot create new ssl remote\n");
        return (void*)NULL;
    }
    wolfSSL_SetIOReadCtx(info.ssl, &info);
    wolfSSL_SetIOWriteCtx(info.ssl, &info);

    wolfSSL_set_using_nonblock(info.ssl, 0);
    info.timeout = SOCK_NO_TIMEOUT;
    wolfSSL_dtls_set_timeout_max(info.ssl, SOCK_NO_TIMEOUT / US_PER_SEC);
    wolfSSL_dtls_set_timeout_init(info.ssl, SOCK_NO_TIMEOUT / US_PER_SEC);

    // if (wolfSSL_accept(info.ssl) != SSL_SUCCESS) {
    //     printf("failed to accept client\n");
    //     return (void*)NULL;
    // }

    while (1) {
        ssize_t len = wolfSSL_read(info.ssl, buf, sizeof(buf));
        if (len <= 0) {
            printf("failed to read incoming packet\n");
            return (void*)NULL;
        }
        int idx = (len / INCREMENT) - 1;
        packets[idx] = packets[idx] + 1;
    }

    // /* Release resources (strict order) */
    // dtls_free_context(dtls_context);    /* This also sends a DTLS Alert record */
    // sock_udp_close(&udp_socket);
    // msg_reply(&msg, &msg);              /* Basic answer to the main thread */
}


int result_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("BEGIN RESULT\n");
    for (int i = 1; i <= (DTLS_MAX_BUF - 100) / INCREMENT; i++) {
        printf("%d,", i * INCREMENT);
    }
    puts("");
    for (int i = 0; i < (DTLS_MAX_BUF - 100) / INCREMENT; i++) {
        printf("%d,", packets[i]);
    }
    puts("");
    printf("END RESULT\n");
    return 0;
}
