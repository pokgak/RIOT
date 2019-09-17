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
#include "net/sock/dtls.h"
#include "net/credman.h"

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

#define SOCK_DTLS_SERVER_TAG (10)

static const credman_credential_t credential = {
    .type = CREDMAN_TYPE_PSK,
    .tag = SOCK_DTLS_SERVER_TAG,
    .params = {
        .psk = {
            .key = { .s = (void*)psk_key_0, .len = sizeof(psk_key_0) - 1, },
        },
    },
};

void *start_server(void *arg)
{
    #ifdef TINYDTLS_LOG_LVL
    dtls_set_log_level(TINYDTLS_LOG_LVL);
    #endif

    uint8_t rcv[DTLS_MAX_BUF];
    ssize_t res;
    sock_dtls_session_t session = {0};
    sock_dtls_t sock;
    sock_udp_t udp_sock;
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = DTLS_DEFAULT_PORT;
    sock_udp_create(&udp_sock, &local, NULL, 0);

    res = sock_dtls_create(&sock, &udp_sock, SOCK_DTLS_SERVER_TAG,
                           SOCK_DTLS_1_2, SOCK_DTLS_SERVER);
    if (res < 0) {
        puts("Error creating DTLS sock");
        return 0;
    }

    res = credman_add(&credential);
    if (res < 0) {
        printf("Error cannot add credential to system: %d\n", (int)res);
        return 0;
    }

    while (1) {
        memset(rcv, 0, sizeof(rcv));
        ssize_t len = sock_dtls_recv(&sock, &session, rcv, sizeof(rcv),
                            SOCK_NO_TIMEOUT);
        if (len < 0) {
            if (len != -ETIMEDOUT && len != 0) {
                printf("Error receiving UDP over DTLS %d\n", (int)len);
            }
            sock_dtls_session_destroy(&sock, &session);
            memset(&session, 0, sizeof(sock_dtls_session_t));
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
