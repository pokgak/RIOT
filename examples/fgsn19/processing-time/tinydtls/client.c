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
 * @brief       Demonstrating the client side of TinyDTLS
 *
 * @author      Raul A. Fuentes Samaniego <raul.fuentes-samaniego@inria.fr>
 * @author      Olaf Bergmann <bergmann@tzi.org>
 * @author      Hauke Mehrtens <hauke@hauke-m.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "xtimer.h"
#include "net/sock/udp.h"
#include "tinydtls_keys.h"

/* TinyDTLS */
#include "dtls_debug.h"
#include "dtls.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

#define CLIENT_PORT DTLS_DEFAULT_PORT + 1
#define MAX_TIMES_TRY_TO_SEND 10 /* Expected to be 1 - 255 */

/* Delay to give time to the remote peer to do the compute (client only). */
#ifdef DTLS_ECC
#define DEFAULT_US_DELAY 100
#else
#define DEFAULT_US_DELAY 100
#endif

static sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
static sock_udp_ep_t remote_ep = SOCK_IPV6_EP_ANY;
static sock_udp_t sock_udp;
static session_t session;
static dtls_context_t *dtls_context = NULL;

static mbox_t mbox;
static msg_t mbox_queue[16];

/* experiment values */
static uint32_t session_start = 0;
static uint32_t session_time = 0;
static int session_count = 0;

/* TinyDTLS callback for detecting the state of the DTLS channel. */
static int _events_handler(struct dtls_context_t *ctx,
                           session_t *session,
                           dtls_alert_level_t level,
                           unsigned short code)
{
    (void) ctx;
    (void) session;
    (void) level;

    if (code == DTLS_EVENT_CONNECTED) {
        DEBUG("CLIENT: event CONNECTED\n");
        session_time += xtimer_now_usec() - session_start;
        session_count++;

        msg_t msg = { .type = code };
        mbox_put(&mbox, &msg);
    }
    /* At least a DTLS Client Hello was prepared? */
    else if (code == DTLS_EVENT_CONNECT) {
        DEBUG("CLIENT: event CONNECT\n");
        session_start = xtimer_now_usec();
    }
    else {
        printf("Unknown event code: %d; alert level: %d\n", code, level);
    }

    /* NOTE: DTLS_EVENT_RENEGOTIATE can be handled here */

    return 0;
}

/*
 * Handles all the packets arriving at the node and identifies those that are
 * DTLS records. Also, it determines if said DTLS record is coming from a new
 * peer or a currently established peer.
 *
 */
static void dtls_handle_read(dtls_context_t *ctx)
{
    static session_t session;
    static sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
    uint8_t packet_rcvd[256];

    if (!ctx) {
        DEBUG("%s: No DTLS context\n", __func__);
        return;
    }

    if (!dtls_get_app_data(ctx)) {
        DEBUG("%s: No app_data stored!\n", __func__);
        return;
    }

    sock_udp_t *sock;
    sock =  (sock_udp_t *)dtls_get_app_data(ctx);


    if (sock_udp_get_remote(sock, &remote) == -ENOTCONN) {
        DEBUG("%s: Unable to retrieve remote!\n", __func__);
        return;
    }

    ssize_t res = sock_udp_recv(sock, packet_rcvd, sizeof(packet_rcvd),
                                1 * US_PER_SEC + DEFAULT_US_DELAY,
                                &remote);

    if (res <= 0) {
        if ((ENABLE_DEBUG) && (res != -EAGAIN) && (res != -ETIMEDOUT)) {
            DEBUG("sock_udp_recv unexepcted code error: %i\n", (int)res);
        }
        return;
    }

    /* session requires the remote socket (IPv6:UDP) address and netif  */
    session.size = sizeof(uint8_t) * 16 + sizeof(unsigned short);
    session.port = remote.port;
    if (remote.netif == SOCK_ADDR_ANY_NETIF) {
        session.ifindex = SOCK_ADDR_ANY_NETIF;
    }
    else {
        session.ifindex = remote.netif;
    }

    if (memcpy(&session.addr, &remote.addr.ipv6, 16) == NULL) {
        puts("ERROR: memcpy failed!");
        return;
    }

    dtls_handle_message(ctx, &session, packet_rcvd, sizeof(packet_rcvd));
}

#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

/*
 * This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session.
 */
static int _peer_get_psk_info_handler(struct dtls_context_t *ctx,
                                      const session_t *session,
                                      dtls_credentials_type_t type,
                                      const unsigned char *id, size_t id_len,
                                      unsigned char *result, size_t result_length)
{
    (void) ctx;
    (void) session;

    switch (type) {
        case DTLS_PSK_IDENTITY:
            if (id_len) {
                dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
            }

            if (result_length < psk_id_length) {
                dtls_warn("cannot set psk_identity -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_id, psk_id_length);
            return psk_id_length;
        case DTLS_PSK_KEY:
            if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
                dtls_warn("PSK for unknown id requested, exiting\n");
                return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
            }
            else if (result_length < psk_key_length) {
                dtls_warn("cannot set psk -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_key, psk_key_length);
            return psk_key_length;
        default:
            dtls_warn("unsupported request type: %d\n", type);
    }

    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int _peer_get_ecdsa_key_handler(struct dtls_context_t *ctx,
                                       const session_t *session,
                                       const dtls_ecdsa_key_t **result)
{
    (void) ctx;
    (void) session;

    /* TODO: Load the key from external source */

    static const dtls_ecdsa_key_t ecdsa_key = {
        .curve = DTLS_ECDH_CURVE_SECP256R1,
        .priv_key = ecdsa_priv_key,
        .pub_key_x = ecdsa_pub_key_x,
        .pub_key_y = ecdsa_pub_key_y
    };

    *result = &ecdsa_key;
    return 0;
}

static int _peer_verify_ecdsa_key_handler(struct dtls_context_t *ctx,
                                          const session_t *session,
                                          const unsigned char *other_pub_x,
                                          const unsigned char *other_pub_y,
                                          size_t key_size)
{
    (void) ctx;
    (void) session;
    (void) other_pub_y;
    (void) other_pub_x;
    (void) key_size;

    /* TODO: As far for tinyDTLS 0.8.2 this is not used */

    return 0;
}
#endif /* DTLS_ECC */

/* Reception of a DTLS Application data record. */
static int _read_from_peer_handler(struct dtls_context_t *ctx,
                                   session_t *session,
                                   uint8 *data, size_t len)
{
    (void) ctx;
    (void) session;

    printf("Client: got DTLS Data App -- ");
    for (size_t i = 0; i < len; i++)
        printf("%c", data[i]);
    puts(" --");

    /*
     * NOTE: To answer the other peer uses dtls_write(). E.g.
     * return dtls_write(ctx, session, data, len);
     */

    return 0;
}

/* Handles the DTLS communication with the other peer. */
static int _send_to_peer_handler(struct dtls_context_t *ctx,
                                 session_t *session, uint8 *buf, size_t len)
{
    (void) session;

    assert(ctx);
    assert(dtls_get_app_data(ctx));

    if (!dtls_get_app_data(ctx)) {
        return -1; /* At this point this should not happen anymore. */
    }

    sock_udp_t *sock;
    sock = (sock_udp_t *)dtls_get_app_data(ctx);

    printf("%lu,", (long unsigned)xtimer_now_usec());
    ssize_t res = sock_udp_send(sock, buf, len, NULL);
    if (res <= 0) {
        puts("ERROR: Unable to send DTLS record");
    }

    return res;
}

static dtls_handler_t cb = {
    .write = _send_to_peer_handler,
    .read = _read_from_peer_handler,
    .event = _events_handler,
#ifdef DTLS_PSK
    .get_psk_info = _peer_get_psk_info_handler,
#endif  /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = _peer_get_ecdsa_key_handler,
    .verify_ecdsa_key = _peer_verify_ecdsa_key_handler
#endif  /* DTLS_ECC */
};

/* Transmits the upper layer data data in one or more DTLS Data App records . */
static ssize_t try_send(uint8_t *buf, size_t len)
{
    int res = dtls_write(dtls_context, &session, buf, len);
    if (res >= 0) {
        memmove(buf, buf + res, len - res);
        len -= res;
        return len;
    }
    else {
        dtls_crit("Client: dtls_write returned error: %d!\n", res);
        return -1;
    }
}

int client_init(char *addr_str)
{
    dtls_init();
    #ifdef TINYDTLS_LOG_LVL
    dtls_set_log_level(TINYDTLS_LOG_LVL);
    #endif
    mbox_init(&mbox, mbox_queue, sizeof(mbox_queue) / sizeof(mbox_queue[0]));

    /* First, we prepare the UDP Sock */
    local_ep.port = (unsigned short) CLIENT_PORT;
    remote_ep.port = (unsigned short) DTLS_DEFAULT_PORT;

    /* Parsing <address>[:<iface>]:Port */
    int iface = ipv6_addr_split_iface(addr_str);
    if (iface == -1) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            session.ifindex = (uint16_t)gnrc_netif_iter(NULL)->pid;
            remote_ep.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            /* FIXME This probably is not valid with multiple interfaces */
            session.ifindex = remote_ep.netif;
        }
    }
    else {
        if (gnrc_netif_get_by_pid(iface) == NULL) {
            puts("ERROR: interface not valid");
            return -1;
        }
        session.ifindex = (uint16_t)gnrc_netif_iter(NULL)->pid;
        remote_ep.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
    }

    if (ipv6_addr_from_str((ipv6_addr_t *)remote_ep.addr.ipv6, addr_str) == NULL) {
        puts("ERROR: unable to parse destination address");
        return -1;
    }

    /* Second: We prepare the DTLS Session by means of ctx->app */
    session.size = sizeof(uint8_t) * 16 + sizeof(unsigned short);
    session.port = remote_ep.port;

    /* NOTE: remote.addr.ipv6 and dst->addr are different structures. */
    if (ipv6_addr_from_str(&session.addr, addr_str) == NULL) {
        puts("ERROR: init_dtls was unable to load the IPv6 addresses!");
        return -1;
    }

    /* The sock must be opened with the remote already linked to it */
    if (sock_udp_create(&sock_udp, &local_ep, &remote_ep, 0) != 0) {
        puts("ERROR: Unable to create UDP sock");
        return -1;
    }

    dtls_context = dtls_new_context(&sock_udp);
    if (dtls_context) {
        dtls_set_handler(dtls_context, &cb);
    }
    else {
        puts("ERROR: Client unable to load context!");
        return -1;
    }

    /*
     * Starts the DTLS handshake process by sending the first DTLS Hello Client
     * record.
     *
     * NOTE: If dtls_connect() returns zero, then the DTLS channel for the
     *      dtls_context is already created (never the case for this example)
     */
    if (dtls_connect(dtls_context, &session) < 0) {
        puts("ERROR: Client unable to start a DTLS channel!\n");
        return -1;
    }

    msg_t msg;
    while (!mbox_try_get(&mbox, &msg) ||
            msg.type != DTLS_EVENT_CONNECTED) {
        dtls_handle_read(dtls_context);
    }
    return 0;
}

int client_send(char *data, size_t len)
{
    ssize_t app_data_buf = len;               /* Upper layer packet to send */
    if (len > DTLS_MAX_BUF - 100) {
        puts("ERROR: Exceeded max size of DTLS buffer.");
        return -1;
    }
    DEBUG("Sending (upper layer) data\n");
    app_data_buf = try_send((uint8_t *)data, len);
    if (app_data_buf < 0) {
        puts("error sending packet");
        return -1;
    }
    else if (app_data_buf != 0 && (size_t)app_data_buf != len) {
        printf("WARN: only %u from %u is sent\n", app_data_buf, len);
    }

    return 0;
}

void client_close(void)
{
    dtls_close(dtls_context, &session);
    dtls_free_context(dtls_context); /* This also sends a DTLS Alert record */
    sock_udp_close(&sock_udp);
}

// int exp_cmd(int argc, char **argv)
// {
//     (void) argc;
//     (void) argv;

//     if (strcmp(argv[1], "session") == 0) {
//         /* init session handshake */
//         int expcount = atoi(argv[2]);
//         for (int i = 0; i < expcount; i++) {
//             client_init(&dtls_context, SERVER_ADDR);
//             dtls_close(dtls_context, &session);
//             dtls_free_context(dtls_context); /* This also sends a DTLS Alert record */
//             sock_udp_close(&sock_udp);
//             xtimer_sleep(1);
//         }

//         printf("session count: %d; session time total: %lu\n", session_count, (long unsigned)session_time);
//         session_time = 0;
//         session_count = 0;
//     }
//     else if (strcmp(argv[1], "run") == 0) {
//         client_init(&dtls_context, SERVER_ADDR);
//         if (dtls_connected == 0) {
//             puts("Client not connected");
//             return -1;
//         }
// #define PAYLOAD_SIZE 300
//         for (int i = 0; i < PAYLOAD_SIZE / 50; i++) {
//             char data[PAYLOAD_SIZE];  // TODO: generate test data
//             size_t len2send = (i + 1) * 50;
//             uint32_t start = xtimer_now_usec();
//             client_send(dtls_context, data, len2send);
//             printf("count = %d; size: %u; time: %lu\n", packets_sent, len2send,(long unsigned)xtimer_now_usec() - start);
//         }
//         // printf("total time: %lu; packets sent: %lu\n", (long unsigned)total_time, (long unsigned)packets_sent);
//         dtls_close(dtls_context, &session);
//         dtls_free_context(dtls_context); /* This also sends a DTLS Alert record */
//         sock_udp_close(&sock_udp);
//     }
//     else {
//         puts("Unknown command");
//     }

//     return 0;
// }
