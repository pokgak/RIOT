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
#include "../tinydtls_keys.h"

/* TinyDTLS */
#include "dtls_debug.h"
#include "dtls.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#ifndef SERVER_ADDR
#define SERVER_ADDR "fe80::7b76:7968:5ef6:617a"
// #define SERVER_ADDR "fe80::6813:98ff:fe97:ab67"
#endif

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

static int dtls_connected = 0; /* This is handled by Tinydtls callbacks */

static sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
static sock_udp_ep_t remote_ep = SOCK_IPV6_EP_ANY;
static sock_udp_t sock_udp;
static session_t server_dst;
static dtls_context_t *dtls_context = NULL;

static mbox_t mbox;
static msg_t mbox_queue[10];

/* experiment values */
static uint32_t session_start = 0;
static uint32_t session_time = 0;
static int session_count = 0;
static int packets_sent = 0;

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
        dtls_connected = 1;

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
    uint8_t packet_rcvd[DTLS_MAX_BUF];

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

    ssize_t res = sock_udp_recv(sock, packet_rcvd, DTLS_MAX_BUF,
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

// #if ENABLE_DEBUG
//         DEBUG("DBG-Client: Msg received from \n\t Addr Src: [");
//         ipv6_addr_print(&session.addr);
//         DEBUG("]:%u\n", remote.port);
// #endif

    dtls_handle_message(ctx, &session, packet_rcvd, (int)DTLS_MAX_BUF);

    return;
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

/* Transmits the upper layer data data in one or more DTLS Data App records . */
ssize_t try_send(struct dtls_context_t *ctx, session_t *dst, uint8 *buf, size_t len)
{
    int res = 0;

    res = dtls_write(ctx, dst, buf, len);

    if (res >= 0) {
        memmove(buf, buf + res, len - res);
        len -= res;
        return len;
    }
    else if (res < 0) {
        dtls_crit("Client: dtls_write returned error!\n");
        printf("Client: dtls_write returned error %d\n", res);
        return -1;
    }

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

static void client_init(dtls_context_t **ctx, char *addr_str)
{
    mbox_init(&mbox, mbox_queue, sizeof(mbox_queue) / sizeof(mbox_queue[0]));

    /* NOTE: dtls_init() must be called previous to this (see main.c) */
    dtls_connected = 0;

#ifdef TINYDTLS_LOG_LVL
    dtls_set_log_level(TINYDTLS_LOG_LVL);
#endif

    /* First, we prepare the UDP Sock */
    local_ep.port = (unsigned short) CLIENT_PORT;
    remote_ep.port = (unsigned short) DTLS_DEFAULT_PORT;

    /* Parsing <address>[:<iface>]:Port */
    int iface = ipv6_addr_split_iface(addr_str);
    if (iface == -1) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            server_dst.ifindex = (uint16_t)gnrc_netif_iter(NULL)->pid;
            remote_ep.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            /* FIXME This probably is not valid with multiple interfaces */
            server_dst.ifindex = remote_ep.netif;
        }
    }
    else {
        if (gnrc_netif_get_by_pid(iface) == NULL) {
            puts("ERROR: interface not valid");
            return;
        }
        server_dst.ifindex = (uint16_t)gnrc_netif_iter(NULL)->pid;
        remote_ep.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
    }

    if (ipv6_addr_from_str((ipv6_addr_t *)remote_ep.addr.ipv6, addr_str) == NULL) {
        puts("ERROR: unable to parse destination address");
        return;
    }

    /* Second: We prepare the DTLS Session by means of ctx->app */
    server_dst.size = sizeof(uint8_t) * 16 + sizeof(unsigned short);
    server_dst.port = remote_ep.port;

    /* NOTE: remote.addr.ipv6 and dst->addr are different structures. */
    if (ipv6_addr_from_str(&server_dst.addr, addr_str) == NULL) {
        puts("ERROR: init_dtls was unable to load the IPv6 addresses!");
        return;
    }

    /* The sock must be opened with the remote already linked to it */
    if (sock_udp_create(&sock_udp, &local_ep, &remote_ep, 0) != 0) {
        puts("ERROR: Unable to create UDP sock");
        return;
    }

    *ctx = dtls_new_context(&sock_udp);
    if (*ctx) {
        dtls_set_handler(*ctx, &cb);
    }
    else {
        puts("ERROR: Client unable to load context!");
        return;
    }

    /*
     * Starts the DTLS handshake process by sending the first DTLS Hello Client
     * record.
     *
     * NOTE: If dtls_connect() returns zero, then the DTLS channel for the
     *      dtls_context is already created (never the case for this example)
     */
    if (dtls_connect(*ctx, &server_dst) < 0) {
        puts("ERROR: Client unable to start a DTLS channel!\n");
        return;
    }

    msg_t msg;
    while (!mbox_try_get(&mbox, &msg) ||
            msg.type != DTLS_EVENT_CONNECTED) {
        dtls_handle_read(*ctx);
    }
}

static void client_send(dtls_context_t *ctx, char *data, size_t len)
{
    // uint8_t watch = MAX_TIMES_TRY_TO_SEND;
    ssize_t app_data_buf = len;               /* Upper layer packet to send */


    char *client_payload;
    if (strlen(data) > DTLS_MAX_BUF) {
        puts("ERROR: Exceeded max size of DTLS buffer.");
        return;
    }
    client_payload = data;

    /*
     * This loop transmits all the DTLS records involved in the DTLS session.
     * Including the real (upper) data to send and to receive. There is a
     * watchdog if the remote peer stop answering.
     *
     * Max lifetime expected for a DTLS handshake is 10 sec. This is reflected
     * with the variable watch and the timeout for sock_udp_recv().
     *
     * NOTE: DTLS Sessions can handles more than one single node but by
     *       default is limited to a single peer with a single context and
     *       a single concurrent handshake.
     *       See tinydtls/platform-specific/riot_boards.h for more info.
     * NOTE: DTLS_DEFAULT_MAX_RETRANSMIT has an impact here.
     */
    // while (app_data_buf > 0) {

        /*  DTLS Session must be established before sending our data */
        if (dtls_connected) {
            DEBUG("Sending (upper layer) data\n");
            app_data_buf = try_send(ctx, &server_dst,
                                    (uint8 *)client_payload, app_data_buf);
            if (app_data_buf == 0) {
                packets_sent++;
            }
        }

        // /* Check if a DTLS record was received */
        // /* NOTE: We expect an answer after try_send() */
        // dtls_handle_read(dtls_context);
        // watch--;
    // } /* END while */

    /*
     * BUG: tinyDTLS (<= 0.8.6)
     * If dtls_connect() is called but the handshake does not complete (e.g.
     * peer is offline) then a netq_t object is allocated and never freed
     * leaving a memory leak of 124 bytes.
     * This can lead to "retransmit buffer full" error.
     *
     * A temporary solution is to make the dtls_context_t global and be sure
     * to never release it. Alternatively, never let this part of the code
     * ends, in a similar approach to the server side.
     */

    /* Release resources (strict order!) */
    // dtls_free_context(ctx); /* This also sends a DTLS Alert record */
    // sock_udp_close(&sock_udp);
    // dtls_connected = 0;
    DEBUG("Client DTLS send finished\n");

    return;
}

int exp_cmd(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    if (strcmp(argv[1], "session") == 0) {
        /* init session handshake */
        int expcount = atoi(argv[2]);
        for (int i = 0; i < expcount; i++) {
            client_init(&dtls_context, SERVER_ADDR);
            dtls_close(dtls_context, &server_dst);
            dtls_free_context(dtls_context); /* This also sends a DTLS Alert record */
            sock_udp_close(&sock_udp);
            xtimer_sleep(1);
        }

        printf("session count: %d; session time total: %lu\n", session_count, (long unsigned)session_time);
        session_time = 0;
        session_count = 0;
    }
    else if (strcmp(argv[1], "run") == 0) {
        client_init(&dtls_context, SERVER_ADDR);
        if (dtls_connected == 0) {
            puts("Client not connected");
            return -1;
        }
        uint32_t total_time = 0;
#define PAYLOAD_SIZE  (50)
#define PACKET_COUNT  (5000)
        for (int i = 0; i < PACKET_COUNT; i++) {
            char data[PAYLOAD_SIZE];  // TODO: generate test data
            uint32_t start = xtimer_now_usec();
            client_send(dtls_context, data, sizeof(data));
            uint32_t time = xtimer_now_usec() - start;
            total_time += time;
            // (c)ount, (s)ize, (t)ime
            printf("c %d s %u t %lu\n", i + 1,sizeof(data), (long unsigned)time);
        }
        // (t)otal (t)ime
        printf("tt %lu\n", (long unsigned)total_time);
        dtls_close(dtls_context, &server_dst);
        dtls_free_context(dtls_context); /* This also sends a DTLS Alert record */
        sock_udp_close(&sock_udp);
    }
    else {
        puts("Unknown command");
    }

    return 0;
}
