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
#include "tinydtls_keys.h"

/* TinyDTLS */
#include "dtls.h"
#include "dtls_debug.h"
#include "tinydtls.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

#define DTLS_STOP_SERVER_MSG 0x4001 /* Custom IPC type msg. */

/*
 * This structure will be used for storing the sock and the remote into the
 * dtls_context_t variable.
 *
 * This is because remote must not have port set to zero on sock_udp_create()
 * making impossible to recover the remote with sock_udp_get_remote()
 *
 * An alternative is to modify dtls_handle_message () to receive the remote
 * from sock_udp_recv(). Also, it's required to modify _send_to_peer_handler()  for
 * parsing an auxiliary sock_udp_ep_t variable from the dls session.
 */
typedef struct {
    sock_udp_t *sock;
    sock_udp_ep_t *remote;
} dtls_remote_peer_t;

#define READER_QUEUE_SIZE (8U)

/*  NOTE: Temporary patch for tinyDTLS 0.8.6 */
#ifndef TINYDTLS_EXTRA_BUFF
#define TINYDTLS_EXTRA_BUFF (0U)
#endif

/* exp values */
#define INCREMENT (25)
uint16_t packets[(DTLS_MAX_BUF - 100) / INCREMENT];
static int session_established = 0;

static int _read_from_peer_handler(struct dtls_context_t *ctx,
                                   session_t *session, uint8 *data, size_t len);
static int _send_to_peer_handler(struct dtls_context_t *ctx,
                                 session_t *session, uint8 *buf, size_t len);
static int _handle_event(struct dtls_context_t *ctx, session_t *session,
                         dtls_alert_level_t level, unsigned short code);
#ifdef DTLS_PSK
static int _peer_get_psk_info_handler(struct dtls_context_t *ctx, const session_t *session,
                                      dtls_credentials_type_t type,
                                      const unsigned char *id, size_t id_len,
                                      unsigned char *result, size_t result_length);
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
static int _peer_get_ecdsa_key_handler(struct dtls_context_t *ctx,
                                       const session_t *session,
                                       const dtls_ecdsa_key_t **result);
static int _peer_verify_ecdsa_key_handler(struct dtls_context_t *ctx,
                                          const session_t *session,
                                          const unsigned char *other_pub_x,
                                          const unsigned char *other_pub_y,
                                          size_t key_size);
#endif /* DTLS_ECC */

static dtls_handler_t cb = {
    .write = _send_to_peer_handler,
    .read = _read_from_peer_handler,
    .event = _handle_event,
#ifdef DTLS_PSK
    .get_psk_info = _peer_get_psk_info_handler,
#endif  /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = _peer_get_ecdsa_key_handler,
    .verify_ecdsa_key = _peer_verify_ecdsa_key_handler
#endif  /* DTLS_ECC */
};

/*
 * Handles all the packets arriving at the node and identifies those that are
 * DTLS records. Also, it determines if said DTLS record is coming from a new
 * peer or a currently established peer.
 */
static void dtls_handle_read(dtls_context_t *ctx)
{
    static session_t session;
    static uint8_t packet_rcvd[DTLS_MAX_BUF];

    assert(ctx);
    assert(dtls_get_app_data(ctx));

    if (!ctx) {
        DEBUG("No DTLS context!\n");
        return;
    }

    if (!dtls_get_app_data(ctx)) {
        DEBUG("No app_data stored!\n");
        return;
    }

    dtls_remote_peer_t *remote_peer;
    remote_peer = (dtls_remote_peer_t *)dtls_get_app_data(ctx);

    ssize_t res = sock_udp_recv(remote_peer->sock, packet_rcvd, sizeof(packet_rcvd),
                                1 * US_PER_SEC, remote_peer->remote);

    if (res <= 0) {
        if ((ENABLE_DEBUG) && (res != -EAGAIN) && (res != -ETIMEDOUT)) {
            DEBUG("sock_udp_recv unexepcted code error: %i\n", (int)res);
        }
        return;
    }

    /* (DTLS) session requires the remote peer address (IPv6:Port) and netif */
    session.size = sizeof(uint8_t) * 16 + sizeof(unsigned short);
    session.port = remote_peer->remote->port;
    if (remote_peer->remote->netif ==  SOCK_ADDR_ANY_NETIF) {
        session.ifindex = SOCK_ADDR_ANY_NETIF;
    }
    else {
        session.ifindex = remote_peer->remote->netif;
    }

    if (memcpy(&session.addr, &remote_peer->remote->addr.ipv6, 16) == NULL) {
        puts("ERROR: memcpy failed!");
        return;
    }

    dtls_handle_message(ctx, &session, packet_rcvd, (int)DTLS_MAX_BUF);

    return;
}

static int _handle_event(struct dtls_context_t *ctx, session_t *session,
                         dtls_alert_level_t level, unsigned short code)
{
    (void) ctx;
    (void) session;
    (void) level;

    switch (code) {
    case DTLS_EVENT_CONNECT:
        DEBUG("EVENT CONNECT\n");
        break;
    case DTLS_EVENT_CONNECTED:
        DEBUG("EVENT CONNECTED\n");
        printf("session_established: %d\n", ++session_established);
        break;
    default:
        printf("Unknown event code: %d; alert level: %d\n", code, level);
    }
    return 0;
}

/* Reception of a DTLS Application data record. */
static int _read_from_peer_handler(struct dtls_context_t *ctx,
                                   session_t *session, uint8 *data, size_t len)
{
    (void)ctx;
    (void)session;
    (void)data;
    printf("got len: %u\n", len);

    int idx = (len / INCREMENT) - 1;
    packets[idx] = packets[idx] + 1;

    return len;
}

/* Handles the DTLS communication with the other peer. */
static int _send_to_peer_handler(struct dtls_context_t *ctx,
                                 session_t *session, uint8 *buf, size_t len)
{

    /*
     * It's possible to create a sock_udp_ep_t variable. But, it's required
     * to copy memory from the session variable to it.
     */
    (void) session;

    assert(ctx);
    assert(dtls_get_app_data(ctx));

    if (!dtls_get_app_data(ctx)) {
        return -1;
    }

    dtls_remote_peer_t *remote_peer;
    remote_peer = (dtls_remote_peer_t *)dtls_get_app_data(ctx);

#ifdef ENABLE_EXP
    /* get packet size */
#endif

    return sock_udp_send(remote_peer->sock, buf, len, remote_peer->remote);
}

#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

/*
 * This function is the "key store" for tinyDTLS. It is called to retrieve a
 * key for the given identity within this particular session.
 */
static int _peer_get_psk_info_handler(struct dtls_context_t *ctx, const session_t *session,
                                      dtls_credentials_type_t type,
                                      const unsigned char *id, size_t id_len,
                                      unsigned char *result, size_t result_length)
{
    (void) ctx;
    (void) session;

    struct keymap_t {
        unsigned char *id;
        size_t id_length;
        unsigned char *key;
        size_t key_length;
    } psk[3] = {
        { (unsigned char *)psk_id, psk_id_length,
          (unsigned char *)psk_key, psk_key_length },
        { (unsigned char *)"default identity", 16,
          (unsigned char *)"\x11\x22\x33", 3 },
        { (unsigned char *)"\0", 2,
          (unsigned char *)"", 1 }
    };

    if (type != DTLS_PSK_KEY) {
        return 0;
    }

    if (id) {
        uint8_t i;
        for (i = 0; i < sizeof(psk) / sizeof(struct keymap_t); i++) {
            if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
                if (result_length < psk[i].key_length) {
                    dtls_warn("buffer too small for PSK");
                    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
                }

                memcpy(result, psk[i].key, psk[i].key_length);
                return psk[i].key_length;
            }
        }
    }

    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int _peer_get_ecdsa_key_handler(struct dtls_context_t *ctx,
                                       const session_t *session,
                                       const dtls_ecdsa_key_t **result)
{
    (void) ctx;
    (void) session;
    static const dtls_ecdsa_key_t ecdsa_key = {
        .curve = DTLS_ECDH_CURVE_SECP256R1,
        .priv_key = ecdsa_priv_key,
        .pub_key_x = ecdsa_pub_key_x,
        .pub_key_y = ecdsa_pub_key_y
    };

    /* TODO: Load the key from external source */

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
    (void) other_pub_x;
    (void) other_pub_y;
    (void) key_size;

    /* TODO: As far for tinyDTLS 0.8.2 this is not used */

    return 0;
}
#endif /* DTLS_ECC */

/* DTLS variables and register are initialized. */
dtls_context_t *_server_init_dtls(dtls_remote_peer_t *remote_peer)
{
    dtls_context_t *new_context = NULL;


    /*
     * The context for the server is different from the client.
     * This is because sock_udp_create() cannot work with a remote endpoint
     * with port set to 0. And even after sock_udp_recv(), sock_udp_get_remote()
     * cannot retrieve the remote.
     */
    new_context = dtls_new_context(remote_peer);

    if (new_context) {
        dtls_set_handler(new_context, &cb);
    }
    else {
        return NULL;
    }

    return new_context;
}

void *start_server(void *arg)
{
    (void)arg;

    sock_udp_t udp_socket;
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

    dtls_context_t *dtls_context = NULL;
    dtls_remote_peer_t remote_peer;

    remote_peer.sock = &udp_socket;
    remote_peer.remote = &remote;

    /* NOTE: dtls_init() must be called previous to this (see main.c) */

    local.port = DTLS_DEFAULT_PORT;
    ssize_t res = sock_udp_create(&udp_socket, &local, NULL, 0);
    if (res == -1) {
        puts("ERROR: Unable create sock.");
        return (void*)NULL;
    }

    dtls_context = _server_init_dtls(&remote_peer);

    if (!dtls_context) {
        puts("ERROR: Server unable to load context!");
        return (void*)NULL;
    }

    while (1) {
        dtls_handle_read(dtls_context);
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
