/*
 * Copyright (C) 2019 HAW Hamburg
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
 * @brief       DTLS sock client example
 *
 * @author      Aiman Ismail <muhammadaimanbin.ismail@haw-hamburg.de>
 */

#include <stdio.h>

#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "net/ipv6/addr.h"
#include "net/credman.h"

#include "client_keys.h"

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

#define DTLS_SOCK_CLIENT_TAG (2)

#ifdef DTLS_PSK
static uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
static ecdsa_public_key_t other_pubkeys[] = {
    { .x = other_pub_key_x, .y = other_pub_key_y },
};
#endif /* DTLS_ECC */

static void client_send(char *addr_str, char *data, size_t datalen)
{
    uint8_t rcv[512];
    ssize_t res;

    sock_udp_t udp_sock;
    sock_dtls_t dtls_sock;
    sock_dtls_session_t session;
    sock_udp_ep_t remote;
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = 12345;
    remote.port = DTLS_DEFAULT_PORT;

    /* get interface */
    int iface = ipv6_addr_split_iface(addr_str);
    if (iface >= 0) {
        if (gnrc_netif_get_by_pid(iface) == NULL) {
            puts("Invalid network interface");
            return;
        }
        remote.netif = iface;
    } else if (gnrc_netif_numof() == 1) {
        /* assign the single interface found in gnrc_netif_numof() */
        remote.netif = gnrc_netif_iter(NULL)->pid;
    } else {
        /* no interface is given, or given interface is invalid */
        /* FIXME This probably is not valid with multiple interfaces */
        remote.netif = SOCK_ADDR_ANY_NETIF;
    }

    /* get ip */
    if (!ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str)) {
        puts("Error parsing destination address");
        return;
    }

    res = sock_udp_create(&udp_sock, &local, NULL, 0);
    if (res < 0) {
        puts("Error creating UDP sock");
        return;
    }

    res = sock_dtls_create(&dtls_sock, &udp_sock, DTLS_SOCK_CLIENT_TAG, 0);
    if (res < 0) {
        puts("Error creating DTLS sock");
        return;
    }

#ifdef DTLS_PSK
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_PSK,
        .tag = DTLS_SOCK_CLIENT_TAG,
        .params = {
            .psk = {
                .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
                .id = { .s = psk_id_0, .len = sizeof(psk_id_0) - 1, },
            }
        },
    };
    res = credman_add(&credential);
    if (res < 0 && res != CREDMAN_EXIST) {
        printf("Error cannot add credential to system: %d\n", (int)res);
        return;
    }
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_ECDSA,
        .tag = DTLS_SOCK_CLIENT_TAG,
        .params = {
            .ecdsa = {
                .private_key = client_ecdsa_priv_key,
                .public_key = {
                    .x = client_ecdsa_pub_key_x,
                    .y = client_ecdsa_pub_key_y,
                },
                .client_keys = other_pubkeys,
                .client_keys_size = sizeof(other_pubkeys) / sizeof(other_pubkeys[0]),
            }
        },
    };
    res = credman_add(&credential);
    if (res < 0 && res != CREDMAN_EXIST) {
        printf("Error cannot add credential to system: %d\n", (int)res);
        return;
    }
#endif /* DTLS_ECC */

    res = sock_dtls_establish_session(&dtls_sock, &remote, &session);
    if (res < 0) {
        printf("Error establishing session: %d\n", (int)res);
        goto end;
    }

    res = sock_dtls_send(&dtls_sock, &session, data, datalen);
    if (res < 0) {
        printf("Error sending DTLS message: %d\n", (int)res);
        goto end;
    }
    printf("Sent %d bytes of DTLS message: %s\n", (int)res, data);

    res = sock_dtls_recv(&dtls_sock, &session, rcv, sizeof(rcv), SOCK_NO_TIMEOUT);
    if (res < 0) {
        printf("Error receiving DTLS message: %d\n", (int)res);
        goto end;
    }
    else if (res == 0) {
        puts("No message received");
    }
    printf("Received %d bytes of DTLS message: %.*s\n", (int)res, (int)res, rcv);

end:
    puts("Terminating");
    sock_dtls_close_session(&dtls_sock, &session);
    sock_dtls_destroy(&dtls_sock);
}

int dtls_client_cmd(int argc, char **argv)
{
    if (argc != 3) {
        printf("usage %s <addr> <data>\n", argv[0]);
        return 1;
    }
    client_send(argv[1], argv[2], strlen(argv[2]));
    return 0;
}
