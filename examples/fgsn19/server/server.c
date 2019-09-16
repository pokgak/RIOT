#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "net/credman.h"
#include "msg.h"
#include "thread.h"

#include "./tinydtls_keys.h"

#ifdef DTLS_PSK
static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
static ecdsa_public_key_t other_pubkeys[] = {
    { .x = ecdsa_pub_key_x, .y = ecdsa_pub_key_y },
};
#endif /* DTLS_ECC */

#define DTLS_SOCK_SERVER_TAG (3)
#define DTLS_SERVER_PORT (20220)

static int packet_count = 0;

void start_server(void)
{
    ssize_t res;
    uint8_t rcv[400];

    sock_dtls_t sock;
    sock_udp_t udp_sock;
    sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
    local_ep.port = DTLS_SERVER_PORT;
    sock_udp_create(&udp_sock, &local_ep, NULL, 0);

    sock_dtls_session_t rcv_session = {0};

    res = sock_dtls_create(&sock, &udp_sock, DTLS_SOCK_SERVER_TAG, SOCK_DTLS_1_2, SOCK_DTLS_SERVER);
    if (res < 0) {
        puts("Error creating DTLS sock");
        return;
    }

#ifdef DTLS_PSK
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_PSK,
        .tag = DTLS_SOCK_SERVER_TAG,
        .params = {
            .psk = {
                .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
            },
        },
    };
    res = credman_add(&credential);
    if (res < 0) {
        printf("Error cannot add credential to system: %d\n", res);
        return;
    }
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_ECDSA,
        .tag = DTLS_SOCK_SERVER_TAG,
        .params = {
            .ecdsa = {
                .private_key = ecdsa_priv_key,
                .public_key = { .x = ecdsa_pub_key_x, .y = ecdsa_pub_key_y },
                .client_keys = other_pubkeys,
                .client_keys_size = sizeof(other_pubkeys) / sizeof(other_pubkeys[0]),
            },
        },
    };
    res = credman_add(&credential);
    if (res < 0) {
        printf("Error cannot add credential to system: %d\n", res);
        return;
    }
#endif /* DTLS_ECC */

    while (1) {
        puts("waiting for packets");
        res = sock_dtls_recv(&sock, &rcv_session, rcv, sizeof(rcv), SOCK_NO_TIMEOUT);
        if (res <= 0) {
            printf("Error receiving UDP over DTLS %d", res);
            continue;
        }
        packet_count++;
        printf("packet count: %u; total: %u\n", packet_count, res);
        // printf("total: %u\n", total_received);
    }

    // sock_dtls_destroy(&sock);
    // puts("Terminating");
}