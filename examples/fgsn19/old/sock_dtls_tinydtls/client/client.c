#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "net/credman.h"
#include "msg.h"
#include "thread.h"

#include "../tinydtls_keys.h"

#ifndef SERVER_ADDR
#define SERVER_ADDR "fe80::7b76:7968:5ef6:617a"
// #define SERVER_ADDR "fe80::6813:98ff:fe97:ab67"
#endif

#ifndef DTLS_DEFAULT_PORT
#define DTLS_DEFAULT_PORT 20220 /* DTLS default port */
#endif

static void _add_credential(void);

static sock_udp_ep_t remote;
static sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
static sock_udp_t sock_udp;
static sock_dtls_t sock_dtls;
static sock_dtls_session_t session;

static int dtls_connected = 0;

static int packets_sent = 0;

#define DTLS_SOCK_CLIENT_TAG (2)

#ifdef DTLS_PSK
static uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
static ecdsa_public_key_t other_pubkeys[] = {
    { .x = ecdsa_pub_key_x, .y = ecdsa_pub_key_y },
};
#endif /* DTLS_ECC */

void client_init(void)
{
    ssize_t res;
    sock_udp_create(&sock_udp, &local, NULL, 0);
    ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, SERVER_ADDR);
    remote.port = DTLS_DEFAULT_PORT;

    res = sock_dtls_create(&sock_dtls, &sock_udp, 0);
    if (res < 0) {
        puts("Error creating DTLS sock");
        return;
    }

    _add_credential();
    res = sock_dtls_establish_session(&sock_dtls, &remote, &session);
    if (res < 0) {
        printf("Error establishing session: %d\n", res);
        return;
    }
    dtls_connected = 1;
}

static void client_send(const char *data, size_t len)
{
    ssize_t res = sock_dtls_send(&sock_dtls, &session, data, len);
    if (res < 0) {
        printf("ERROR send data failed: %d\n", res);
    }
    else {
        packets_sent++;
    }
    // else if (res != len) {

    // }
}

int exp_cmd(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    if (strcmp(argv[1], "session") == 0) {
        /* init session handshake */
        int expcount = atoi(argv[2]);
        for (int i = 0; i < expcount; i++) {
            client_init();
            sock_dtls_close_session(&sock_dtls, &session);
            sock_dtls_destroy(&sock_dtls);
            dtls_connected = 0;
            xtimer_sleep(1);
        }
    }
    else if (strcmp(argv[1], "run") == 0) {
        client_init();
        if (dtls_connected == 0) {
            puts("Client not connected");
            return -1;
        }
        // uint32_t total_time = 0;
#define PAYLOAD_SIZE 300
        for (int i = 0; i < PAYLOAD_SIZE / 50; i++) {
            // char data[PAYLOAD_SIZE];  // TODO: generate test data
            char data[PAYLOAD_SIZE];  // TODO: generate test data
            size_t len2send = (i + 1) * 50;
            uint32_t start = xtimer_now_usec();
            client_send(data, len2send);
            printf("count = %d; size: %u; time: %lu\n", i + 1, len2send,(long unsigned)xtimer_now_usec() - start);
        }
        // printf("total_time for count %d: %lu\n", atoi(argv[2]), (long unsigned)total_time);
        // printf("effective count: %d; total time: %lu\n", packets_sent, (long unsigned)total_time);
        sock_dtls_close_session(&sock_dtls, &session);
        sock_dtls_destroy(&sock_dtls);
    }
    else {
        puts("Unknown command");
    }

    return 0;
}

static void _add_credential(void)
{
    credman_tag_t tags[] = { DTLS_SOCK_CLIENT_TAG };
#ifdef DTLS_PSK
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_PSK,
        .tag = tags[0],
        .params = {
            .psk = {
                .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
                .id = { .s = psk_id_0, .len = sizeof(psk_id_0) - 1, },
            }
        },
    };
    credman_credential_t cred;
    if (credman_get(&cred, credential.tag, credential.type) == CREDMAN_NOT_FOUND) {
        ssize_t res = credman_add(&credential);
        if (res < 0) {
            printf("Error cannot add credential to system: %d\n", res);
            return;
        }
    }
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    credman_credential_t credential = {
        .type = CREDMAN_TYPE_ECDSA,
        .tag = tags[0],
        .params = {
            .ecdsa = {
                .private_key = ecdsa_priv_key,
                .public_key = { .x = ecdsa_pub_key_x, .y = ecdsa_pub_key_y },
                .client_keys = other_pubkeys,
                .client_keys_size = sizeof(other_pubkeys) / sizeof(other_pubkeys[0]),
            }
        },
    };
    credman_credential_t cred;
    if (credman_get(&cred, credential.tag, credential.type) == CREDMAN_NOT_FOUND) {
        ssize_t res = credman_add(&credential);
        if (res < 0) {
            printf("Error cannot add credential to system: %d\n", res);
            return;
        }
    }
#endif /* DTLS_ECC */

    sock_dtls_register_credential_tags(&sock_dtls, tags, sizeof(tags) / sizeof(tags[0]));
}
