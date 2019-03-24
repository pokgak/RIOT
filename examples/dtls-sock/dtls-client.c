#include <stdio.h>

#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "net/ipv6/addr.h"

#include "client/keys.h"

#ifdef DTLS_ECC
#include "client/server_pub_keys.h"
#endif /* DTLS_ECC */

/* TinyDTLS WARNING check */
#ifdef WITH_RIOT_SOCKETS
#error TinyDTLS is set to use sockets but the app is configured for socks.
#endif

static uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;

int _load_client_credential(tlscred_type type, const char *cred, size_t *credlen)
{
    (void)cred;
    switch (type) {
        case TLSCRED_PSK_HINT:
            /* unused */
            break;
        case TLSCRED_PSK_IDENTITY:
            if (*credlen < sizeof(psk_id_0) - 1) {
                return -1;
            }

            cred = (const char *)psk_id_0;
            *credlen = sizeof(psk_id_0) - 1;
            break;
        case TLSCRED_PSK_KEY:
            if (*credlen < sizeof(psk_key_0) - 1) {
                return -1;
            }

            cred = (const char *)psk_key_0;
            *credlen = sizeof(psk_key_0) - 1;
            break;
        default:
            printf("Error: unsupported credential type %u\n", type);
            return -1;
    }

    return 0;
}

static void client_send(char *addr_str, uint8_t port, char *data, size_t datalen)
{
    uint8_t rcv[512];
    ssize_t res;
    sock_udp_ep_t remote_ep;
    sock_dtls_session_t remote;
    sock_dtls_t sock;

    sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
    local_ep.port = 12345;
    sock_udp_t udp_sock;
    sock_udp_create(&udp_sock, &local_ep, NULL, 0);

    tlscred_t cred;
    cred.psk.key = (const char *)psk_key_0;
    cred.psk.key_len = sizeof(psk_key_0) - 1;
    cred.psk.id = (const char *)psk_id_0;
    cred.psk.id_len = sizeof(psk_id_0) - 1;
    cred.load_credential = _load_client_credential;

    ipv6_addr_from_str((ipv6_addr_t *)&remote_ep.addr.ipv6, addr_str);
    //remote_ep.port = port;
    (void)port;
    remote_ep.port = 20220;

    res = sock_dtls_create(&sock, &udp_sock, &cred, 0);
    if (res < 0) {
        puts("Error creating DTLS sock");
        return;
    }

    res = sock_dtls_establish_session(&sock, &remote_ep, &remote);
    if (res < 0) {
        printf("Error establishing session: %d\n", res);
        return;
    }

    res = sock_dtls_send(&sock, &remote, data, datalen);
    if (res < 0) {
        printf("Error sending DTLS message: %d\n", res);
        return;
    }
    printf("Sent %d bytes of DTLS message: %s\n", res, data);

    res = sock_dtls_recv(&sock, &remote, rcv, sizeof(rcv), SOCK_NO_TIMEOUT);
    if (res < 0) {
        printf("Error receiving DTLS message: %d\n", res);
        return;
    }
    else if (res == 0) {
        puts("No message received");
    }
    printf("Received %d bytes of DTLS message: %.*s\n", res, res, rcv);

    puts("Terminating");
    sock_dtls_close_session(&sock, &remote);
    sock_dtls_destroy(&sock);
}

int dtls_client_cmd(int argc, char **argv)
{
    if (argc != 4) {
        printf("usage %s <addr> <port> <data>\n", argv[0]);
        return 1;
    }
    client_send(argv[1], atoi(argv[2]), argv[3], strlen(argv[3]));
    return 0;
}

