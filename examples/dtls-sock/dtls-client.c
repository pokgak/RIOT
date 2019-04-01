#include <stdio.h>

#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "net/ipv6/addr.h"
#include "net/tlsman.h"

#include "client/keys.h"

#ifdef DTLS_ECC
#include "client/server_pub_keys.h"
#endif /* DTLS_ECC */

/* TinyDTLS WARNING check */
#ifdef WITH_RIOT_SOCKETS
#error TinyDTLS is set to use sockets but the app is configured for socks.
#endif

#ifdef DTLS_PSK
static uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;

static int _get_psk_params(psk_params_t *psk)
{
    psk->key = (const char *)psk_key_0;
    psk->id = (const char *)psk_id_0;
    psk->hint = NULL;

    psk->key_len = sizeof(psk_key_0) - 1;
    psk->id_len = sizeof(psk_id_0) -1;
    psk->hint_len = 0;
    return 0;
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int _get_ecdsa_params(ecdsa_params_t *ecdsa)
{
    ecdsa->priv_key = ecdsa_priv_key;
    ecdsa->pub_key_x = ecdsa_pub_key_x;
    ecdsa->pub_key_y = ecdsa_pub_key_y;
#ifdef USE_TINYDTLS     // FIXME: remove?
    ecdsa->curve = DTLS_ECDH_CURVE_SECP256R1;
#endif
    return 0;
}
#endif /* DTLS_ECC */

static tlsman_handler_t handler = {
#ifdef DTLS_PSK
    .get_psk_params = _get_psk_params,
#endif
#ifdef DTLS_ECC
    .get_ecdsa_params = _get_ecdsa_params,
#endif
};

static void client_send(char *addr_str, uint8_t port, char *data, size_t datalen)
{
    uint8_t rcv[512];
    ssize_t res;

    tlsman_set_credentials_handler(&handler);

    sock_dtls_t sock;
    sock_dtls_session_t remote;
    sock_udp_ep_t remote_ep;
    sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
    local_ep.port = 12345;
    sock_udp_t udp_sock;
    sock_udp_create(&udp_sock, &local_ep, NULL, 0);

    ipv6_addr_from_str((ipv6_addr_t *)&remote_ep.addr.ipv6, addr_str);
    //remote_ep.port = port;
    (void)port;
    remote_ep.port = 20220;

    res = sock_dtls_create(&sock, &udp_sock, 0);
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

