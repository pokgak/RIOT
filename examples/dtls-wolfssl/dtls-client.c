/*
 * Copyright (C) 2019 Daniele Lacamera
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
 * @brief       Demonstrating DTLS 1.2 client using wolfSSL
 *
 * @author      Daniele Lacamera <daniele@wolfssl.com>
 * @}
 */

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <sock_tls.h>
#include <net/sock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERVER_PORT 11111

extern const unsigned char server_cert[];
extern const unsigned long server_cert_len;

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

static void usage(const char *cmd_name)
{
    printf("Usage: %s <server-address>\n", cmd_name);
}

int dtls_client(int argc, char **argv)
{
    int ret = 0;
    char buf[64] = "Hello from DTLS client!";
    int iface;
    char *addr_str;
    int connect_timeout = 0;
    const int max_connect_timeouts = 5;

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    addr_str = argv[1];
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

    /* Parsing <address> */
    iface = ipv6_addr_split_iface(addr_str);
    if (iface == -1) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
    }
    else {
        if (gnrc_netif_get_by_pid(iface) == NULL) {
            puts("ERROR: interface not valid");
            usage(argv[0]);
            return -1;
        }
        remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
    }
    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
        puts("ERROR: unable to parse destination address");
        usage(argv[0]);
        return -1;
    }
    remote.port = SERVER_PORT;
    if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
        puts("ERROR: Unable to create DTLS sock");
        return -1;
    }

    /* Disable certificate validation from the client side */
    wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);

    /* Load certificate file for the DTLS client */
    if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_cert,
                server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        printf("Error loading cert buffer\n");
        return -1;
    }

    if (sock_dtls_session_create(sk) < 0)
        return -1;
    printf("connecting to server...");
    /* attempt to connect until the connection is successful */
    do {
        ret = wolfSSL_connect(sk->ssl);
        if ((ret != SSL_SUCCESS)) {
            if(wolfSSL_get_error(sk->ssl, ret) == SOCKET_ERROR_E) {
                printf("Socket error: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
            if ((wolfSSL_get_error(sk->ssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
                    (connect_timeout++ >= max_connect_timeouts)) {
                printf("Server not responding: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
        }
    } while(ret != SSL_SUCCESS);

    /* set remote endpoint */
    sock_dtls_set_endpoint(sk, &remote);

    /* send the hello message */
    wolfSSL_write(sk->ssl, buf, strlen(buf));

    /* wait for a reply, indefinitely */
    do {
        ret = wolfSSL_read(sk->ssl, buf, 63);
        printf("wolfSSL_read returned %d\r\n", ret);
    } while (ret <= 0);
    buf[ret] = (char)0;
    printf("Received: '%s'\r\n", buf);

    /* Clean up and exit. */
    printf("Closing connection.\r\n");
    sock_dtls_session_destroy(sk);
    sock_dtls_close(sk);
    return 0;
}
