/*
 * Copyright (C) 2019 Kaleb J. Himes <kaleb@wolfssl.com>
 *
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
 * @brief       wolfSSL client example
 *
 * @author      Kaleb J. Himes <kaleb@wolfssl.com>
 *
 * @}
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include "application_user_settings.h"
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define SERVER_PORT 11111
#define SERVER_ADDRESS 


int tls_client(int argc, char *argv[])
{
    int                sockfd;
    struct sockaddr_in6 servAddr;
    char               buff[] = "Hello, wolfSSL Server!\0";
    char               *server_ip;
    size_t             len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
    puts("This is the wolfSSL Client!");
    if (argc != 2) {
        fprintf(stderr, "Usage: %s IP_ADDR_SERVER\n", argv[0]);
        return -1;
    }
    printf("Client is connecting to server at address %s port 11111...\n", argv[1]);
    server_ip = argv[1];

/*----------------------------------------------------------------------------*/
/* TLS Setup:
 * This section will need resolved on a per-device basis depending on the
 * available TCP/IP stack
 */
/*----------------------------------------------------------------------------*/

    /* Create a socket that uses an internet IPv6 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin6_family       = AF_INET6;             /* using IPv6      */
    servAddr.sin6_port         = htons(SERVER_PORT);  /* on SERVER_PORT */

    /* Get the server IPv6 address from the compile-time string parameter */
    if (inet_pton(AF_INET6, server_ip, &servAddr.sin6_addr.s6_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        return -1;
    }

    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to connect, error %d\n", errno);
        return -1;
    }
/*----------------------------------------------------------------------------*/
/* END TCP SETUP, BEGIN TLS */
/*----------------------------------------------------------------------------*/

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_buffer(ctx, ca_cert_der_2048,
                                       sizeof_ca_cert_der_2048,
                                       SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load ca buffer\n");
        return -1;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return -1;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: %s\n", buff);
    len = strlen(buff);

    /* Send the message to the server */
    if (wolfSSL_write(ssl, buff, len) != (int) len) {
        fprintf(stderr, "ERROR: failed to write\n");
        return -1;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        return -1;
    }

    /* Print to stdout any data the server sends */
    printf("Server sent a reply!\n");
    printf("Server Response was:  %s\n", buff);

    /* Cleanup and exit */
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return 0;               /* Return reporting a success               */
}
