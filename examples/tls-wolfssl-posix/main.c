/*
 * Copyright (C) 2019 Daniele Lacamera
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
 * @brief       Example application using wolfSSL
 *
 * @author      Daniele Lacamera <daniele@wolfssl.com>
 * @author      Kaleb J. Himes <kaleb@wolfssl.com>
 *
 * @}
 */

#include <stdio.h>
#include <wolfssl/ssl.h>

#include "lwip.h"
#include "lwip/opt.h"
#include "lwip/netif.h"
#include "net/ipv6/addr.h"
#include "shell.h"
#include "msg.h"


#ifndef MODULE_POSIX_SOCKETS
#   error RIOT-OS lacks support for posix sockets, and this TLS app is configured to use them. Please ensure that MODULE_POSIX_SOCKETS is enabled in your configuration.
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int tls_client(int argc, char **argv);
extern int tls_server(int argc, char **argv);

static int ip_show(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("Interfaces:\n");
    for (struct netif *iface = netif_list; iface != NULL; iface = iface->next) {
        printf("%s_%02u: ", iface->name, iface->num);
        char addrstr[IPV6_ADDR_MAX_STR_LEN];
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            if (!ipv6_addr_is_unspecified((ipv6_addr_t *)&iface->ip6_addr[i])) {
                printf(" inet6 %s\n", ipv6_addr_to_str(addrstr, (ipv6_addr_t *)&iface->ip6_addr[i],
                                                       sizeof(addrstr)));
            }
        }
        puts("");
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "tlsc", "Start a TLS client", tls_client },
    { "tlss", "Start and stop a TLS server", tls_server },
    { "ip", "Shows assigned IPv6 addresses", ip_show},
    { NULL, NULL, NULL }
};

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT wolfSSL TLS testing implementation");
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
