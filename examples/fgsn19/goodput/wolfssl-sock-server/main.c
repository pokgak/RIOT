#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"

#include <wolfssl/ssl.h>

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

char server_stack[THREAD_STACKSIZE_MAIN +
                  THREAD_EXTRA_STACKSIZE_PRINTF];

extern void *start_server(void *arg);
extern int result_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "result", "Get packets received count", result_cmd },
};

static void _print_ip(void)
{
    /* get interfaces and print their addresses */
    gnrc_netif_t *netif = NULL;
    while ((netif = gnrc_netif_iter(netif))) {
        ipv6_addr_t ipv6_addrs[GNRC_NETIF_IPV6_ADDRS_NUMOF];
        int res = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, ipv6_addrs,
                                  sizeof(ipv6_addrs));

        if (res < 0) {
            continue;
        }
        for (unsigned i = 0; i < (unsigned)(res / sizeof(ipv6_addr_t)); i++) {
            char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];

            ipv6_addr_to_str(ipv6_addr, &ipv6_addrs[i], IPV6_ADDR_MAX_STR_LEN);
            printf("My address is %s\n", ipv6_addr);
        }
    }

}

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("WolfSSL server for FGSN19 paper");

    _print_ip();

    /* TinyDTLS settings (Universal and called only one time by reboot) */
    puts("Starting server");
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    thread_create(server_stack, sizeof(server_stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  start_server, NULL, "DTLS Server");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
