#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "xtimer.h"

#include "net/sock/udp.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#define SERVER_PORT (20220)
#define SERVER_ADDR "fe80::7b76:7968:5ef6:617a"
// #define SERVER_ADDR "fe80::6813:98ff:fe97:ab67"
#define CLIENT_PORT (20220)

sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
sock_udp_t sock;

static int packets_sent = 0;
// static uint32_t total_time = 0;

extern int exp_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "exp", "Start experiment", exp_cmd },
    { NULL, NULL, NULL }
};

void run_exp(void)
{
    sock_udp_ep_t remote = {
        .family = AF_INET6,
        .port = SERVER_PORT,
     };

    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, SERVER_ADDR) == NULL) {
        puts("ERROR: unable to parse destination address");
        return;
    }
#define PAYLOAD_SIZE 300
    for (int i = 0; i < PAYLOAD_SIZE / 50; i++) {
        char data[PAYLOAD_SIZE];  // TODO: generate test data
        size_t len2send = (i + 1) * 50;
        uint32_t start = xtimer_now_usec();
        if (sock_udp_send(&sock, data, len2send, &remote) < 0) {
            puts("Error sending message");
        }
        else {
            printf("count = %d; size: %u; time: %lu\n", ++packets_sent, len2send,(long unsigned)xtimer_now_usec() - start);
            packets_sent = 0;
        }
        // total_time += xtimer_now_usec() - start;
    }
    // printf("packets sent %u; time total: %lu\n", packets_sent, (long unsigned)total_time);
    // total_time = 0;
    packets_sent = 0;
}

int exp_cmd(int argc, char **argv)
{
    (void)argc;

    if (argc < 2) {
        return -1;
    }

    if (strcmp(argv[0], "run")) {
        run_exp();
    }
    else {
        puts("Unknown commands");
    }

    return 0;
}

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("FGSN19 sock_udp client");

    /* init sock_udp */
    local.port = CLIENT_PORT;
    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("Error creating UDP sock");
        return 1;
    }

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
