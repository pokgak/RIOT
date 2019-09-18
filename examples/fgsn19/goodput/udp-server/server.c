#include "net/sock/udp.h"

#define SERVER_PORT (20220)

#define ENABLE_DEBUG (1)
#include "debug.h"

/* exp values */
#define INCREMENT (25)
#define RECV_BUF 600
uint16_t packets[(RECV_BUF) / INCREMENT];

sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
sock_udp_t sock;

void *start_server(void *arg)
{
    (void)arg;

    DEBUG("Starting UDP server\n");
    local.port = SERVER_PORT;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("Error creating UDP sock");
        return (void*)NULL;
    }
    while (1) {
        char buf[RECV_BUF];
        ssize_t res = sock_udp_recv(&sock, buf, sizeof(buf), SOCK_NO_TIMEOUT, NULL);
        if (res < 0) {
            DEBUG("ERROR receiveing udp packet\n");
            continue;
        }
        int idx = (res / INCREMENT) - 1;
        packets[idx] = packets[idx] + 1;
    }
}

int result_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("BEGIN RESULT\n");
    for (int i = 1; i <= (RECV_BUF) / INCREMENT; i++) {
        printf("%d,", i * INCREMENT);
    }
    puts("");
    for (int i = 0; i < (RECV_BUF) / INCREMENT; i++) {
        printf("%d,", packets[i]);
    }
    puts("");
    printf("END RESULT\n");
    return 0;
}
