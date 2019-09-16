#include "net/sock/udp.h"

#define SERVER_PORT (20220)

#define ENABLE_DEBUG (1)
#include "debug.h"

/* exp values */
int packet_count = 0;

sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
sock_udp_t sock;

void start_server(void)
{
    DEBUG("Starting UDP server\n");
    local.port = SERVER_PORT;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("Error creating UDP sock");
        return;
    }
    while (1) {
#define RECV_BUF 400
        char buf[RECV_BUF];
        ssize_t res = sock_udp_recv(&sock, buf, sizeof(buf), SOCK_NO_TIMEOUT, NULL);
        if (res < 0) {
            DEBUG("ERROR receiveing udp packet\n");
            continue;
        }
        packet_count++;
        DEBUG("received: %d; size: %d\n", packet_count, res);
    }
}
