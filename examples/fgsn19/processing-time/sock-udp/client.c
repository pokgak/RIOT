#include <stdio.h>

#include "net/sock/udp.h"

sock_udp_t sock;
sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
sock_udp_ep_t local = SOCK_IPV6_EP_ANY;

#define SERVER_PORT (20220)

int client_init(const char *addr)
{
    remote.family = AF_INET6;
    remote.port = SERVER_PORT;

    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr) == NULL) {
        puts("ERROR: unable to parse destination address");
        return -1;
    }

    if (sock_udp_create(&sock, &local, &remote, 0) < 0) {
        puts("Error creating UDP sock");
        return -1;
    }
    return 0;
}

int client_send(const char *data, size_t len)
{
    ssize_t res = sock_udp_send(&sock, data, len, NULL);
    if (res < 0) {
        puts("Error sending message");
        return -1;
    }
    return res;
}