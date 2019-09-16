#include "net/sock/udp.h"

#define SERVER_PORT (20220)

#define ENABLE_DEBUG (1)
#include "debug.h"

/* exp values */
uint16_t packet25, packet50,packet75, packet100, packet125, packet150;
uint16_t packet175, packet200, packet225, packet250, packet275, packet300;

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
#define RECV_BUF 400
        char buf[RECV_BUF];
        ssize_t res = sock_udp_recv(&sock, buf, sizeof(buf), SOCK_NO_TIMEOUT, NULL);
        if (res < 0) {
            DEBUG("ERROR receiveing udp packet\n");
            continue;
        }
        switch (res) {
            case 25: packet25++; break;
            case 50: packet50++; break;
            case 75: packet75++; break;
            case 100: packet100++; break;
            case 125: packet125++; break;
            case 150: packet150++; break;
            case 175: packet175++; break;
            case 200: packet200++; break;
            case 225: packet225++; break;
            case 250: packet250++; break;
            case 275: packet275++; break;
            case 300: packet300++; break;
        }
    }
}

int result_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("BEGIN RESULT\n");
    printf("25,50,75,100,125,150,175,200,225,250,275,300\n");
    printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
        packet25, packet50, packet75, packet100, packet125, packet150,
        packet175, packet200, packet225, packet250, packet275, packet300);
    printf("END RESULT\n");
    return 0;
}
