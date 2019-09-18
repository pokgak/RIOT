#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "xtimer.h"

#ifndef SERVER_ADDR
#define SERVER_ADDR "fe80::7b76:645c:f47e:8e1a"
// #define SERVER_ADDR "fe80::f085:96ff:fefc:440b"
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int client_init(const char *addr);
extern int client_send(const char *data, size_t len);

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    xtimer_sleep(2);
    int res = client_init(SERVER_ADDR);
    if (res < 0) {
        puts("Client not connected");
        return -1;
    }

#define MAX_PAYLOAD_SIZE  (600)
#define INCREMENT (25)
#define PACKETS_PER_SIZE (5000)
// #define PACKETS_PER_SIZE (1)

    char payload[MAX_PAYLOAD_SIZE];
    puts("tinydtls experiment for FGSN19 paper - CLIENT");
    puts("----------------BEGIN EXPERIMENT----------------");
    puts("full start,end,packet number,payload size,type");
    for (int i = 0; i < PACKETS_PER_SIZE * (MAX_PAYLOAD_SIZE / INCREMENT); i++) {
        size_t payload_size = ((i / PACKETS_PER_SIZE) + 1) * INCREMENT;
        uint32_t full_start = xtimer_now_usec();
        client_send(payload, payload_size);
        uint32_t end = xtimer_now_usec();
        printf("%lu,%lu,%u,%u,sock-udp\n",
            (long unsigned)full_start, (long unsigned)end, (i % PACKETS_PER_SIZE) + 1, payload_size);
    }
    puts("----------------END OF EXPERIMENT----------------");
    while (1) {};

    /* should be never reached */
    return 0;
}
