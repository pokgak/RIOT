#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "xtimer.h"

#ifndef SERVER_ADDR
#define SERVER_ADDR "fe80::7b76:7968:5ef6:617a"
// #define SERVER_ADDR "fe80::440e:62ff:fe60:960b"
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int client_init(const char *addr);
extern int client_send(char *data, size_t len);
extern void client_close(void);

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

#define MAX_PAYLOAD_SIZE  (DTLS_MAX_BUF - 100)
#define INCREMENT (25)
#define PACKETS_PER_SIZE (1)

    printf("######### THREAD_STACKSIZE_DEFAULT=%d\n", THREAD_STACKSIZE_DEFAULT);
    printf("######### THREAD_STACKSIZE_DEFAULT=%d\n", THREAD_STACKSIZE_LARGE);
    printf("######### THREAD_STACKSIZE_MAIN=%d\n", THREAD_STACKSIZE_MAIN);

    char payload[MAX_PAYLOAD_SIZE];
    puts("sock_dtls experiment for FGSN19 paper - CLIENT");
    puts("----------------BEGIN EXPERIMENT----------------");
    puts("dtls start,full start,end,packet number,payload size,type");
    for (int i = 0; i < PACKETS_PER_SIZE * (MAX_PAYLOAD_SIZE / INCREMENT); i++) {
        size_t payload_size = ((i / PACKETS_PER_SIZE) + 1) * INCREMENT;
        uint32_t dtls_start = xtimer_now_usec();
        client_send(payload, payload_size);
        uint32_t end = xtimer_now_usec();
        printf("%lu,%lu,%u,%u,sock-dtls\n",
            (long unsigned)dtls_start, (long unsigned)end, (i % PACKETS_PER_SIZE) + 1, payload_size);
    }
    puts("----------------END OF EXPERIMENT----------------");
    client_close();
    while (1) {};

    /* should be never reached */
    return 0;
}
