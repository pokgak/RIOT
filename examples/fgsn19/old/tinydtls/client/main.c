#include <stdio.h>

#include "shell.h"
#include "msg.h"

#include "dtls.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int exp_cmd(int argc, char **argv);
extern void start_server(void);

static const shell_command_t shell_commands[] = {
    { "exp", "Start experiment", exp_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("TinyDTLS experiment for FGSN19 paper - CLIENT");

    /* TinyDTLS settings (Universal and called only one time by reboot) */
    dtls_init();

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
