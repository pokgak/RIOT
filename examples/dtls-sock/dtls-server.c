#include <stdio.h>

#include "net/sock/udp.h"
#include "net/sock/dtls.h"
#include "msg.h"
#include "thread.h"

#include "server/keys.h"

#ifdef DTLS_ECC
#include "server/client_pub_keys.h"
#endif /* DTLS_ECC */

/* TinyDTLS WARNING check */
#ifdef WITH_RIOT_SOCKETS
#error TinyDTLS is set to use sockets but the app is configured for socks.
#endif

#define DTLS_STOP_SERVER_MSG 0x4001 /* Custom IPC type msg. */
#define DTLS_SERVER_PORT (20220)
#define READER_QUEUE_SIZE (8U)
#define MAX_SESSIONS    (5U)

char _dtls_server_stack[THREAD_STACKSIZE_MAIN +
                        THREAD_EXTRA_STACKSIZE_PRINTF];

static kernel_pid_t _dtls_server_pid = KERNEL_PID_UNDEF;

#define READER_QUEUE_SIZE (8U)

static uint8_t psk_key_0[] = PSK_DEFAULT_KEY;

int _load_server_credential(tlscred_type type, const char *cred, size_t *credlen)
{
    (void)cred;
    switch (type) {
        case TLSCRED_PSK_HINT:
        case TLSCRED_PSK_IDENTITY:
            /* unused */
            break;
        case TLSCRED_PSK_KEY:
            if (*credlen < sizeof(psk_key_0) - 1) {
                return -1;
            }

            cred = (const char *)psk_key_0;
            *credlen = sizeof(psk_key_0) - 1;
            break;
        default:
            printf("Error: unsupported credential type %u\n", type);
            return -1;
    }

    return 0;
}

void *_dtls_server_wrapper(void *arg)
{
    (void) arg;

    ssize_t res;
    bool active = true;
    msg_t _reader_queue[READER_QUEUE_SIZE];
    msg_t msg;
    uint8_t rcv[512];

    /* Prepare (thread) messages reception */
    msg_init_queue(_reader_queue, READER_QUEUE_SIZE);

    sock_dtls_t sock;
    sock_udp_t udp_sock;
    sock_udp_ep_t local_ep = SOCK_IPV6_EP_ANY;
    local_ep.port = DTLS_SERVER_PORT;
    sock_udp_create(&udp_sock, &local_ep, NULL, 0);

    tlscred_t cred;
    cred.psk.key = (const char *)psk_key_0;
    cred.psk.key_len = sizeof(psk_key_0) - 1;
    cred.load_credential = _load_server_credential;

    sock_dtls_queue_t queue;
    sock_dtls_session_t queue_array[MAX_SESSIONS];
    sock_dtls_session_t rcv_session;

    sock_dtls_create(&sock, &udp_sock, &cred, 0);
    sock_dtls_init_server(&sock, &queue, queue_array, MAX_SESSIONS);

    while (active) {
        msg_try_receive(&msg);
        if (msg.type == DTLS_STOP_SERVER_MSG) {
            active = false;
        }
        else {
            res = sock_dtls_recv(&sock, &rcv_session, rcv, sizeof(rcv), SOCK_NO_TIMEOUT);
            if (res < 0) {
                printf("Error receiving UDP over DTLS %d", res);
                continue;
            }
            printf("Received %d bytes of DTLS message: %.*s\n", res, res, rcv);

            puts("Resending received message");
            res = sock_dtls_send(&sock, &rcv_session, rcv, res);
            if (res < 0) {
                printf("Error resending DTLS message: %d", res);
            }
        }
    }

    sock_dtls_destroy(&sock);
    puts("Terminating");
    return 0;
}

static void start_server(void)
{
    /* Only one instance of the server */
    if (_dtls_server_pid != KERNEL_PID_UNDEF) {
        puts("Error: server already running");
        return;
    }

    /* Start the server thread */
    _dtls_server_pid = thread_create(_dtls_server_stack,
                                     sizeof(_dtls_server_stack),
                                     THREAD_PRIORITY_MAIN - 1,
                                     THREAD_CREATE_STACKTEST,
                                     _dtls_server_wrapper, NULL, "dtls_server");

    /* Uncommon but better be sure */
    if (_dtls_server_pid == EINVAL) {
        puts("ERROR: Thread invalid");
        _dtls_server_pid = KERNEL_PID_UNDEF;
        return;
    }

    if (_dtls_server_pid == EOVERFLOW) {
        puts("ERROR: Thread overflow!");
        _dtls_server_pid = KERNEL_PID_UNDEF;
        return;
    }

    return;
}

static void stop_server(void)
{
    /* check if server is running at all */
    if (_dtls_server_pid == KERNEL_PID_UNDEF) {
        puts("Error: DTLS server is not running");
        return;
    }

    /* prepare the stop message */
    msg_t m;
    m.type = DTLS_STOP_SERVER_MSG;

    puts("Stopping server...");

    /* send the stop message to thread AND wait for (any) answer */
    msg_send_receive(&m, &m, _dtls_server_pid);

    _dtls_server_pid = KERNEL_PID_UNDEF;
    puts("Success: DTLS server stopped");
}

int dtls_server_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s start | stop\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "start") == 0) {
        start_server();
    }
    else if (strcmp(argv[1], "stop") == 0) {
        stop_server();
    }
    else {
        printf("Error: invalid command. Usage: %s start | stop\n", argv[0]);
    }
    return 0;
}
