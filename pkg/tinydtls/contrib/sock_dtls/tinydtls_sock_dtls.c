#include "dtls.h"
#include "tinydtls/dtls.h"
#include "net/sock/dtls.h"

#define RCV_BUFFER (512)

static dtls_handler_t _dtls_handler = {
    .event = _event,
#ifdef DTLS_PSK
    .get_psk_info = _get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = _get_ecdsa_key,
    .verify_ecdsa_key = _verify_ecdsa_key,
#endif /* DTLS_ECC */
    .write = _write,
    .read = _read,
};

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock, unsigned method)
{
    (void)method;
    assert(sock && udp_sock);
    sock->udp_sock = udp_sock;
    sock->dtls_ctx = dtls_new_context(sock);
    sock->queue = NULL;
    if (!sock->dtls_ctx) {
        DEBUG("Error while getting a DTLS context\n");
        return -1;
    }
    mbox_init(&sock->mbox, sock->mbox_queue, SOCK_DTLS_MBOX_SIZE);
    dtls_set_handler(sock->dtls_ctx, &_dtls_handler);
    return 0;
}

void sock_dtls_init_server(sock_dtls_t *sock, sock_dtls_queue_t *queue,
                           sock_dtls_session_t *queue_array, unsigned len)
{
    queue->array = queue_array;
    queue->len = len;
    queue->used = 0;
    //queue->mutex = NULL;
    sock->queue = queue;
}


int sock_dtls_establish_session(sock_dtls_t *sock, sock_dtls_ep_t *ep) {
    /* tinyDTLS */
    dtls_set_handler();
    dtls_connect() / dtls_connect_peer();   /* remote not null */
    
    dtls_get_peer();
    dtls_reset_peer();
    dtls_peer_state();
}

int sock_dtls_close_session(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_close();

}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_ep_t *ep, void *data, size_t maxlen) {
    /* tinyDTLS */
    dtls_handle_message();
}

int sock_dtls_send(sock_dtls_t *sock, sock_dtls_ep_t *ep, const void *data, size_t len) {
    /* tinyDTLS */
    dtls_write();

}

int sock_dtls_destroy(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_free_context();

}
