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

int sock_dtls_establish_session(sock_dtls_t *sock, sock_udp_ep_t *ep,
                                sock_dtls_session_t *session)
{
    uint8_t rcv_buffer[RCV_BUFFER];
    msg_t msg;
    session_t dtls_session;

    /* get a tinydtls session (remote party to connect to) */
    // FIXME: change name of sock_dtls_session_t to not confused with session_t from tinydtls
    memcpy(dtls_session.addr, &ep->addr.ipv6, sizesof(ipv6_addr_t));
    dtls_session.ifindex = ep->netif;
    dtls_session.size = sizeof(session->peer->session.addr);

    session->peer = dtls_new_peer(&dtls_session);
    session->remote_ep = ep;

    /* start a handshake */
    if (dtls_connect(sock->dtls_ctx, &session->peer->session) < 0) {
        DEBUG("Error establishing a session\n");
        return -1;
    }
    DEBUG("Waiting for ClientHello to be sent\n");
    mbox_get(&sock->mbox, &msg);
    if (msg.type != DTLS_EVENT_CONNECT) {
        DEBUG("DTLS handshake was not started\n");
        return -1;
    }
    DEBUG("ClientHello sent, waiting for handshake\n");
    /* receive packages from sock until the session is established */
    while (!mbox_try_get(&sock->mbox, &msg)) {
        ssize_t rcv_len = sock_udp_recv(sock->udp_sock, rcv_buffer,
                                        sizeof(rcv_buffer), SOCK_NO_TIMEOUT,
                                        &session->remote_ep);
        if (rcv_len >= 0) {
            dtls_handle_message(sock->dtls_ctx, &session->peer->session, rcv_buffer,
                                rcv_len);
        }
    }

    if (msg.type == DTLS_EVENT_CONNECTED) {
        DEBUG("DTLS handshake successful\n");
        return 0;
    }
    else {
        DEBUG("DTLS handshake was not successful\n");
        return -1;
    }
}

int sock_dtls_close_session(sock_dtls_t *sock, sock_dtls_session_t *session)
{
    return dtls_close(sock->dtls_ctx, &session->peer->session);
