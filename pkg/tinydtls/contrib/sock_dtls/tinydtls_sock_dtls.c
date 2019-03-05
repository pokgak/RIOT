#include "dtls.h"
#include "tinydtls/dtls.h"
#include "net/sock/dtls.h"

#define RCV_BUFFER (512)

static int _read(struct dtls_context_t *ctx, session_t *session, uint8_t *buf,
                 size_t len);

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

static int _read(struct dtls_context_t *ctx, session_t *session, uint8_t *buf,
                 size_t len)
{
    msg_t msg = { .type = DTLS_EVENT_READ };
    sock_dtls_t *sock = dtls_get_app_data(ctx);
    int res = 1;

    DEBUG("Decrypted message arrived\n");
    if (sock->buflen < len && sock->buf) {
        DEBUG("Not enough place on buffer\n");
        res = -1;
    }
    else {
        sock->buflen = len;
        sock->buf = buf;
    }
    mbox_put(&sock->mbox, &msg);
    return res;
}

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
                                sock_dtls_session_t *remote)
{
    uint8_t rcv_buffer[RCV_BUFFER];
    msg_t msg;

    assert(sock && ep && remote);

    // FIXME: change name of sock_dtls_session_t to not confused with session_t from tinydtls
    /* prepare a dtls session (remote party to connect to) */
    memset(remote, 0, sizeof(sock_dtls_session_t));
    memcpy(&remote->remote_ep, ep, sizeof(sock_udp_ep_t));
    memcpy(&remote->dtls_session.addr, &ep->addr.ipv6, sizesof(ipv6_addr_t));
    remote->dtls_session.ifindex = ep->netif;
    remote->dtls_session.size = sizeof(remote->dtls_session);

    /* start a handshake */
    if (dtls_connect(sock->dtls_ctx, &remote->dtls_session) < 0) {
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
    // can an application data sent to ep A (this ep) from ep B interrupt ongoing handshake
    // between this ep (A) and other ep (C)?
    /* receive packages from sock until the session is established */
    while (!mbox_try_get(&sock->mbox, &msg)) {
        ssize_t rcv_len = sock_udp_recv(sock->udp_sock, rcv_buffer,
                                        sizeof(rcv_buffer), SOCK_NO_TIMEOUT,
                                        &remote->remote_ep);
        if (rcv_len >= 0) {
            dtls_handle_message(sock->dtls_ctx, &remote->session, rcv_buffer,
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

int sock_dtls_close_session(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    return dtls_close(sock->dtls_ctx, &remote->session);
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t max_len, uint32_t timeout)
{
    ssize_t res;
    msg_t msg;

    // what if remote is NULL? can remote be NULL?
    // no cannot we need a session_t to fill in the information of remote ep of received data
    assert(sock && data && remote);

    while (1) {
        // should we include receive sock
        res = sock_udp_recv(sock->udp_sock, data, max_len, timeout,
                            &remote->remote_ep);
        if (res > 0) {
            // the function uses session to find peer, if no matching found then no peer, then fail and
            // return < 0
            // dtls_handle_message() uses the same buffer given to put the decrypted data, just
            // points to slightly vorne due to record header
            // TODO: handle if return < 1?
            _ep_to_session(&remote->session, &remote->remote-ep);
            dtls_handle_message(sock->dtls_ctx, &remote->session,
                                (uint8_t *)data, res);

            // blocks until we got a decrypted message OR TODO timeout
            while (msg.type != DTLS_EVENT_READ) {
                mbox_get(&sock->mbox, &msg);
            }
            data = sock->buf;
            return sock->buflen;
        }
        // TODO: handle errors from sock_udp_recv()
        else {
            DEBUG("Error receiving UDP packet: %d\n", res);
            goto error_out;
        }
    }

error_out:
    return res;
}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{

}

int sock_dtls_destroy(sock_dtls_t *sock)
{
    dtls_free_context(sock->dtls_ctx);
    return 0;
}

static void _ep_to_session(session_t *session, sock_udp_ep_t *ep) {
    //session->port = ep->port; // if WITH_CONTIKI not defined, then no port
    session->size = sizeof(ipv6_addr_t);
    session->ifindex = ep->netif;
    memcpy(&session->addr, &ep->addr.ipv6, sizeof(ipv6_addr_t)); // can this be casted like that?
}
