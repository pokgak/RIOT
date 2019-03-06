#include "dtls.h"
#include "tinydtls/dtls.h"
#include "net/sock/dtls.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#define RCV_BUFFER (512)

static void _timeout_callback(void *arg);

#ifdef DTLS_PSK
static int _get_psk_info(struct dtls_context_t *ctx, const session_t *session,
                         dtls_credentials_type_t type,
                         const unsigned char *id, size_t id_len,
                         unsigned char *result, size_t result_length);
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int _get_ecdsa_key(struct dtls_context_t *ctx, const session_t *session,
                          const dtls_ecdsa_key_t **result);

static int _verify_ecdsa_key(struct dtls_context_t *ctx,
                             const session_t *session,
                             const unsigned char *other_pub_x,
                             const unsigned char *other_pub_y,
                             size_t key_size);
#endif /* DTLS_ECC */

static int _write(struct dtls_context_t *ctx, session_t *session, uint8_t *buf,
                  size_t len);

static int _read(struct dtls_context_t *ctx, session_t *session, uint8_t *buf,
                 size_t len);

static int _event(struct dtls_context_t *ctx, session_t *session,
                  dtls_alert_level_t level, unsigned short code);

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

static int _write(struct dtls_context_t *ctx, session_t *session, uint8_t *buf,
                  size_t len)
{
    sock_dtls_t *sock = (sock_dtls_t *)dtls_get_app_data(ctx);
    sock_udp_ep_t remote;

    _session_to_udp_ep(session, &remote);
    remote.family = AF_INET6;

    // do we need remote?
    // if client maybe not, because udp_sock already has a remote pointing
    // to the server
    // but as a server we remote MUST be valid and not NULL
    // port must also not be 0
    ssize_t res = sock_udp_send(sock->udp_sock, buf, len, &remote);
    if (res <= 0) {
        DEBUG("Error: Failed to send DTLS record: %d\n", res);
    }
    return res;
}

static int _event(struct dtls_context_t *ctx, session_t *session,
           dtls_alert_level_t level, unsigned short code)
{
    (void)level;
    (void)session;

    sock_dtls_t *sock = dtls_get_app_data(ctx);
    msg_t msg = { .type = code };
#ifdef ENABLE_DEBUG
    switch(code) {
        case DTLS_EVENT_CONNECT:
            DEBUG("Event connect\n");
            break;
        case DTLS_EVENT_CONNECTED:
            DEBUG("Event connected\n");
            break;
        case DTLS_EVENT_RENEGOTIATE:
            DEBUG("Event renegotiate\n");
            break;
    }
#endif  /* ENABLE_DEBUG */
    mbox_put(&sock->mbox, &msg);
    return 0;
}

#ifdef DTLS_PSK
static int _get_psk_info(struct dtls_context_t *ctx, const session_t *session,
                         dtls_credentials_type_t type,
                         const unsigned char *id, size_t id_len,
                         unsigned char *result, size_t result_length)
{
    (void)session;
    sock_dtls_t *sock = (sock_dtls_t *)dtls_get_app_data(ctx);
    sock_dtls_session_t _session;
    sock_udp_ep_t ep;

    _session_to_udp_ep(session, &ep);
    _session.remote_ep = &ep;
    memcpy(&_session.dtls_session, session, sizeof(session_t));
    switch(type) {
        case DTLS_PSK_HINT:
            if (sock->psk.psk_hint_storage) {
                return sock->psk.psk_hint_storage(sock, &_session, result,
                                                  result_length);
            }
            return 0;

        case DTLS_PSK_IDENTITY:
            DEBUG("psk id request\n");
            if (sock->psk.psk_id_storage) {
                return sock->psk.psk_id_storage(sock, &_session, id, id_len,
                                                result, result_length);
            }
            return 0;
        case DTLS_PSK_KEY:
            if (sock->psk.psk_key_storage) {
                return sock->psk.psk_key_storage(sock, &_session, id, id_len,
                                                 result, result_length);
            }
            return 0;
        default:
            DEBUG("Unsupported request type: %d\n", type);
            return 0;
    }
}
#endif

#ifdef DTLS_ECC
static int _get_ecdsa_key(struct dtls_context_t *ctx, const session_t *session,
                          const dtls_ecdsa_key_t **result)
{
    dtls_ecdsa_key_t *key;
    sock_dtls_t *sock = (sock_dtls_t *)dtls_get_app_data(ctx);
    sock_dtls_session_t _session;
    sock_udp_ep_t ep;
    if (sock->ecdsa.ecdsa_storage) {
        _session_to_udp_ep(session, &ep);
        _session.remote_ep = &ep;
        memcpy(&_session.dtls_session, session, sizeof(session_t));
        if (sock->ecdsa.ecdsa_storage(sock, &_session, &key) < 0) {
            DEBUG("Could not get the ECDSA key\n");
            return -1;
        }
        *result = key;
        return 0;
    }
    DEBUG("no ecdsa storage registered\n");
    return -1;
}

static int _verify_ecdsa_key(struct dtls_context_t *ctx,
                             const session_t *session,
                             const unsigned char *other_pub_x,
                             const unsigned char *other_pub_y, size_t key_size)
{
    sock_dtls_session_t _session;
    sock_udp_ep_t ep;
    sock_dtls_t *sock = (sock_dtls_t *)dtls_get_app_data(ctx);
    if (sock->ecdsa.ecdsa_verify) {
        _session_to_udp_ep(session, &ep);
        _session.remote_ep = &ep;
        memcpy(&_session.dtls_session, session, sizeof(session_t));
        if (sock->ecdsa.ecdsa_verify(sock, &_session, other_pub_x, other_pub_y,
                                     key_size)) {
            DEBUG("Could not verify ECDSA public keys\n");
            return -1;
        }
    }
    return 0;
}
#endif /* DTLS_ECC */

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
    // no cannot we need a sock_udp_ep_t to fill in the information of remote ep of received data
    // and dtls_handle_message() needs a filled session_t, that requires information from sock_udp_ep_t
    assert(sock && data && remote);

    if ((timeout != SOCK_NO_TIMEOUT) && (timeout != 0)) {
        timeout_timer.callback = _timeout_callback;
        timeout_timer.arg = sock;
        xtimer_set(&timeout_timer, timeout);
    }

    res = sock_udp_recv(sock->udp_sock, data, max_len, timeout,
                        &remote->remote_ep);
    if (res < 0) {
        DEBUG("Error receiving UDP packet: %d\n", res);
        goto error_out;
    }

    // the function uses session to find peer, if no matching found then no peer, then fail and
    // return < 0
    // dtls_handle_message() uses the same buffer given to put the decrypted data, just
    // points to slightly vorne due to record header
    _ep_to_session(&remote->session, &remote->remote-ep);
    res = dtls_handle_message(sock->dtls_ctx, &remote->session,
                        (uint8_t *)data, res);
    if (res < 0) {
        DEBUG("Error decrypting message\n");
        goto error_out;
    }

    // blocks until we got a decrypted message OR TODO timeout
    // race condition between this and tinydtls _read callback?
    while (msg.type != DTLS_EVENT_READ || msg.type != _TIMEOUT_MSG_TYPE) {
        if (timeout != 0) {
            mbox_get(sock->mbox, &msg);
        }
        else {
            if (!mbox_try_get(sock->mbox, &msg)) {
                return -EAGAIN;
            }
        }
    }

    switch (msg.type) {
        case DTLS_EVENT_READ:
            DEBUG("Message decrypted successfully\n");
            data = sock->buf;
            return sock->buflen;
        case _TIMEOUT_MSG_TYPE:
            DEBUG("Error timed out while decrpting message\n");
            return -ETIMEDOUT;
        default:
            /* Falls through */
            return -EINVAL;
    }
}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{
    assert(sock && remote && data);
    return dtls_write(sock->dtls_ctx, &remote->session, (uint8_t *)data, len);
}

int sock_dtls_destroy(sock_dtls_t *sock)
{
    dtls_free_context(sock->dtls_ctx);
    return 0;
}

static void _ep_to_session(session_t *session, sock_udp_ep_t *ep) {
    session->port = ep->port; // only if WITH_CONTIKI is set
    session->size = sizeof(ipv6_addr_t);
    session->ifindex = ep->netif;
    memcpy(&session->addr, &ep->addr.ipv6, sizeof(ipv6_addr_t)); // can this be casted like that?
}

static void _session_to_udp_ep(const session_t *session, sock_udp_ep_t *ep)
{
    ep->port = session->port; // only if WITH_CONTIKI is set
    ep->netif = session->ifindex;
    memcpy(&ep->addr.ipv6, &session->addr, sizeof(ipv6_addr_t));
}

static void _timeout_callback(void *arg)
{
    msg_t timeout_msg = { .type = _TIMEOUT_MSG_TYPE };
    sock_dtls_t *sock = arg;
    mbox_try_put(&sock->mbox, &timeout_msg);
}
