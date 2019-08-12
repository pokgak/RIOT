int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    if (!sock) {
        return -EINVAL;
    }

    XMEMSET(sock->wolfssl, 0, sizeof(sock->wolfssl));
    
    WOLFSSL_METHOD *method = NULL;
    if (role == SOCK_DTLS_CLIENT) {
        DEBUG("sock_dtls: DTLS client\n");
        switch (version) {
        case SOCK_DTLS_1_0:
            DEBUG("sock_dtls: DTLS 1.0 not handled\n");
            break;
        case SOCK_DTLS_1_2:
            DEBUG("sock_dtls: DTLS version 1.2\n");
            method = wolfDTLSv1_2_client_method();
            break;
        case SOCK_DTLS_1_3:
            DEBUG("sock_dtls: DTLS 1.3 not handled\n");
            break;
        }
    }
    else if (role == SOCK_DTLS_SERVER) {
        DEBUG("sock_dtls: DTLS server\n");
        switch (version) {
        case SOCK_DTLS_1_0:
            DEBUG("sock_dtls: DTLS 1.0 not handled\n");
            break;
        case SOCK_DTLS_1_2:
            DEBUG("sock_dtls: DTLS version 1.2\n");
            method = wolfDTLSv1_2_server_method();
            break;
        case SOCK_DTLS_1_3:
            DEBUG("sock_dtls: DTLS 1.3 not handled\n");
            break;
        }
    }
    else {
        DEBUG("sock_dtls: unknown role\n");
        return -EINVAL;
    }

    sock->tag = tag;
    sock->wolfssl.ctx = wolfSSL_CTX_new(method);
    if (!sock->wolfssl.ctx){
        return -ENOMEM;
    }
    
    XMEMCPY(&sock->wolfssl.conn.udp, udp_sock, sizeof(sock_udp_t));

    return 0;
}

int sock_dtls_session_create(sock_dtls_t *sock, sock_udp_ep_t *ep,
                             sock_dtls_session_t *remote)
{
    if (!sock || !sock->wolfssl.ctx) {
        return -EINVAL;
    }

    XMEMCPY(&sock->wolfssl.peer_addr, ep, sizeof(sock_udp_ep_t));

    sock->wolfssl.ssl = wolfSSL_new(sock->wolfssl.ctx);
    if (!sock->wolfssl.ssl) {
        DEBUG("sock_dtls: error allocating ssl session\n");
        return -ENOMEM;
    }
    wolfSSL_SetIOReadCTX(sock->wolfssl.ssl, sock->wolfssl);
    wolfSSL_SetIOWriteCtx(sock->wolfssl.ssl, sock->wolfssl);
    sock->ssl->gnrcCtx = sock->wolfssl;

    memcpy(remote->remote, ep, sizeof(sock_udp_ep_t));

    /* start handshake */
    int ret = wolfSSL_connect(sock->wolfssl.ssl);
    if (ret != SSL_SUCCESS) {
        if (wolfSSL_get_error(sock->wolfssl.ssl, ret) == SOCKET_ERROR_E) {
            DEBUG("sock_dtls: socket error: reconnecting...\n");
            sock_dtls_session_destroy(sock->wolfssl);
            connect_timeout = 0;
            if (sock_dtls_session_create(sock->wolfssl) < 0) {
                return -1;
            }
        }
        if ((wolfSSL_get_error(sock->wolfssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
            (connect_timeout++ >= max_connect_timeouts)) {
                DEBUG("sock_dtls: server not responding: reconnecting...\n");
                sock_dtls_session_destroy(sock->wolfssl);
                connect_timeout = 0;
                if (sock_dtls_session_create(sock->wolfssl) < 0) {
                    return -1;
                }
            }
    }
    return 0;
}

void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    (void)remote;
    wolfSSL_free(sock->wolfssl);
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    (void)remote;
    (void)timeout;

    int ret = wolfSSL_write(sock->wolfssl.ssl, data, maxlen - 1);
    if (ret > 0) {
        return ret;
    }
    else {
        return wolfSSL_get_error(sock->wolfssl.ssl, ret);
    }

}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{
    (void)remote;
    int ret = wolfSSL_write(sock->wolfssl.ssl, data, len);
    if (ret > 0) {
        return ret;
    }
    else {
        return wolfSSL_get_error(sock->wolfssl.ssl, ret);
    }
}

void sock_dtls_close(sock_dtls_t *sock)
{
    (void)sock;
}