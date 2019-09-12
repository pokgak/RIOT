#include "net/sock/dtls.h"

void sock_dtls_init(void)
{
    return;
}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    (void)sock;
    (void)udp_sock;
    (void)tag;
    (void)version;
    (void)role;
    return 0;
}

int sock_dtls_session_create(sock_dtls_t *sock, const sock_udp_ep_t *ep,
                             sock_dtls_session_t *remote)
{
    (void)sock;
    (void)ep;
    (void)remote;
    return 0;
}

void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    (void)sock;
    (void)remote;
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       void *data, size_t maxlen, uint32_t timeout)
{
    (void)sock;
    (void)remote;
    (void)data;
    (void)maxlen;
    (void)timeout;
    return 0;
}

ssize_t sock_dtls_send(sock_dtls_t *sock, sock_dtls_session_t *remote,
                       const void *data, size_t len)
{
    (void)sock;
    (void)remote;
    (void)data;
    (void)len;
    return 0;
}

void sock_dtls_close(sock_dtls_t *sock)
{
    (void)sock;
}