#include "net/sock/dtls.h"
#ifdef MODULE_SOCK_DTLS_TINYDTLS
#include "tinydtls/dtls.h"
#endif

/**
 * NOTES
 * =====
 * 
 * # TinyDTLS
 * 
 * - `dtls_renegotiate` and `dtls_check_retransmit` not yet used. Where to put? Internal event?
 * - tinyDTLS have event notifier that can notify applications for following events:
 *     + DTLS_EVENT_CONNECT
 *     + DTLS_EVENT_CONNECTED
 *     + DTLS_EVENT_RENEGOTIATE
 * - what about key storage/certificate ?
 * 
 * # wolfSSL
 * 
 * - certificate handling dont know yet where to put:
 *     + wolfSSL_CTX_set_verify
 *     + wolfSSL_CTX_use_certificate_buffer
 *     + wolfSSL_CTX_use_PrivateKey_buffer
 */

/* Called by autoinit. 
 * Initializes the memory management.
 */
int sock_dtls_init() {
    /* tinyDTLS */
    dtls_init();
    /* initialize PSK params */

    /* wolfSSL */
}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock, unsigned method) {
    /* tinyDTLS */
    dtls_new_context();

    // /* wolfSSL */
    // wolfSSL_CTX_new();
    // wolfSSL_SetIORecv();
    // wolfSSL_SetIOSend();
}

void sock_dtls_init_server(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_set_handler();
    // dtls_connect() / dtls_connect_peer();     /* remote NULL */

    // /* wolfSSL */
    // wolfSSL_new();
    // wolfSSL_SetIOReadCtx();
    // wolfSSL_SetIOWriteCtx();

    // wolfSSL_accept();
}

int sock_dtls_establish_session(sock_dtls_t *sock, sock_dtls_ep_t *ep) {
    /* tinyDTLS */
    dtls_set_handler();
    dtls_connect() / dtls_connect_peer();   /* remote not null */
    
    dtls_get_peer();
    dtls_reset_peer();
    dtls_peer_state();

    // /* wolfSSL */
    // wolfSSL_new();
    // wolfSSL_SetIOReadCtx();
    // wolfSSL_SetIOWriteCtx();

    // wolfSSL_connect();
}

int sock_dtls_close_session(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_close();

    // /* wolfSSL */
    // wolfSSL_free()
}

ssize_t sock_dtls_recv(sock_dtls_t *sock, sock_dtls_ep_t *ep, void *data, size_t maxlen) {
    /* tinyDTLS */
    dtls_handle_message();

    // /* wolfSSL */
    // wolfSSL_read();
}

int sock_dtls_send(sock_dtls_t *sock, sock_dtls_ep_t *ep, const void *data, size_t len) {
    /* tinyDTLS */
    dtls_write();

    // /* wolfSSL */
    // wolfSSL_write();
}

int sock_dtls_destroy(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_free_context();

    // /* wolfSSL */
    // sock_udp_close();
}
