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
 */

/* Called by autoinit. 
 * Initializes the memory management.
 */
int sock_dtls_init() {
    /* tinyDTLS */
    dtls_init();
    /* initialize PSK params */

}

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock, unsigned method) {
    /* tinyDTLS */
    dtls_new_context();
}

void sock_dtls_init_server(sock_dtls_t *sock) {
    /* tinyDTLS */
    dtls_set_handler();
    // dtls_connect() / dtls_connect_peer();     /* remote NULL */
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
