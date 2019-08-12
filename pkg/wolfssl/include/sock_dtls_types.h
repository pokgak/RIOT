#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#include "net/sock/udp.h"
#include "net/credman.h"

struct sock_dtls {
    struct gnrc_wolfssl_ctx wolfssl;
    credman_tag_t tag;
}

struct sock_dtls_session {
    sock_udp_ep_t remote;
}