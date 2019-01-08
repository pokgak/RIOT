#include "net/sock/udp.h"

/**
 * Methods for sock_dtls_create
 */
#define DTLSv1_SERVER
#define DTLSv1_CLIENT
#define DTLSv12_SERVER
#define DTLSv12_CLIENT

typedef struct sock_dtls {
    sock_udp_t *udp_sock;
    /* TODO */
} sock_dtls_t;

typedef struct sock_dtls_ep {
    sock_udp_ep_t *ep;
    /* TODO */
} sock_dtls_ep_t;

/**
 * @brief Creates a new DTLS sock object
 *
 * @param[out] sock     The resulting sock object
 * @param[in] udp_sock  Existing UDP sock to be used
 * @param[in] method    Defines the DTLS protocol for the client or server to use.
 *
 * @return  0 on success.
 */
int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock, unsigned method);

/**
 * @brief Initialises the server to listen for incoming connections
 *
 * @param[in] sock      DTLS sock to listens to
 */
void sock_dtls_init_server(sock_dtls_t *sock);

/**
 * @brief Establish DTLS session with a server. Execute the handshake step in DTLS.
 *
 * @param[in] sock      DLTS sock to use
 * @param[in] ep        Endpoint to establish session with
 *
 * @return 0 on success
 */
int sock_dtls_establish_session(sock_dtls_t *sock, sock_dtls_ep_t *ep);

/**
 * @brief Close an existing DTLS session
 *
 * @param[in] sock      DTLS session to close
 *
 * @return 0 on success.
 */
int sock_dtls_close_session(sock_dtls_t *sock);

/**
 * @brief Decrypts and reads a message from a remote peer
 *
 * @param[in] sock      DTLS sock to use
 * @param[in] ep        DTLS Endpoint to receive from
 * @param[out] buf      Pointer where the data should be stored
 * @param[in] maxlen    Maximum space available at @p data
 *
 * @return The number of bytes received on success
 */
ssize_t sock_dtls_recv(sock_dtls_t *sock, void *data, size_t max_len,
                       uint32_t timeout, sock_dtls_ep_t *remote);

/**
 * @brief Encrypts and send a message to a remote peer
 *
 * @param[in] sock      DTLS sock to use
 * @param[in] ep        DTLS enpoint to send to
 * @param[in] data      Pointer where the data to be send are stored
 * @param[in] len       Length of @p data to be send
 *
 * @return The number of bytes sent on success
 */
ssize_t sock_dtls_send(sock_dtls_t *sock, const void *data, size_t len,
                       sock_dtls_ep_t *remote);

/**
 * @brief Destroys DTLS sock created by `sock_dtls_create`
 *
 * @param sock          DTLS sock to destroy
 *
 * @return 0 on success
 */
int sock_dtls_destroy(sock_dtls_t *sock);