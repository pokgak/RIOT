/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_tinydtls_sock   tinyDTLS-specific implementation of the
 *                                  sock_dtls API
 * @ingroup     net_sock_dtls
 * @brief       Provides an implementation of the @ref net_sock_dtls using
 *              tinyDTLS
 *
 * @{
 *
 * @file
 * @brief   tinyDTLS-specific types and function definitions
 *
 * @author  Aiman Ismail <muhammadaimanbin.ismail@haw-hamburg.de>
 */
#ifndef SOCK_DTLS_TYPES_H
#define SOCK_DTLS_TYPES_H


#ifdef __cplusplus
extern "C" {
#endif

#include "event.h"
#include "dtls.h"
#include "net/sock/udp.h"

#ifndef SOCK_DTLS_MBOX_SIZE
#define SOCK_DTLS_MBOX_SIZE     (8)
#endif

typedef int (*psk_hint_storage_t)(struct sock_dtls *sock,
                                 struct sock_dtls_session *session,
                                 unsigned char *hint, size_t hint_len);

typedef int (*psk_id_storage_t)(struct sock_dtls *sock,
                                struct sock_dtls_session *session,
                                const unsigned char *hint, size_t hint_len,
                                unsigned char *id, size_t id_len);

typedef int (*psk_key_storage_t)(struct sock_dtls *sock,
                                 struct sock_dtls_session *session,
                                 const unsigned char *id, size_t id_len,
                                 unsigned char *key, size_t key_len);

typedef int (*ecdsa_storage_t)(struct sock_dtls *sock,
                               struct sock_dtls_session *session,
                               dtls_ecdsa_key_t **key);

typedef int (*ecdsa_verify_t)(struct sock_dtls *sock,
                              struct sock_dtls_session *session,
                              const unsigned char *pub_x,
                              const unsigned char *pub_y, size_t key_size);

typedef struct {
    psk_hint_storage_t psk_hint_storage;
    psk_id_storage_t psk_id_storage;
    psk_key_storage_t psk_key_storage;
} psk_keys_t;

typedef struct {
    ecdsa_storage_t ecdsa_storage;
    ecdsa_verify_t ecdsa_verify;
} ecdsa_keys_t;

struct sock_dtls {
    dtls_context_t *dtls_ctx;
    sock_udp_t *udp_sock;
    struct sock_dtls_queue *queue;
    mbox_t mbox;
    msg_t mbox_queue[SOCK_DTLS_MBOX_SIZE];
    uint8_t *buf;
    size_t buflen;
    psk_keys_t psk;
    ecdsa_keys_t ecdsa;
};

// what do i need to know about remote
/**
 * @brief Information about remote client connected to the server
 */
struct sock_dtls_session {
    sock_udp_ep_t   remote_ep;
    session_t       dtls_session;
};

struct sock_dtls_queue {
    struct sock_dtls_session *array;
    mutex_t mutex;
    unsigned short len;
    unsigned short used;
};

#ifdef __cplusplus
}
#endif

#endif /* SOCK_DTLS_TYPES_H */
/** @} */
