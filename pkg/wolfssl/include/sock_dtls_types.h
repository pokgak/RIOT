/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @brief   wolfssl-specific types and functions definitions
 *
 * @author  Aiman Ismail <muhammadaimanbin.ismail@haw-hamburg.de>
 * @author  Leandro Lanzieri <leandro.lanzieri@haw-hamburg.de>
 */

#ifndef SOCK_DTLS_TYPES_H
#define SOCK_DTLS_TYPES_H

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "net/sock/udp.h"
#include "net/credman.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOCK_DTLS_MBOX_SIZE
#define SOCK_DTLS_MBOX_SIZE     (4)         /**< Size of DTLS sock mailbox */
#endif

/**
 * @brief Information about DTLS sock
 */
struct sock_dtls {
    int test;
};

/**
 * @brief Information about remote client connected to the server
 */
struct sock_dtls_session {
    int test;
};

#ifdef __cplusplus
}
#endif

#endif /* SOCK_DTLS_TYPES_H */
/** @} */
