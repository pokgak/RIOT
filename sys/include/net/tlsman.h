/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net
 * @brief       Credentials management system for (D)TLS
 *
 * This module **doesn't** save the credentials in the system. It just
 * holds the pointers to the credentials given by the user.
 *
 * @note Limitation: only one entry for each type of credential
 *
 * @author      Aiman Ismail <muhammadaimanbin.ismail@haw-hamburg.de>
 */

#ifndef NET_TLSMAN_H
#define NET_TLSMAN_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *hint;
    const char *id;
    const char *key;
    size_t hint_len;
    size_t id_len;
    size_t key_len;
} psk_params_t;

typedef struct {
    const unsigned char *priv_key;
    const unsigned char *pub_key_x;
    const unsigned char *pub_key_y;
#ifdef USE_TINYDTLS // FIXME: remove?
    dtls_ecdh_curve curve;
#endif
} ecdsa_params_t;

typedef struct {
    /**
     * Called by tlsman_load_credential() to get PSK params from
     * the user and load it into the system. User must provide this to use
     * PSK for authentication.
     *
     * @param[in] psk   Must be filled with the requested information
     *
     * @return 0 on success
     * @return < 0 if error
     */
    int (*get_psk_params)(psk_params_t *psk);

    /**
     * Called by tlsman_load_credential() to get ECDSA params from
     * the user and load it into the system. User must provide this to use
     * ECDSA for authentication.
     *
     * @param[in] ecdsa   Must be filled with the requested information
     *
     * @return 0 on success
     * @return < 0 if error
     */
    int (*get_ecdsa_params)(ecdsa_params_t *ecdsa);
} tlsman_handler_t;

/**
 * @brief Set handler to get the credentials
 *
 * @param[in] cbs       Callbacks to access user-given credentials
 *
 * @return 0 on success
 * @return < 0 if error
 */
int tlsman_set_credentials_handler(tlsman_handler_t *h);

/**
 * @brief Get the registered PSK credentials
 *
 * @param[out] psk      This structure will be filled with PSK credentials
 * @return 0 on success
 * @return < 0 if error
 */
int tlsman_get_psk_credentials(psk_params_t *psk);

/**
 * @brief Get the registered ECDSA credentials
 *
 * @param[out] ecdsa    This structure will be filled with ECDSA credentials
 * @return 0 on success
 * @return < 0 if error
 */
int tlsman_get_ecdsa_credentials(ecdsa_params_t *ecdsa);

#ifdef __cplusplus
}
#endif

#endif /* NET_TLSMAN_H */
/** @} */
