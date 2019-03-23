#ifndef NET_TLSCRED_H
#define NET_TLSCRED_H

#include <sys/types.h>

typedef struct {
    const char *hint;
    size_t hint_len;
    const char *id;
    size_t id_len;
    const char *key;
    size_t key_len;
} psk_keys_t;

typedef struct {
    void *priv_key;
    void *pub_key_x;
    void *pub_key_y;
} ecdsa_keys_t;

typedef struct {
    psk_keys_t psk;
    ecdsa_keys_t ecdsa;
    /* more supported credential goes here */
} tlscred_t;

typedef enum {
    TLSCRED_PSK_HINT,
    TLSCRED_PSK_IDENTITY,
    TLSCRED_PSK_KEY,
} tlscred_type;

/**
 * @brief Add a TLS credential.
 *
 * @param[in] cred      A security tag that credential will be referenced with
 * @param[in] type      A TLS/DTLS credential type
 * @param[in] value     A TLS/DTLS credential
 * @param[in] len       Length of @p cred
 *
 * @return 0 if success
 * @return < 0 if error
 */
int tlscred_add_psk_info(tlscred_t *cred, tlscred_type type,
                         const void *val, size_t len);

/**
 * @brief Get an already registered TLS credential, referenced by @p tag secure
 *        tag of @p type
 *
 * @param[in] tag       A Security tag of requested credential
 * @param[in] type      A TLS/DTLS credential type of requested credential
 * @param[out] result   A buffer to write the TLS/DTLS credential to
 * @param[in] len       Length of the buffer available at @p cred
 *
 * @return 0 on success
 * @return < 0 if error
 */
int tlscred_get(tlscred_t *cred, tlscred_type type, void *result,
                size_t len);

/**
 * @brief Delete a TLS credential referenced by @p tag of type @p type
 *
 * @param[in] tag       A security tag corresponding to credential to be
 *                      removed
 * @param[in] type      A TLS/DTLS credential type of credential to be removed
 *
 * @return 0 on success
 * @return < 0 if error
 */
int tlscred_delete(tlscred_t *cred, tlscred_type type);

#endif /* NET_TLSCRED_H */
