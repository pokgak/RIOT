#ifndef NET_TLSCRED_H
#define NET_TLSCRED_H

#include <sys/types.h>

typedef enum {
    TLSCRED_PSK_HINT,
    TLSCRED_PSK_IDENTITY,
    TLSCRED_PSK_KEY,
} tlscred_type;

typedef int (*tlscred_load_credential_t)(tlscred_type type, const char *cred, size_t *credlen);

typedef struct psk_keys {
    const char *hint;
    size_t hint_len;
    const char *id;
    size_t id_len;
    const char *key;
    size_t key_len;
} psk_params_t;

typedef struct {
    psk_params_t psk;
    tlscred_load_credential_t load_credential;
} tlscred_t;

#endif /* NET_TLSCRED_H */
