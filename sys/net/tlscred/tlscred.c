#include "net/tlscred.h"
#include <string.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

int tlscred_add_psk_info(tlscred_t *cred, tlscred_type type,
                         const void *val, size_t len)
{
    switch (type) {
        case TLSCRED_PSK_IDENTITY:
            cred->psk.id = val;
            cred->psk.id_len = len;
            break;
        case TLSCRED_PSK_KEY:
            cred->psk.key = val;
            cred->psk.key_len = len;
            break;
        case TLSCRED_PSK_HINT:
            cred->psk.hint = val;
            cred->psk.hint_len = len;
            break;
        default:
            DEBUG("ERROR: Unsupported credential type\n");
            return -1;
    }

    return 0;
}

int tlscred_get(tlscred_t *cred, tlscred_type type, void *result, size_t len)
{
    switch (type) {
        case TLSCRED_PSK_HINT:
            if (len < cred->psk.hint_len) {
                DEBUG("ERROR: not enough space at buffer\n");
                return -1;
            }

            memcpy(result, cred->psk.hint, cred->psk.hint_len);
            break;
        case TLSCRED_PSK_IDENTITY:
            if (len < cred->psk.id_len) {
                DEBUG("ERROR: not enough space at buffer\n");
                return -1;
            }

            memcpy(result, cred->psk.id, cred->psk.id_len);
            break;
        case TLSCRED_PSK_KEY:
            if (len < cred->psk.key_len) {
                DEBUG("ERROR: not enough space at buffer\n");
                return -1;
            }

            memcpy(result, cred->psk.key, cred->psk.key_len);
            break;
    }

    return 0;
}

int tlscred_delete(tlscred_t *cred, tlscred_type type)
{
    (void)cred;
    (void)type;
    return 0;
}
