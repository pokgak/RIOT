#include "net/tlsman.h"

static tlsman_handler_t handlers;

int tlsman_set_credentials_handler(tlsman_handler_t *h)
{
    if (h->get_psk_params != NULL) {
        handlers.get_psk_params = h->get_psk_params;
    }

    if (h->get_ecdsa_params != NULL) {
        handlers.get_ecdsa_params = h->get_ecdsa_params;
    }

    return 0;
}

int tlsman_get_psk_credentials(psk_params_t *psk)
{
    return handlers.get_psk_params(psk);
}

int tlsman_get_ecdsa_credentials(ecdsa_params_t *ecdsa)
{
    return handlers.get_ecdsa_params(ecdsa);
}
