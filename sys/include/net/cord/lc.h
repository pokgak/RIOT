/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_cord_lc CoRE RD Lookup Client
 * @ingroup     net_cord
 * @brief       Library for using RIOT as CoRE Resource Directory lookup client
 *
 * This module implements a CoRE Resource Directory lookup client library, that
 * allows RIOT nodes to lookup resources, endpoints and groups with resource
 * directories.
 * It implements the standard lookup functionality as defined in
 * draft-ietf-core-resource-directory-20.
 * @see https://tools.ietf.org/html/draft-ietf-core-resource-directory-20
 *
 * @{
 *
 * @file
 * @brief       CoRE Resource Directory lookup interface
 *
 * @author      Aiman Ismail <muhammadaimanbin.ismail@haw-hamburg.de>
 */

#ifndef NET_CORD_LC_H
#define NET_CORD_LC_H

#include "net/sock/udp.h"
#include "net/nanocoap.h"
#include "clif.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Return values and error codes used by this module
 */
enum {
    CORD_LC_OK        =  0,     /**< everything went as expected */
    CORD_LC_TIMEOUT   = -1,     /**< no response from the network */
    CORD_LC_ERR       = -2,     /**< internal error or invalid reply */
    CORD_LC_OVERFLOW  = -3,     /**< internal buffers can not handle input */
    CORD_LC_NORSC     = -4,     /**< lookup interface not found */
};

/**
 * @brief  RD lookup types
 */
enum {
    CORD_LC_RES,                /**< Resource lookup type */
    CORD_LC_EP,                 /**< Endpoint lookup type */
};

/**
 * @brief  Information about RD server and its lookup interface resources
 */
typedef struct {
    const sock_udp_ep_t *remote;        /**< Remote endpoint of RD server */
    char *res_lookif;                   /**< Resource lookup interface */
    size_t res_lookif_len;              /**< Length of @p res_lookif */
    char *ep_lookif;                    /**< Endpoint lookup interface */
    size_t ep_lookif_len;               /**< Length of @p ep_lookif */
    unsigned res_last_page;             /**< Page of last resource lookup */
    unsigned ep_last_page;              /**< Page of last endpoint lookup */
} cord_lc_rd_t;

/**
 * @brief Result of lookup
 */
struct cord_lc_result {
    clif_t link;                /** Resource link */
    clif_attr_t *attrs;         /** Array of Link Format parameters */
    size_t max_attrs;           /** Max parameters at @p params */
};

typedef struct cord_lc_result cord_lc_res_t;    /**< Resource typedef */
typedef struct cord_lc_result cord_lc_ep_t;     /**< Endpoint typedef */

/**
 * @brief Filters to use for a lookup
 */
typedef struct cord_lc_filter {
    clif_attr_t *array;                     /**< Array of filter(s) */
    size_t len;                             /**< No. of filters at @p array */
    struct cord_lc_filter *next;            /**< Next set of filters */
} cord_lc_filter_t;

/**
 * @brief Discover the lookup interfaces of a RD server
 *
 * @param[out] rd       Information about RD server at @p remote
 * @param[in]  remote   Remote endpoint of RD server
 * @param[out] buf      Buffer to store found lookup interfaces
 * @param[in]  maxlen   Maximum memory available at @p lookif
 *
 * @return bytes used on success
 * @return CORD_LC_TIMEOUT if the discovery request times out
 * @return CORD_LC_NORSC if no lookup interfaces found for all types
 *         of lookups
 * @return CORD_LC_NOMEM if not enough memory available for result
 * @return CORD_LC_ERR on any other internal error
 */
ssize_t cord_lc_rd_init(cord_lc_rd_t *rd, const sock_udp_ep_t *remote,
                        void *buf, size_t maxlen);

/**
 * @brief Raw lookup for registered resources/endpoints at a RD server
 *
 * To specify the number of resources/endpoints to search for,
 * `count` and `page` attributes can be used as the filter.
 * If the same filter used multiple times with different values,
 * only the last filter will be applied.
 *
 * Content format (e.g. link-format, coral) must be set through
 * filters. If none defined, link-format will be used.
 *
 * @param[in]  rd               RD server to query
 * @param[in]  content_format   Data format wanted from RD server
 * @param[in]  lookup_type      Lookup type to use
 * @param[in]  filters          Filters for the lookup. Can be NULL.
 * @param[out] result           Buffer holding the raw response
 * @param[in]  maxlen           Max length of @p result
 *
 * @return bytes used on success
 * @return CORD_LC_NORSC if there is no lookup interface for @p lookup_type
 *         at @p rd
 * @return CORD_LC_TIMEOUT if lookup timed out
 * @return CORD_LC_NOMEM if not enough memory available for result
 * @return CORD_LC_ERR on any other internal error
 */
ssize_t cord_lc_raw(const cord_lc_rd_t *rd, unsigned content_format,
                    unsigned lookup_type, cord_lc_filter_t *filters,
                    void *result, size_t maxlen);

/**
 * @brief Get one resource from RD server
 *
 * Gets only one resource from specified RD server each time called.
 * Can be called iteratively to get all the resources on the server.
 * If there is no more resource on the server, it will return
 * CORD_LC_NORSC.
 *
 * @param[in]  rd               RD server to query
 * @param[out] resource         Resource link
 * @param[in]  filters          Filters for the lookup
 * @param[out] buf              Result buffer
 * @param[in]  buflen           Maximum memory available at @p buf
 *
 * @return bytes used on success
 * @return CORD_LC_INVALIF if the resource lookup interface at @p rd is invalid
 * @return CORD_LC_NORSC if there is no resource (anymore) at @p rd
 * @return CORD_LC_TIMEOUT if lookup timed out
 * @return CORD_LC_NOMEM if not enough memory available for result
 * @return CORD_LC_ERR on any other internal error
 */
ssize_t cord_lc_res(cord_lc_rd_t *rd, cord_lc_res_t *resource,
                    cord_lc_filter_t *filters, void* buf, size_t maxlen);

/**
 * @brief Get one endpoint from RD server
 *
 * Gets only one endpoint from specified RD server each time called.
 * Can be called iteratively to get all the endpoints on the server.
 * If there is no more endpoint on the server, it will return
 * CORD_LC_NORSC.
 *
 * @param[in]  rd               RD server to query
 * @param[out] endpoint         Resource link
 * @param[in]  filters          Filters for the lookup
 * @param[out] buf              Result buffer
 * @param[in]  buflen           Maximum memory available at @p buf
 *
 * @return bytes used on success
 * @return CORD_LC_INVALIF if the endpoint lookup interface at @p rd is invalid
 * @return CORD_LC_NORSC if there is no endpoints (anymore) at @p rd
 * @return CORD_LC_TIMEOUT if lookup timed out
 * @return CORD_LC_NOMEM if not enough memory available for result
 * @return CORD_LC_ERR on any other internal error
 */
ssize_t cord_lc_ep(cord_lc_rd_t *rd, cord_lc_ep_t *endpoint,
                   cord_lc_filter_t *filters, void* buf, size_t maxlen);

#ifdef __cplusplus
}
#endif

#endif /* NET_CORD_LC_H */
/** @} */
