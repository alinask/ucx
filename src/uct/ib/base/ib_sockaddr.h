/**
 * Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCS_SOCKADDR_H_
#define UCS_SOCKADDR_H_

#include "ib_verbs.h"
#include "ib_iface.h"

#include "string.h"
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>
#include <ucs/time/time.h>
#include <ucs/sys/string.h>
#include <ucs/config/types.h>
#include <ucs/async/async.h>

#ifdef HAVE_RDMACM
#include <rdma/rdma_cma.h>

ucs_status_t uct_ib_sockaddr_rdmacm_resolve_addr(struct rdma_cm_id *cm_id,
                                                 struct sockaddr *addr, int timeout_ms,
                                                 ucs_log_level_t log_level);

#endif

int uct_ib_is_sockaddr_accessible(struct sockaddr *addr,
                                  uct_sockaddr_accessibility_t mode,
                                  double addr_resolve_timeout);

ucs_status_t uct_ib_sockaddr_fill_ah_attr(struct sockaddr_storage *addr,
                                          struct ibv_ah_attr *ah_attr);

ucs_status_t uct_ib_sockaddr_setup_server_side(uct_ib_iface_t *iface);

void uct_ib_sockaddr_destroy_server_side(uct_ib_iface_t *iface);

void uct_ib_sockaddr_server_event_handler(uct_ib_iface_t *iface);

#endif
