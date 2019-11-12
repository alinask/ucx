/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <uct/base/uct_cm.h>
#include "rdmacm_def.h"


/**
 * RDMACM CM configuration.
 */
typedef struct uct_rdmacm_cm_config {
    uct_cm_config_t  super;
} uct_rdmacm_cm_config_t;


/**
 * An rdmacm connection manager
 */
typedef struct uct_rdmacm_cm {
    uct_cm_t                  super;
    struct rdma_event_channel *ev_ch;
} uct_rdmacm_cm_t;

UCS_CLASS_DECLARE(uct_rdmacm_cm_t, uct_component_h, uct_worker_h, const uct_cm_config_t*);
UCS_CLASS_DECLARE_NEW_FUNC(uct_rdmacm_cm_t, uct_cm_t, uct_component_h,
                           uct_worker_h, const uct_cm_config_t*);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_rdmacm_cm_t, uct_cm_t);

ucs_status_t uct_rdmacm_cm_destroy_id(struct rdma_cm_id *id);

ucs_status_t uct_rdmacm_cm_ack_event(struct rdma_cm_event *event);

ucs_status_t uct_rdmacm_cm_reject(struct rdma_cm_id *id);

extern ucs_config_field_t uct_rdmacm_cm_config_table[];
