/**
 * Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "ib_sockaddr.h"

#ifdef HAVE_RDMACM

ucs_status_t uct_ib_sockaddr_rdmacm_resolve_addr(struct rdma_cm_id *cm_id,
                                                 struct sockaddr *addr, int timeout_ms,
                                                 ucs_log_level_t log_level)
{
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];

    if (rdma_resolve_addr(cm_id, NULL, addr, timeout_ms)) {
        ucs_log(log_level, "rdma_resolve_addr(addr=%s) failed: %m",
                ucs_sockaddr_str(addr, ip_port_str, UCS_SOCKADDR_STRING_LEN));
        return UCS_ERR_IO_ERROR;
    }
    return UCS_OK;
}

static int uct_ib_sockaddr_rdmacm_get_event_type(struct rdma_event_channel *event_ch,
                                                 struct rdma_cm_event *event_copy)
{
    struct rdma_cm_event *event = NULL;
    int ret, event_type;

    /* Fetch an event */
    ret = rdma_get_cm_event(event_ch, &event);
    if (ret) {
        ucs_warn("rdma_get_cm_event() failed: %m");
        return 0;
    }

    event_type = event->event;
    /* save a copy of this event so that we can access it later, after acking it. */
    memcpy(event_copy, event, sizeof(*event));

    ret = rdma_ack_cm_event(event);
    if (ret) {
        ucs_warn("rdma_ack_cm_event() failed. event status: %d. %m.", event->status);
    }

    return event_type;
}

static int uct_ib_sockaddr_is_route_resolved(struct rdma_cm_id *cm_id,
                                             struct sockaddr *addr,
                                             int timeout_ms, ucs_log_level_t log_level)
{
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    ucs_status_t status;
    int event_type;
    struct rdma_cm_event event_copy;

    status = uct_ib_sockaddr_rdmacm_resolve_addr(cm_id, addr, timeout_ms, log_level);
    if (status != UCS_OK) {
        return 0;
    }

    event_type = uct_ib_sockaddr_rdmacm_get_event_type(cm_id->channel, &event_copy);
    if (event_type != RDMA_CM_EVENT_ADDR_RESOLVED) {
        ucs_log(log_level, "failed to resolve address (addr = %s). RDMACM event %s.",
                ucs_sockaddr_str(addr, ip_port_str, UCS_SOCKADDR_STRING_LEN),
                rdma_event_str(event_type));
        return 0;
    }

    if (rdma_resolve_route(cm_id, timeout_ms)) {
        ucs_log(log_level, "rdma_resolve_route(addr = %s) failed: %m",
                ucs_sockaddr_str(addr, ip_port_str, UCS_SOCKADDR_STRING_LEN));
        return 0;
    }

    event_type = uct_ib_sockaddr_rdmacm_get_event_type(cm_id->channel, &event_copy);
    if (event_type != RDMA_CM_EVENT_ROUTE_RESOLVED) {
        ucs_log(log_level, "failed to resolve route to addr = %s. RDMACM event %s.",
                ucs_sockaddr_str(addr, ip_port_str, UCS_SOCKADDR_STRING_LEN),
                rdma_event_str(event_type));
        return 0;
    }

    return 1;
}

static int uct_ib_sockaddr_is_inaddr_any(struct sockaddr *addr)
{
    struct sockaddr_in6 *addr_in6;
    struct sockaddr_in *addr_in;

    switch (addr->sa_family) {
    case AF_INET:
        addr_in = (struct sockaddr_in *)addr;
        return addr_in->sin_addr.s_addr == INADDR_ANY;
    case AF_INET6:
        addr_in6 = (struct sockaddr_in6 *)addr;
        return !memcmp(&addr_in6->sin6_addr, &in6addr_any, sizeof(addr_in6->sin6_addr));
    default:
        ucs_debug("Invalid address family: %d", addr->sa_family);
    }

    return 0;
}

#endif

int uct_ib_is_sockaddr_accessible(struct sockaddr *addr,
                                  uct_sockaddr_accessibility_t mode,
                                  double addr_resolve_timeout)
{
#ifdef HAVE_RDMACM
    struct rdma_event_channel *event_ch = NULL;
    struct rdma_cm_id *cm_id = NULL;
    int is_accessible = 0;
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];

    if ((mode != UCT_SOCKADDR_ACC_LOCAL) && (mode != UCT_SOCKADDR_ACC_REMOTE)) {
        ucs_error("Unknown sockaddr accessibility mode %d", mode);
        return 0;
    }

    event_ch = rdma_create_event_channel();
    if (event_ch == NULL) {
        ucs_error("rdma_create_event_channel() failed: %m");
        goto out;
    }

    if (rdma_create_id(event_ch, &cm_id, NULL, RDMA_PS_UDP)) {
        ucs_error("rdma_create_id() failed: %m");
        goto out_destroy_event_channel;
    }

    if (mode == UCT_SOCKADDR_ACC_LOCAL) {
        /* Server side to check if can bind to the given sockaddr */
        if (rdma_bind_addr(cm_id, addr)) {
            ucs_debug("rdma_bind_addr(addr = %s) failed: %m",
                      ucs_sockaddr_str(addr, ip_port_str, UCS_SOCKADDR_STRING_LEN));
            goto out_destroy_id;
        }

        if (uct_ib_sockaddr_is_inaddr_any(addr)) {
            is_accessible = 1;
            goto out_print;
        }
    }

    /* Client and server sides check if can access the given sockaddr.
     * The timeout needs to be passed in ms */
    is_accessible = uct_ib_sockaddr_is_route_resolved(cm_id,
                                                      addr,
                                                      UCS_MSEC_PER_SEC * addr_resolve_timeout,
                                                      UCS_LOG_LEVEL_DEBUG);
    if (!is_accessible) {
        goto out_destroy_id;
    }

out_print:
    ucs_debug("address %s (port %d) is accessible with mode: %d",
              ucs_sockaddr_str(addr, ip_port_str,
                               UCS_SOCKADDR_STRING_LEN),
                               ntohs(rdma_get_src_port(cm_id)), mode);

out_destroy_id:
    rdma_destroy_id(cm_id);
out_destroy_event_channel:
    rdma_destroy_event_channel(event_ch);
out:
    return is_accessible;

#else
    return 0;
#endif
}

#ifdef HAVE_RDMACM

static UCS_F_ALWAYS_INLINE
void uct_ib_sockaddr_fill_ah_attr_from_rdmacm_event(struct rdma_cm_event *event,
                                                    struct ibv_ah_attr *ah_attr)
{
    char p[128];

    memset(ah_attr, 0, sizeof(*ah_attr));
    memcpy(ah_attr, &event->param.ud.ah_attr, sizeof(*ah_attr));

    inet_ntop(AF_INET6, &ah_attr->grh.dgid, p, sizeof(p));
    ucs_debug("RDMACM packed in ah_attr: dgid %s. sgid_index: %d",
              p, ah_attr->grh.sgid_index);
}

/**
 * Set an address for the server to listen on - INADDR_ANY on a well known port.
 */
void uct_ib_sockaddr_set_listen_addr(struct sockaddr_in *listen_addr)
{
    /* The server will listen on INADDR_ANY */
    memset(listen_addr, 0, sizeof(struct sockaddr_in)); //ipv4 for now
    listen_addr->sin_family      = AF_INET;
    listen_addr->sin_addr.s_addr = INADDR_ANY;
    listen_addr->sin_port        = 0;    /* each process will get its own port */
}

static ucs_status_t uct_ib_sockaddr_setup_client_side(struct rdma_event_channel **event_ch,
                                                      struct sockaddr_storage *remote_addr,
                                                      struct rdma_cm_id **cm_id)
{
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    struct rdma_conn_param conn_param;
    ucs_status_t status = UCS_OK;
    int ret;

    /* create an event channel and keep in a blocking mode for now.
     * Since this is blocking, it should be running from the main thread */
    *event_ch = rdma_create_event_channel();
    if (event_ch == NULL) {
        ucs_error("rdma_create_event_channel failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    if (rdma_create_id(*event_ch, cm_id, NULL, RDMA_PS_UDP)) {
        ucs_error("rdma_create_id() remote failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_event_channel;
    }

    ret = uct_ib_sockaddr_is_route_resolved(*cm_id, (struct sockaddr *)remote_addr,
                                            UCS_MSEC_PER_SEC * 0.5,
                                            UCS_LOG_LEVEL_ERROR);
    if (!ret) {
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_id;
    }

    memset(&conn_param, 0, sizeof(conn_param));
    if (rdma_connect(*cm_id, &conn_param)) {
        ucs_error("rdma_connect(to addr=%s) failed: %m",
                  ucs_sockaddr_str((struct sockaddr *)remote_addr, ip_port_str,
                                   UCS_SOCKADDR_STRING_LEN));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_id;
    }

    ucs_debug("rdma_connect(to addr=%s)",
              ucs_sockaddr_str((struct sockaddr *)remote_addr, ip_port_str,
                               UCS_SOCKADDR_STRING_LEN));
    return status;

err_destroy_id:
    rdma_destroy_id(*cm_id);
err_destroy_event_channel:
    rdma_destroy_event_channel(*event_ch);
err:
    return status;
}

static void uct_ib_sockaddr_rdmacm_accept(struct rdma_cm_event *event,
                                          struct sockaddr *remote_addr)
{
    struct rdma_conn_param conn_param;
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];

    memset(&conn_param, 0, sizeof(conn_param));
    if (rdma_accept(event->id, &conn_param)) {
        ucs_error("rdma_accept(to addr=%s) failed: %m.",
                  ucs_sockaddr_str((struct sockaddr *)remote_addr, ip_port_str,
                                   UCS_SOCKADDR_STRING_LEN));
        rdma_reject(event->id, NULL, 0);
    }

    /* Destroy the new rdma_cm_id which was created when receiving the
     * RDMA_CM_EVENT_CONNECT_REQUEST event. (this is not the listening rdma_cm_id)*/
    rdma_destroy_id(event->id);
}

#endif


ucs_status_t uct_ib_sockaddr_setup_server_side(uct_ib_iface_t *iface)
{
#ifdef HAVE_RDMACM
    struct sockaddr_storage listen_addr;
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    ucs_status_t status;

    UCS_ASYNC_BLOCK(iface->super.worker->async);

    iface->event_ch = rdma_create_event_channel();
    if (iface->event_ch == NULL) {
        ucs_error("rdma_create_event_channel failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* Set the event_channel fd to non-blocking mode
     * (so that rdma_get_cm_event won't be blocking) */
    status = ucs_sys_fcntl_modfl(iface->event_ch->fd, O_NONBLOCK, 0);
    if (status != UCS_OK) {
        goto err_destroy_event_channel;
    }

    if (rdma_create_id(iface->event_ch, &iface->cm_id, NULL, RDMA_PS_UDP)) {
        ucs_error("rdma_create_id() failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_event_channel;
    }

    uct_ib_sockaddr_set_listen_addr((struct sockaddr_in *)&listen_addr);

    if (rdma_bind_addr(iface->cm_id, (struct sockaddr *)&listen_addr)) {
        ucs_error("rdma_bind_addr(addr=%s) failed: %m",
                  ucs_sockaddr_str((struct sockaddr *)&listen_addr,
                                   ip_port_str, UCS_SOCKADDR_STRING_LEN));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_id;
    }

    if (rdma_listen(iface->cm_id, 1024)) {
        ucs_error("rdma_listen(cm_id:=%p event_channel=%p addr=%s) failed: %m",
                  iface->cm_id, iface->event_ch,
                  ucs_sockaddr_str((struct sockaddr *)&listen_addr,
                                   ip_port_str, UCS_SOCKADDR_STRING_LEN));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_id;
    }

    ucs_debug("rdma_listen(cm_id:=%p event_channel=%p addr=%s fd=%d) port: %d",
              iface->cm_id, iface->event_ch,
              ucs_sockaddr_str((struct sockaddr *)&listen_addr,
                               ip_port_str, UCS_SOCKADDR_STRING_LEN),
                               iface->event_ch->fd,
                               ntohs(rdma_get_src_port(iface->cm_id)));

    iface->sockaddr_port = rdma_get_src_port(iface->cm_id);

    UCS_ASYNC_UNBLOCK(iface->super.worker->async);
    return UCS_OK;

err_destroy_event_channel:
    rdma_destroy_event_channel(iface->event_ch);
err_destroy_id:
    rdma_destroy_id(iface->cm_id);
err:
    UCS_ASYNC_UNBLOCK(iface->super.worker->async);
    return status;

#else
    ucs_fatal("RDMACM must be compiled in to support connection establishment through sockaddr");
#endif
}

void uct_ib_sockaddr_destroy_server_side(uct_ib_iface_t *iface)
{
#ifdef HAVE_RDMACM
    UCS_ASYNC_BLOCK(iface->super.worker->async);
    rdma_destroy_id(iface->cm_id);
    rdma_destroy_event_channel(iface->event_ch);
    UCS_ASYNC_UNBLOCK(iface->super.worker->async);
#else
    ucs_fatal("RDMACM must be compiled in to support connection establishment through sockaddr");
#endif
}

void uct_ib_sockaddr_server_event_handler(uct_ib_iface_t *iface)
{
#ifdef HAVE_RDMACM
    struct rdma_cm_event *event;
    struct sockaddr *remote_addr;
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    int ret;

    for (;;) {
        /* Fetch an event */
        ret = rdma_get_cm_event(iface->event_ch, &event);
        if (ret) {
            /* EAGAIN (in a non-blocking rdma_get_cm_event) means that
             * there are no more events */
            if (errno != EAGAIN) {
                ucs_warn("rdma_get_cm_event() failed: %m");
            }
            return;
        }

        remote_addr = rdma_get_peer_addr(event->id);

        ucs_debug("rdmacm event (fd=%d cm_id %p) on iface=%p: %s. Peer: %s.",
                  iface->event_ch->fd, event->id, iface, rdma_event_str(event->event),
                  ucs_sockaddr_str(remote_addr, ip_port_str, UCS_SOCKADDR_STRING_LEN));

        switch (event->event) {
        case RDMA_CM_EVENT_CONNECT_REQUEST:
            uct_ib_sockaddr_rdmacm_accept(event, remote_addr);
            break;
        default:
            ucs_warn("unexpected RDMACM event: %s", rdma_event_str(event->event));
            break;
        }

        ret = rdma_ack_cm_event(event);
        if (ret) {
            ucs_warn("rdma_ack_cm_event() failed: %m");
        }
    }

#else
    ucs_fatal("RDMACM must be compiled in to support connection establishment through sockaddr");
#endif
}

ucs_status_t uct_ib_sockaddr_fill_ah_attr(struct sockaddr_storage *remote_addr,
                                          struct ibv_ah_attr *ah_attr)
{
#ifdef HAVE_RDMACM
    struct rdma_event_channel *event_ch;
    struct rdma_cm_id *cm_id_to_remote;
    struct rdma_cm_event event_copy;
    ucs_status_t status = UCS_OK;
    int event_type;

    /* Setup a client side to connect to remote server. Once the client gets the
     * RDMA_CM_EVENT_ESTABLISHED event, it can fill the address_handle attributes */

    /* Connect to the remote peer so that RDMACM can gather ah attributes
     * once the peer (server) accepts the connection request. */
    status = uct_ib_sockaddr_setup_client_side(&event_ch, remote_addr, &cm_id_to_remote);
    if (status != UCS_OK) {
        goto out;
    }

    event_type = uct_ib_sockaddr_rdmacm_get_event_type(event_ch, &event_copy);
    if (event_type != RDMA_CM_EVENT_ESTABLISHED) {
        ucs_error("Unexpected RDMACM event: %s.", rdma_event_str(event_type));
        status = UCS_ERR_IO_ERROR;
        goto out_destroy_client_side;
    }

    /* RDMACM provides the required information for filling the ah_attr
     * only after receiving the RDMA_CM_EVENT_ESTABLISHED event. */
    uct_ib_sockaddr_fill_ah_attr_from_rdmacm_event(&event_copy, ah_attr);

out_destroy_client_side:
    rdma_destroy_id(cm_id_to_remote);   /* same as event_copy.id */
    rdma_destroy_event_channel(event_ch);
out:
    return status;

#else
    ucs_fatal("RDMACM must be compiled in to support connection establishment through sockaddr");
#endif
}
