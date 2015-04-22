
/*
 * Copyright (C) Justin Martin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CAS)

typedef struct {
    ngx_str_t                    staple;
    ngx_msec_t                   timeout;

    ngx_addr_t                  *addrs;
    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    ngx_str_t                    scan_host;
    in_port_t                    scan_port;
    ngx_str_t                    scan_version;
    unsigned                     scan_intensity:0;
    time_t                       scan_completed;

    unsigned                     verify:1;
    unsigned                     loading:1;
} ngx_ssl_config_audit_stapling_t;

static ngx_int_t ngx_ssl_config_audit_stapling_file(ngx_conf_t *cf,
                                                    ngx_ssl_t *ssl,
                                                    ngx_str_t *file);
static void ngx_ssl_config_audit_stapling_update(
                                       ngx_ssl_config_audit_stapling_t *staple);

static void ngx_ssl_config_audit_stapling_cleanup(void *data);

static u_char *ngx_ssl_config_audit_stapling_log_error(ngx_log_t *log,
                                                       u_char *buf, size_t len);
