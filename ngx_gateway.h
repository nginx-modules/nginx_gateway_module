/*
 * Copyright (c) 2013 zhuyx
 */

 #ifndef _NGX_GATEWAY_H_INCLUDED_
 #define _NGX_GATEWAY_H_INCLUDED_

 #include <nginx.h>
 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_event.h>
 #include <ngx_event_connect.h>

 typedef ngx_gateway_protocol_s ngx_gateway_protocol_t;
 typedef ngx_gateway_cleanup_s  ngx_gateway_cleanup_t;

 #include <ngx_gateway_session.h>

typedef struct {
	void				**main_conf;
	void				**srv_conf;
	void 				**biz_conf;
} ngx_gateway_conf_ctx_t;

typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_gateway_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_gateway_listen_t;

typedef struct {
    ngx_gateway_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
} ngx_gateway_addr_conf_t;

typedef struct {
	in_addr_t				addr;
	ngx_gateway_addr_conf_t conf;
} ngx_gateway_in_addr_t;

#if (NGX_HAVE_INET6)

typedef struct {
	struct in6_addr			addr6;
	ngx_gateway_addr_conf_t conf;
} ngx_gateway_in6_addr_t;

#endif

typedef struct {
	/*ngx_gateway_in_addr_t or ngx_gateway_in6_addr_t*/
	void					*addrs;
	ngx_uint_t				naddrs;
} ngx_gateway_port_t;

typedef struct {
	int 					family;
	in_port_t				port;
	ngx_array_t				addrs;		/* array of ngx_gateway_conf_addr_t */
} ngx_gateway_conf_port_t;

typedef struct {
	struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_gateway_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_gateway_conf_addr_t



typedef struct {
    ngx_array_t             servers;        /* ngx_gateway_core_srv_conf_t */
    ngx_array_t             listen;         /* ngx_gateway_listen_t */
} ngx_gateway_core_main_conf_t;

typedef struct {
    ngx_open_file_t          *file;
    time_t                  disk_full_time;
    time_t                  error_log_time;
} ngx_gateway_log_t;

typedef struct {
    u_char                  *start;
    u_char                  *pos;
    u_char                  *last;
} ngx_gateway_log_buf_t;


typedef struct {
    ngx_array_t             *logs;          /* array of ngx_gateway_log_t */

    ngx_open_file_cache_t   *open_file_cache;
    time_t                  open_file_cache_valid;
    ngx_uint_t              open_file_cache_min_uses;

    ngx_uint_t              off;            /* unsigned off:1 */
} ngx_gateway_log_srv_conf_t;

typedef struct {
    ngx_array_t             businesses;     /* array of ngx_gateway_core_biz_conf_t */

    ngx_gateway_protocol_t  *protocol;

    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;
    ngx_flag_t              tcp_nodelay;

    u_char                  *file_name;
    ngx_int_t               line;

    ngx_resolver_t          *resolver;

    /* 访问控制 */
    ngx_array_t             *rules;

    ngx_gateway_log_srv_conf_t  *access_log;

    /* server ctx */
    ngx_gateway_conf_ctx_t  *ctx;
} ngx_gateway_core_srv_conf_t;

typedef struct {
    ngx_array_t             businesses;     /* array of ngx_gateway_core_biz_conf_t */
    ngx_str_t               name;  
    void                    **biz_conf;
} ngx_gateway_core_biz_conf_t;

typedef void (*ngx_gateway_init_session_pt)(ngx_gateway_session_t *s);
typedef void (*ngx_gateway_init_protocol_pt)(ngx_event_t *rev);
typedef void (*ngx_gateway_parse_protcol_pt)(ngx_event_t *rev);

struct ngx_gateway_protocol_s { 
    ngx_str_t                       name;
    in_port_t                       port[4];
    ngx_uint_t                      type;

    ngx_gateway_init_session_pt     init_session;
    ngx_gateway_init_protocol_pt    init_protocol;
    ngx_gateway_parse_protcol_pt    pasrse_protocol;

    ngx_str_t                       internal_server_error;
};

typedef struct {
    ngx_gateway_protocol_t          *protocol;

    void                            *(*create_main_conf)(ngx_conf_t *cf);
    char                            *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                            *(*create_srv_conf)(ngx_conf_t *cf);
    char                            *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void* conf);

    void                            *(*create_biz_conf)(ngx_conf_t *cf);
    char                            *(*merge_biz_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_gateway_module_t;

#define NGX_GATEWAY_MODULE          0x5E2D2165

#define NGX_GATEWAY_MAIN_CONF       0x02000000
#define NGX_GATEWAY_SRV_CONF        0x04000000
#define NGX_GATEWAY_BIZ_CONF        0x08000000
#define NGX_GATEWAY_UPS_CONF        0x10000000

#define NGX_GATEWAY_MAIN_CONF_OFFSET    offsetof(ngx_gateway_conf_ctx_t, main_conf)
#define NGX_GATEWAY_SRV_CONF_OFFSET     offsetof(ngx_gateway_conf_ctx_t, srv_conf)
#define NGX_GATEWAY_BIZ_CONG_OFFSET     offsetof(ngx_gateway_conf_ctx_t, biz_conf)

#define ngx_gateway_get_module_ctx(s, module)       (s)->ctx[module.ctx_index]
#define ngx_gateway_set_ctx(s, c, module)           s->ctx[module.ctx_index] = c;
#define ngx_gateway_delete_ctx(s, module)           s->ctx[module.ctx_index] = NULL;

#define ngx_gateway_get_module_main_conf(s, module)                                 \
    (s)->main_conf[module.ctx_index]
#define ngx_gateway_get_module_srv_conf(s, module)                                  \
    (s)->srv_conf[module.ctx_index]
#define ngx_gateway_get_module_biz_conf(s, module)                                  \
    (s)->biz_conf[module.ctx_index]

#define ngx_gateway_conf_get_module_main_conf(cf, module)                           \
    ((ngx_gateway_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_gateway_conf_get_modlule_srv_conf(cf, module)                           \
    ((ngx_gateway_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_gateway_conf_get_module_biz_conf(cf, module)                            \
    ((ngx_gateway_conf_ctx_t *) cf->ctx)->biz_congf[module.ctx_index]

extern ngx_uint_t       ngx_gateway_max_module;
extern ngx_module_t     ngx_gateway_core_module;


#endif /* _NGX_GATEWAY_H_INCLUDED_ */