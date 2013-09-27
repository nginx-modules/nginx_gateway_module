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
} ngx_gateway_conf_addr_t;



#endif