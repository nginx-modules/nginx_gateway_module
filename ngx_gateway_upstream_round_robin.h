
#ifndef _NGX_GATEWAY_UPSTREAM_ROUND_ROBIN_H_
#define _NGX_GATEWAY_UPSTREAM_ROUND_ROBIN_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_gateway.h>

typedef struct {
	struct sockaddr					*sockaddr;
	socklen_t						socklen;
	ngx_str_t 						name;

	ngx_int_t						current_weight;
	ngx_int_t						weight;

	ngx_uint_t						fails;
	time_t 							accessed;

	ngx_uint_t						max_fails;
	time_t							fail_timeout;

	ngx_int_t 						check_index;

	ngx_uint_t 						down;
} ngx_gateway_upstream_rr_peer_t;

typedef struct ngx_gateway_upstream_rr_peers_s 	ngx_gateway_upstream_rr_peers_t;

struct ngx_gateway_upstream_rr_peers_s {
	ngx_uint_t								single;
	ngx_uint_t								number;
	ngx_uint_t								last_cached;

	ngx_connection_t 						**cached;

	ngx_str_t 								*name;

	ngx_gateway_upstream_rr_peers_t 		*next;

	ngx_gateway_upstream_rr_peer_t 			peer[1];
};

typedef struct {
	ngx_gateway_upstream_rr_peers_t			*peers;
	ngx_uint_t 								current;
	uintptr_t								*tried;
	uintptr_t 								data;
} ngx_gateway_upstream_rr_peer_data_t;

ngx_int_t ngx_gateway_upstream_init_round_robin(ngx_conf_t *cf, ngx_gateway_upstream_srv_conf_t *us);
ngx_int_t ngx_gateway_upstream_init_round_robin_peer(ngx_gateway_session_t *s,
			ngx_gateway_upstream_srv_conf_t *us);
ngx_int_t ngx_gateway_upstream_create_round_robin_peer(ngx_gateway_session_t *s,
			ngx_gateway_upstream_resolved_t *ur);
ngx_int_t ngx_gateway_upstream_get_round_robin_peer(ngx_peer_conenction_t *pc, 
			void *data);
void ngx_gateway_upstream_free_round_robin_peer(ngx_peer_conenction_t *pc,
			void *data, ngx_uint_t state);

#endif /* _NGX_GATEWAY_UPSTREAM_ROUND_ROBIN_H_ */