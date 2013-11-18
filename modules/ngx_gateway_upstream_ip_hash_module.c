
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_gateway.h>

typedef struct {
	ngx_gateway_upstream_rr_peer_data_t		rrp;

	ngx_uint_t								hash;

	u_char									addr[3];

	u_char									tries;

	ngx_event_get_peer_pt					get_rr_peer;
} ngx_gateway_upstream_ip_hash_peer_data_t;

static ngx_int_t ngx_gateway_upstream_init_ip_hash_peer(ngx_gateway_request_t *r,
	ngx_gateway_upstream_srv_conf_t *us);
static ngx_int_t ngx_gateway_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
	void *data);
static char *ngx_gateway_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_gateway_upstream_ip_hash_commands = {
	{
		ngx_string("ip_hash"),
		NGX_GATEWAY_UPS_CONF|NGX_CONF_NOARGS,
		ngx_gateway_upstream_ip_hash,
		0,
		0,
		NULL
	},

	ngx_null_command
};

static ngx_gateway_module_t ngx_gateway_upstream_ip_hash_module_ctx = {
	NULL,								/* protocol */

	NULL,								/* create main configuration */
	NULL,								/* init main configuration */

	NULL,								/* create srv configuration */
	NULL,								/* merge srv configuration */

	NULL,								/* create biz configuration */
	NULL, 								/* merge biz configuration */
};

ngx_module_t ngx_gateway_upstream_ip_hash_module = {
	NGX_MODULE_V1,
	&ngx_gateway_upstream_ip_hash_module_ctx,			/* module context */
	ngx_gateway_upstream_ip_hash_commands,				/* module commands */
	NGX_GATEWAY_MODULE,									/* module type */
	NULL,												/* init master */
	NULL,												/* init module */
	NULL,												/* init process */
	NULL,												/* init thread */
	NULL,												/* exit thread */
	NULL,												/* exit process */
	NULL,												/* exit master */
	NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_gateway_upstream_init_ip_hash(ngx_conf_t *cf, ngx_gateway_upstream_srv_conf_t *us)
{
	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, cf->log, 0,
					"init ip hash");

	if (ngx_gateway_upstream_init_round_robin(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}

	us->peer.init = ngx_gateway_upstream_init_ip_hash;

	return NGX_OK;
}

static ngx_int_t
ngx_gateway_upstream_init_ip_hash_peer(ngx_gateway_request_t *r,
	ngx_gateway_upstream_srv_conf_t *us)
{
	u_char										*p;
	struct sockaddr_in							*sin;
	ngx_gateway_upstream_ip_hash_peer_data_t	*iphp;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, cf->log, 0, 
					"init ip hash peer");

	iphp = ngx_pcalloc(r->pool, sizeof(ngx_gateway_upstream_ip_hash_peer_data_t));
	if (NULL == iphp) {
		return NGX_ERROR;
	}

	r->upstream->peer.data = &iphp->rrp;

	if (ngx_gateway_upstream_init_round_robin_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}

	r->upstream->peer.get = ngx_gateway_upstream_get_ip_hash_peer;

	if (r->connection->sockaddr->sa_family == AF_INET) {

		sin = (struct sockaddr_in *)r->connection->sockaddr;
		p = (u_char *)sin->sin_addr.s_addr;
		iphp->addr[0] = p[0];
		iphp->addr[1] = p[1];
		iphp->addr[2] = p[2];
	} else {
		iphp->addr[0] = 0;
		iphp->addr[1] = 0;
		iphp->addr[2] = 0;
	}

	iphp->hash = 89;
	iphp->tries = 0;
	iphp->get_rr_peer = ngx_gateway_upstream_get_round_robin_peer;

	return NGX_OK;
}

static ngx_int_t
ngx_gateway_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
	ngx_gateway_upstream_ip_hash_peer_data_t 	*iphp = data;

	time_t 										now;
	uintptr_t									m;
	ngx_uint_t 									i, n, p, hash;
	ngx_gateway_upstream_rr_peer_data_t 		*peer;

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
				"get ip hash peer, try: %ui", pc->tries);

	if (iphp->tries > 20 || iphp->rrp.peers->single) {
		return iphp->get_rr_peer(pc, &iphp->rrp);
	}

	now = ngx_time();

	pc->cached = 0;
	pc->connection = NULL;

	hash = iphp->hash;

	for ( ;; ) {

		for (i = 0; i < 3; ++i) {
			hash = (hash * 113 + iphp->addr[i]) %6271;
		}

		p = hash % hash->rrp.peers->number;

		n = p / (8 * sizeof(uintptr_t));
		m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

		if (!(iphp->rrp.tried[n] & m)) {

			ngx_log_debug4(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
						"get ip hash peer hash: %d, %ui, %04XA, num: %d",
						hash, p, m, iphp->rrp->peers->number);

			peer = &iphp->rrp.peers->peer[p];

			if (!peer->down) {
				if (!ngx_gateway_check_peer_down(peer->check_index)) {

					if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
						break;
					}

					if (now - peer->accessed > peer->fail_timeout) {
						peer->fails = 0;
						break;
					}
				}
			}

			iphp->rrp.tried[n] |= m;

			pc->tries--;
		}

		if (++iphp->tries >= 20) {
			return iphp->get_rr_peer(pc, &iphp->rrp);
		}
	}

	iphp->rrp.current = p;

	pc->sockaddr = peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;
	pc->check_index = peer->check_index;

	iphp->rrp.tried[n] |= m;
	iphp->hash = hash;

	return NGX_OK; 
}

static void *
ngx_gateway_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
	ngx_gateway_upstream_srv_conf_t		*uscf;

	uscf = ngx_gateway_conf_get_module_srv_conf(cf, ngx_gateway_upstream_module);

	uscf->peer.init_upstream = ngx_gateway_upstream_init_ip_hash;

	uscf->flags = NGX_GATEWAY_UPSTREAM_CREATE
				  |NGX_GATEWAY_UPSTREAM_MAX_FAILS
				  |NGX_GATEWAY_UPSTREAM_FAIL_TIMEOUT
				  |NGX_GATEWAY_UPSTREAM_MAX_BUSY
				  |NGX_GATEWAY_UPSTREAM_DOWN;

	return NGX_CONF_OK;
}