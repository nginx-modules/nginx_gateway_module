

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_gateway.h>

typedef struct {
	ngx_uint_t										max_cached;

	ngx_queue_t										cache;
	ngx_queue_t 									free;

	ngx_gateway_upstream_init_pt					original_init_upstream;
	ngx_gateway_upstream_init_peer_pt 				original_init_peer;

} ngx_gateway_upstream_keepalive_srv_conf_t;

typedef struct {
	ngx_gateway_upstream_keepalive_srv_conf_t		*conf;

	ngx_gateway_upstream_t 							*upstream;

	void 											*data;

	ngx_event_get_peer_t							origianl_get_peer;
	ngx_event_free_peer_t							origianl_free_peer;

} ngx_gateway_upstream_keepalive_peer_data_t;


typedef struct {
	ngx_gateway_upstream_keepalive_srv_conf_t		*conf;

	ngx_queue_t										queue;
	ngx_connection_t								*connection;

	socklen_t										socklen;
	u_char											sockaddr[NGX_SOCKADDRLEN];
} ngx_gateway_upstream_keepalive_cache_t;

static ngx_int_t ngx_gateway_upstream_init_keepalive_peer(ngx_gateway_request_t *t, 
	ngx_gateway_upstream_srv_conf_t *us);
static ngx_int_t ngx_gateway_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
	void *data);
static void ngx_gateway_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
	void *data, ngx_uint_t state);

static void ngx_gateway_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_gateway_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_gateway_upstream_keepalive_close(ngx_connection_t *c);

static void *ngx_gateway_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_gateway_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_gateway_upstream_keepalive_commands[] = {
	{
		ngx_string("keepalive"),
		NGX_GATEWAY_UPS_CONF|NGX_CONF_TAKE12,
		ngx_gateway_upstream_keepalive,
		NGX_GATEWAY_SRV_CONF_OFFSET,
		0,
		NULL
	},

	ngx_null_command
};

static ngx_gateway_modult_t  ngx_gateway_upstream_keepalive_module_ctx = {
	NULL,													/* protocol */

	NULL,													/* create main configuration */
	NULL,													/* init main configuration */

	ngx_gateway_upstream_keepalive_create_conf,				/* create srv configuration */
	NULL,													/* merge srv configuration */

	NULL,													/* create biz configuration */
	NULL 													/* merge biz configuration */
};

ngx_module_t ngx_gateway_upstream_keepalive_module = {
	NGX_MODULE_V1,
	&ngx_gateway_upstream_keepalive_module_ctx,
	ngx_gateway_upstream_keepalive_commands,
	NGX_GATEWAY_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_gateway_upstream_init_keepalive(ngx_conf_t *cf,
	ngx_gateway_upstream_srv_conf_t *us)
{
	ngx_uint_t 									i;
	ngx_gateway_upstream_keepalive_srv_conf_t 	*kcf;
	ngx_gateway_upstream_keepalive_cache_t		*cached;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, cf->log, 0,
					"init keepalive");

	kcf = ngx_gateway_conf_upstream_srv_conf(us, ngx_gateway_upstream_keepalive_module);

	if (kcf->original_init_upstream(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}

	kcf->original_init_peer = us->peer.init;

	us->peer.init = ngx_gateway_upstream_init_keepalive_peer;

	cached = ngx_pcalloc(cf->pool,
						sizeof(ngx_gateway_upstream_keepalive_cache_t) * kcf->max_cached);
	if (NULL == cached) {
		return NGX_ERROR;
	}

	ngx_queue_init(&kcf->cache);
	ngx_queue_init(&kcf->free);

	for (i = 0; i < kcf->max_cached; ++i) {
		ngx_queue_insert_head(&kcf->free, &cached[i].queue);
		cached[i].conf = kcf;
	}

	return NGX_OK;
}

static ngx_int_t 
ngx_gateway_upstream_init_keepalive_peer(ngx_gateway_request_t *r,
	ngx_gateway_upstream_srv_conf_t *us)
{
	ngx_gateway_upstream_keepalive_peer_data_t				*kp;
	ngx_gateway_upstream_keepalive_srv_conf_t				*kcf;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, r->connection->log, 0, 
					"init keepalive peer");

	kcf = ngx_gateway_conf_upstream_srv_conf(us, ngx_gateway_upstream_keepalive_module);

	kp = ngx_pcalloc(s->connection->pool, sizeof(ngx_gateway_upstream_keepalive_peer_data_t));
	if (NULL == kp) {
		return NGX_ERROR;
	}

	if (kcf->original_init_peer(s, us) != NGX_OK) {
		return NGX_ERROR;
	}

	kp->conf = kcf;

	kp->upstream = r->upstream;
	kp->data = r->upstream->peer.data;
	kp->origianl_get_peer = r->upstream->peer.get;
	kp->origianl_free_peer = r->upstream->peer.free;

	r->upstream->peer.data = kp;
	r->upstream->peer.get = ngx_gateway_upstream_get_keepalive_peer;
	r->upstream->peer.free = ngx_gateway_upstream_free_keepalive_peer;

	return NGX_OK;
}

static ngx_int_t 
ngx_gateway_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data);
{
	ngx_gateway_upstream_keepalive_peer_data_t		*kp = data;
	ngx_gateway_upstream_keepalive_cache_t			*item;

	ngx_int_t 										rc;
	ngx_queue_t 									*q, *cahche;
	ngx_connection_t 								*c;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
					"get keepalive peer");

	/* ask balancer */

	rc = kp->origianl_get_peer(pc, kp->data);
	if (rc != NGX_OK) {
		return rc;
	}

	/* search cache for suitable connection */

	cache = &kp->conf->cache;

	for (q = ngx_queue_head(cache);
		q != ngx_queue_sentinel(cache);
		q = ngx_queue_next(cache))
	{
		item = ngx_queue_data(q, ngx_gateway_upstream_keepalive_cache_t, queue);
		c = item->connection;

		if (mgx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
						item->socklen, pc->socklen)
			 == 0)
		{
			ngx_queue_remove(q);
			ngx_queue_insert_head(&kp->conf->free, q);

			ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
							"get keepalive peer: using connection %p", c);

			c->idle = 0;
			c->log = pc->log;
			c->read->log = pc->log;
			c->write->log = pc->log;
			c->pool->log = pc->log;

			pc->connection = c;
			pc->cached = 1;

			return NGX_DONE;
		}
	}

	return NGX_OK;
}

static void 
ngx_gateway_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
	ngx_uint_t state)
{
	ngx_gateway_upstream_keepalive_peer_data_t 		*kp = data;
	ngx_gateway_upstream_keepalive_cache_t			*item;

	ngx_queue_t 									*q;
	ngx_connection_t 								*c;
	ngx_gateway_upstream_t 							*u;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
					"free keepalive peer");

	u = kp->upstream;
	c = pc->connection;

	if (state & NGX_PEER_FAILED
		|| c == NULL
		|| c->read->eof
		|| c->read->error
		|| c->read->timeout
		|| c->write->error
		|| c->write->timeout)
	{
		goto invalid;
	}

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
		goto invalid;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, pc->log, 0,
				"free keepalive peer: saving connection %p", c);

	if (ngx_queue_empty(&kp->conf->free)) {

		q = ngx_queue_last(&kp->conf->cache);
		ngx_queue_remove(q);

		item = ngx_queue_data(q, ngx_gateway_upstream_keepalive_cache_t, queue);

		ngx_gateway_upstream_keepalive_close(item->connection);
	} else {
		q = ngx_queue_head(&kp->conf->free);
		ngx_queue_remove(q);

		item = ngx_queue_data(q, ngx_gateway_upstream_keepalive_cache_t, queue);
	}

	item->connection = c;
	ngx_queue_insert_head(&kp->conf->cache, q);

	pc->connection = NULL;

	if (c->read->timer_set) {
		ngx_del_timer(c->read);
	}

	if (c->write->timer_set) {
		ngx_del_timer(c->write);
	}

	c->write->handler = ngx_gateway_upstream_keepalive_dummy_handler;
	c->read->handler = ngx_gateway_upstream_keepalive_close_handler;

	c->data = item;
	c->idle = 1;
	c->log = ngx_cycle->log;
	c->read->log = ngx_cycle->log;
	c->write->log = ngx_cycle->log;
	c->pool->log = ngx_cycle->log;

	item->socklen = pc->socklen;
	ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

	if (c->read->ready) {
		ngx_gateway_upstream_keepalive_close_handler(c->read);
	}

invalid:
	
	kp->origianl_free_peer(pc, kp->data, state);
}

static void 
ngx_gateway_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, ev->log, 0,
				"keepalive dummy handler");
}

static void 
ngx_gateway_upstream_keepalive_close_handler(ngx_event_t *ev)
{
	ngx_gateway_upstream_keepalive_srv_conf_t		*conf;
	ngx_gateway_upstream_keepalive_cache_t			*item;

	int 											n;
	char 											buf[1];
	ngx_connection_t 								*c;

	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, ev->log, 0,
					"keepalive close handler");

	c = ev->data;

	if (c->close) {
		goto close;
	}

	n = recv(c->fd, buf, 1, MSG_PEEK);

	if (n == -1 && ngx_socket_errno == NGX_EAGEIN) {

		if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
			goto close;
		}

		return;
	}

close:
	
	item = c->data;
	conf = item->conf;

	ngx_gateway_upstream_keepalive_close(c);

	ngx_queue_remove(&item->queue);
	ngx_queue_insert_head(&conf->free, &item->queue);
}

static void
ngx_gateway_upstream_keepalive_close(ngx_connection_t *c)
{
	ngx_destroy_pool(c->pool);
	ngx_close_connection(c);
}

static void *
ngx_gateway_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
	ngx_gateway_upstream_keepalive_srv_conf_t		*conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_upstream_keepalive_srv_conf_t));
	if (NULL == conf) {
		return NULL;
	}

	conf->max_cached = 1;

	return conf;
}

static char *
ngx_gateway_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_gateway_upstream_keepalive_srv_conf_t				*kcf = conf;
	ngx_gateway_upstream_srv_conf_t 						*uscf;

	ngx_int_t 												n;
	ngx_str_t 												*value;
	ngx_uint_t 												i;

	uscf = ngx_gateway_conf_get_module_srv_conf(cf, ngx_gateway_upstream_module);

	if (kcf->original_init_upstream) {
		return "is duplicate";
	}

	kcf->original_init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream 
															:ngx_gateway_upstream_init_round_robin;

	uscf->peer.init_upstream = ngx_gateway_upstream_init_keepalive;

	value = cf->args->elts;

	n = ngx_atoi(value[1].data, value[1].len);

	if (NGX_ERROR == n || 0 == n) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
						"invalid value \"%V\" \"%V\" directive",
						&value[1], &cmd->name);

		return NGX_CONF_ERROR;
	} 

	kcf->max_cached = n;

	for (i = 2; i < cf->args->nelts; ++i) {

		if (ngx_strcmp(value[i].data, "single") == 0) {
			ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
								"the \"single\" parameter is deprecated");

			continue;
		}

		goto invalid;
	}

	return NGX_CONF_OK;

invalid:

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"invalid parameter \"%V\"", &value[i]);

	return NGX_CONF_ERROR;
}


