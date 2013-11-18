
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_gateway.h>
#include <ngx_gateway_upstream.h>

static void ngx_gateway_upstream_cleanup(void *data);

static void ngx_gateway_upstream_handler(ngx_event_t *ev);
static void ngx_gateway_upstream_connect(ngx_gateway_request_t *r, ngx_gateway_upstream_t *u);
static void ngx_gateway_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_gateway_upstream_finalize_session(ngx_gateway_request_t *r,
									ngx_gateway_upstream_t *u, ngx_int_t rc);

static char *ngx_gateway_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_gateway_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_gateway_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_gateway_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_gateway_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_command_t	ngx_gateway_upstream_commmand[] = {
	{
		ngx_string("upstream"),
		NGX_GATEWAY_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
		ngx_gateway_upstream,
		0,
		0,
		NULL
	},

	{
		ngx_string("server"),
		NGX_GATEWAY_UPS_CONF|NGX_CONF_1MORE,
		ngx_gateway_upstream_server,
		NGX_GATEWAY_SRV_CONF_OFFSET,
		0,
		NULL
	},

	{
		ngx_string("check"),
		NGX_GATEWAY_UPS_CONF|NGX_CONF_1MORE,
		ngx_gateway_upstream_check,
		NGX_GATEWAY_SRV_CONF_OFFSET,
		0,
		NULL
	},

	{
		ngx_string("check_shm_size"),
		NGX_GATEWAY_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_GATEWAY_MAIN_CONF_OFFSET,
		offsetof(ngx_gateway_upstream_main_conf_t, check_shm_size),
		NULL
	},

	ngx_null_command
};

static ngx_gateway_module_t  ngx_gateway_upstream_module_ctx = {
	NULL,

	ngx_gateway_upstream_create_main_conf,					/* create main configuration */
	ngx_gateway_upstream_init_main_conf,					/* init main configuration */

	NULL,													/* create server configuration */
	NULL,													/* init server configuration */

	NULL,													/* create business configuration */
	NULL 													/* init business configuration */
};

ngx_module_t ngx_gateway_upstream_module = {
	NGX_MODULE_V1,
	&ngx_gateway_upstream_module_ctx,						/* module context */
	ngx_gateway_upstream_commmand, 							/* module directives */
	NGX_GATEWAY_MODULE, 									/* module type */
	NULL,													/* init master */
	NULL,													/* init module */
	NULL,													/* init process */
	NULL,													/* init thread */
	NULL,													/* exit thread */
	NULL,													/* exit process */
	NULL,													/* exit master */
	NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_gateway_upstream_create(ngx_gateway_request_t *r)
{
	ngx_gateway_upstream_t 	*u;

	u = r->upstream;

	if (u && u->cleanup) {
		ngx_gateway_upstream_cleanup(r);
	}

	u = ngx_pcalloc(r->pool, sizeof(ngx_gateway_upstream_t));
	if (NULL == u) {
		return NGX_ERROR;
	}

	r->upstream = u;

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;

	return NGX_OK;
}

void
ngx_gateway_upstream_init(ngx_gateway_request_t *r)
{
	ngx_str_t 							*host;
	ngx_uint_t 							i;
	ngx_connection_t					*c;
	ngx_gateway_cleanup_t 				*cln;
	ngx_resolver_ctx_t					*ctx, temp;
	ngx_gateway_upstream_t 				*u;
	ngx_gateway_core_srv_conf_t 		*cscf;
	ngx_gateway_upstream_srv_conf_t 	*uscf, **uscfp;
	ngx_gateway_upstream_main_conf_t 	*umcf;

	c = r->connection;

	cscf = ngx_gateway_get_module_src_conf(r->s, ngx_gateway_core_module);

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, c->log, 0, 
					"gateway init upstream, client timer: %d", c->read->timer_set);

	if (c->read->timer_ser) {
		ngx_del_timer(c->read);
	}

	u = r->upstream;

	cln = ngx_gateway_cleanup_add(r, 0);

	cln->handler = ngx_gateway_upstream_cleanup;
	cln->data = r;
	u->cleanup = &cln->handler;

	if (u->resolved == NULL) {

		uscf = u->conf->upstream;

	} else {

		if (u->resolved->sockaddr) {
			if (ngx_gateway_upstream_create_round_robin_peer(r, u->resolved)
				!= NGX_OK) 
			{
				ngx_gateway_close_request(r);
				return;
			}

			ngx_gateway_upstream_connect(r, u);

			return;
		}

		host = &u->resolved->host;

		umcf = ngx_gateway_get_module_main_conf(r->s, ngx_gateway_upstream_module);

		uscfp = umcf->upstreams.elts;
		for ( i = 0; i < umcf->upstream.nelts; ++i) {
			uscf = uscfp[i];

			if (uscf->host.len == host->len
				&& ((uscf->port == 0 && u->resolved->no_port)
					|| uscf->port == u->resolved->port)
				&& ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
			{
				goto found;
			}
		}

		temp.name = *host;

		ctx = ngx_resolve_start(cscf->resolver, &temp);
		if (NULL == ctx) {
			ngx_gateway_close_request(r);
			return;
		}

		if (ctx == NGX_NO_RESOLVER) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"no resolver defined to resolve %V", host);
			ngx_gateway_close_request(r);
			return;
		}

		ctx->name = *host;
		ctx->type = NGX_RESOLVE_A;
		ctx->handler = ngx_gateway_upstream_resolve_handler;
		ctx->data = r;
		ctx->timeout = cscf->resolver_timeout;

		u->resolved->ctx = ctx;

		if (ngx_resolve_name(ctx) != NGX_OK) {
			u->resolved->ctx = NULL;
			ngx_gateway_close_request(r);
			return;
		}

		return;
	}

found:
	if (uscf->peer.init(r, uscf) != NGX_OK) {
		ngx_gateway_close_request(r);
		return;
	}

	ngx_gateway_upstream_connect(r, u);
}

static void 
ngx_gateway_upstream_connect(ngngx_gateway_request_t *r, ngx_gateway_upstream_t *u)
{
	int 							tcp_nodely;
	ngx_int_t 						rc;
	ngx_connection_t 				*c;
	ngx_gateway_core_srv_conf_t 	*cscf;

	r->connection->log->action = "connecting to upstream";

	cscf = ngx_gateway_get_module_srv_conf(s, ngx_gateway_core_module);

	rc = ngx_event_connect_peer(&u->peer);

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, s->connection->log, 0,
				"gateway upstream conenct: %d", rc);

	if (NGX_OK != rc && NGX_AGAIN != rc) {

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"upstream servers are busy or encounter error!");

		ngx_gateway_upstream_finalize_session(r, u, 0);

		return;
	}

	if (u->peer.check_index != NGX_INVALID_CHECK_INDEX) {
		ngx_gateway_check_get_peer(u->peer.check_index);
	}

	c = u->peer.connection;

	c->data = r;
	c->pool = r->pool;
	c->log = r->log;
	c->read->log = c->log;
	c->write->log = c->log;

	c->write->handler = ngx_gateway_upstream_handler;
	c->read->handler = ngx_gateway_upstream_handler;

	if (cscf->tcp_nodely) {
		tcp_nodely = 1;

		if (setsockopt(c->fd, IPPROTO_TCP, 
					(const void *)tcp_nodely, sizeof(int)) == -1)
		{
			ngx_connection_error(c, ngx_socket_errno, "setsockopt(TCP_NODELAY) failed");

			ngx_gateway_upstream_finalize_session(s, u, 0);
			return;
		}

		c->tcp_nodely = NGX_TCP_NODLAY_SET;
	}

	if (NGX_AGAIN) {
		ngx_add_timer(c->write, u->conf->connect_timeout);
		return;
	} else {
		ngx_add_timer(c->read, u->conf->read_timeout);
		ngx_add_timer(c->write, u->conf->send_timeout);

		c->write->handler(c->write);
	}
}

static void 
ngx_gateway_upstream_handler(ngx_event_t *ev)
{
	ngx_connection_t 		*c;
	ngx_gateway_request_t 	*r;
	ngx_gateway_upstream_t 	*u;

	c = ev->data;
	r = c->data;

	u = r->upstream;
	c = r->connection;

	if (ev->write) {
		if (u->write_event_handler) {
			u->write_event_handler(r, u);
		}
	} else {
		if (u->read_event_handler) {
			u->read_event_handler(r, u);
		}
	}
}

ngx_int_t 
ngx_gateway_upstream_check_broken_connection(ngx_gateway_request_t *r)
{
	int 								n;
	char								buf[1];
	ngx_err_t 							err;
	ngx_connection_t					*c;
	ngx_gateway_upstream_t 				*u;

	u = r->upstream;
	c = u->peer.connection;

	if (NULL == u->peer.connection) {
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, c->log, 0,
					"gateway upstream check upstream, fd: %d", c->fd);

	n = recv(c->fd, buf, 1, MSG_PEEK);

	err = ngx_socket_errno;

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, c->log, err,
				"gateway check upstream recv(): %d", c->fd);

	if ( n >= 0 || NGX_AGAIN == err) {
		return NGX_OK;
	}

	c->error = 1;

	return NGX_ERROR;
}

void 
ngx_gateway_upstream_next(ngx_gateway_request_t *r, ngx_gateway_upstream_t *u, ngx_uint_t ft_type) 
{
	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, r->connection->log, 0, 
				"gateway next upstream, fail type: %xi", ft_type);

	if (ft_type != NGX_GATEWAY_UPSTREAM_FT_NOLIVE) {
		u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
	}

	if (ft_type == NGX_GATEWAY_UPSTREAM_FT_TIMEOUT) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ETIMEDOUT,
						"upstream timed out");
	}

	if (r->connection->error) {
		ngx_gateway_upstream_finalize_session(r, u, 0);

		return;
	}

	if (u->peer.tries == 0) {
		ngx_gateway_upstream_finalize_session(r, u, 0);
		return;
	}

	if (u->peer.connection) {
		ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, r->connection->log, 0
					"close gateway upstream connecton: %d", u->peer.connecton->fd);

		if (u->peer.check_index != NGX_INVALID_CHECK_INDEX) {
			ngx_gateway_check_free_peer(u->peer.check_index);
			u->peer.check_index = NGX_INVALID_CHECK_INDEX;
		}

		ngx_close_connection(u->peer.connecton);
	}

	ngx_gateway_upstream_connect(r, u);
}

static void 
ngx_gateway_upstream_cleanup(void *data)
{
	ngx_gateway_request_t			*r = data;

	ngx_gateway_upstream_t 			*u;

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, s->connection->log, 0,
			"cleanup gateway upstream session: fd: %d", s->connection->fd);

	u = r->upstream;

	if (u->resolved && u->resolved->ctx) {
		ngx_resolve_name_done(u->resolved->ctx);
	}

	ngx_gateway_upstream_finalize_session(r, u, NGX_DONE);
}

static void 
ngx_gateway_upstream_finalize_session(ngx_gateway_request_t *r, ngx_gateway_upstream_t *u, ngx_uint_t rc)
{
	ngx_time_t		*tp;

	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, r->connection->log, 0,
				"finalize gateway upstream request: %i", rc);

	if (u->cleanup) {
		*u->cleanup = NULL;
		u->cleanup = NULL;
	}

	if (u->state && u->state->responese_sec) {
		tp = ngx_timeofday();
		u->state->responese_sec = tp->sec - u->state->responese_sec;
		u->state->responese_sec = tp->msec - u->state->responese_msec;
	}

	if (u->peer.free) {
		u->peer.free(&u->peer, u->peer.data, 0);
	}

	if (u->peer.check_index != NGX_INVALID_CHECK_INDEX) {
		ngx_gateway_check_free_peer(u->peer.check_index);
		u->peer.check_index = NGX_INVALID_CHECK_INDEX;
	}

	if (u->peer.connection) {
		ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, s->connection->log, 0,
					"close gateway upstream connection: %d", u->peer.connection->fd);

		ngx_close_connection(u->peer.connection);
	}

	u->peer.connection = NULL;

	if (NGX_DECLINED == rc || rc == NGX_DONE) {
		return;
	}

	r->connection->log->action = "sending to client";

	ngx_gateway_close_request(r);
}

ngx_gateway_upstream_srv_conf_t *
ngx_gateway_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags) 
{
	ngx_uint_t 					  			i;
	ngx_gateway_upstream_server_t			*us;
	ngx_gateway_upstream_srv_conf_t 		*uscf, **uscfp;
	ngx_gateway_upstream_main_conf_t 		*umcf;

	if (!(flags & NGX_GATEWAY_UPSTREAM_CREATE)) {
		
		if (ngx_parse_url(cf->pool, u) != NGX_OK) {
			if (u->err) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"%s in upstream \"%V\"", u->err, &u->url);
			}

			return NULL;
		}
	}

	umcf = ngx_gateway_conf_get_module_main_conf(cf, ngx_gateway_upstream_module);

	uscfp = umcf->upstreams.elts;

	for ( i = 0; i < umcf->upstreams.nelts; ++i) {

		if (uscfp[i]->host.len != u->host.len ||
			ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len) != 0)
		{
			continue;
		}

		if ((flags & NGX_GATEWAY_UPSTREAM_CREATE)
			&& (uscfp[i]->flags & NGX_GATEWAY_UPSTREAM_CREATE))
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"duplicate upstream \"%V\"", &u->host);
			return NULL;
		}
#if defined(nginx_version) && (nginx_version) >= 1003011
		if ((uscfp[i]->flags & NGX_GATEWAY_UPSTREAM_CREATE) && !u->no_port) {
#else
		if ((uscfp[i]->flags & NGX_GATEWAY_UPSTREAM_CREATE) && u->port) {
#endif
			ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
							"upstream \"%V\" may not have port %d",
							&u->host, u->port);
			return NULL
		}

#if defined(nginx_version) && (nginx_version) >= 1003011
		if ((flags & NGX_GATEWAY_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
#else
		if ((flags && NGX_GATEWAY_UPSTREAM_CREATE) && uscfp[i]->port) {
#endif
			ngx_log_error(NGX_LOG_WARN, cf->log, 0,
						"upstream \"%V\" may not have port %d in %s:%ui",
						&u->host, uscfp[i]->port,
						uscfp[i]->file_name, uscfp[i]->line);

			return NULL;
		}

#if defined(nginx_version) && (nginx_version) >= 1003011
		if (uscfp[i]->port && u->port && uscfp[i]->port != u->port) {
#else
		if (uscfp[i]->port != u->port) {
#endif
			continue;
		}
	
		if (uscfp[i]->default_port && u->default_port
			&& uscfp[i]->default_port != u->default_port)
		{
			continue;
		}

		return uscfp[i];
	}


	uscf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_upstream_srv_conf_t));
	if (NULL == uscf) {
		return NULL;
	}

	uscf->flags = flags;
	uscf->host = u->host;
	uscf->file_name = cf->conf_file->file.name.data;
	uscf->line = cf->conf_file->line;
	uscf->port = u->port;
	uscf->default_port = u->default_port;
#if defined(nginx_version) && (nginx_version) >= 1003011
	uscf>no_port = u->no_port;
#endif
	uscf->code.status_alive = 0;

	if (u->naddrs == 1) {
		uscf->servers = ngx_array_create(cf->pool, sizeof(ngx_gateway_upstream_server_t));
		if (NULL == uscf->servers) {
			return NGX_CONF_ERROR;
		}

		us = ngx_array_push(uscf->servers);
		if (NULL == us) {
			return NGX_CONF_ERROR;
		}

		ngx_memzero(us, sizeof(ngx_gateway_upstream_server_t));

		us->addrs = u->addrs;
		us->naddrs = u->naddrs;
	}

	uscfp = ngx_array_push(&umcf->upstreams);
	if (NULL == uscfp) {
		return NULL;
	}

	*uscfp = uscf;

	return uscf;
}


static char *
ngx_gateway_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char								*rv;
	void 								*mconf;
	ngx_str_t 							*value;
	ngx_url_t 							u;
	ngx_uint_t 							m;
	ngx_conf_t 							pcf;
	ngx_gateway_module_t 				*module;
	ngx_gateway_conf_ctx_t 				*ctx, *gateway_ctx;
	ngx_gateway_upstream_srv_conf_t 	*uscf;

	ngx_memzero(&u, sizeof(ngx_url_t));

	value = cf->args->elts;
	u.host = value[1];
	u.no_resolve = 1;
	u.no_port = 1;


	uscf = ngx_gateway_upstream_add(cf, &u,
									NGX_GATEWAY_UPSTREAM_CREATE
									|NGX_GATEWAY_UPSTREAM_WEIGHT
									|NGX_GATEWAY_UPSTREAM_MAX_FAILS
									|NGX_GATEWAY_UPSTREAM_FAIL_TIMEOUT
									|NGX_GATEWAY_UPSTREAM_DOWN
									|NGX_GATEWAY_UPSTREAM_MAX_BUSY
									|NGX_GATEWAY_UPSTREAM_BACKUP);
	if (NULL == uscf) {
		return NGX_CONF_ERROR;
	}

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_conf_ctx_t));
	if (NULL == ctx) {
		return NGX_CONF_ERROR;
	}

	gateway_ctx = cf->ctx;
	ctx->main_conf = gateway_ctx->main_conf;

	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_gateway_max_module);
	if (NULL == ctx->srv_conf) {
		return NGX_CONF_ERROR;
	}

	ctx->srv_conf[ngx_gateway_upstream_module.ctx_index] = uscf;

	uscf->srv_conf = ctx->srv_conf;

	for (m = 0; ngx_modules[m]; ++m) {
		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
			continue;
		}

		module = ngx_modules[m];

		if (module->create_srv_conf) {
			mconf = module->create_srv_conf(cf);
			if (NULL == mconf) {
				return NGX_CONF_ERROR;
			}

			ctx->srv_conf[module.ctx_index] = mconf;
		}
	}

	pcf = *cf;
	cf->ctx = ctx;
	cf->cmd_type = NGX_GATEWAY_UPS_CONF;

	rv = ngx_conf_parse(cf, NULL);

	*cf = pcf;

	if ( NGX_CONF_OK != rv ) {
		return rv;
	}

	if (NULL == uscf->servers) {
		ngx_cong_log_error(NGX_LOG_EMERG, cf, 0
							"no servers are inside upstream");

		return NGX_CONF_ERROR;
	}

	return rv;
}

static char *
ngx_gateway_upstream_server(ngx_conf_t *cf, ngx_command_t *cmf, void *void) 
{
	ngx_gateway_upstream_srv_conf_t		*uscf = conf;

	time_t 								fail_timeout;
	ngx_str_t 							*value, s;
	ngx_url_t 							u;
	ngx_int_t 							weight, max_fails, max_busy;
	ngx_uint_t 							i;
	ngx_gateway_upstream_server_t 		*us;


	if (NULL = uscf->servers) {
		uscf->servers = ngx_array_create(cf->pool, 4, sizeof(ngx_gateway_upstream_server_t));
		if (NULL == uscf->servers) {
			return NGX_CONF_ERROR;
		}
	}

	us = ngx_array_push(uscf->servers);
	if (NULL == us) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(us, sizeof(ngx_gateway_upstream_server_t));

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.default_port = 10000;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"%s in upstream \"%V\"", u.err, &u.url);
		}

		return NGX_CONF_ERROR;
	}

	weight = 1;
	max_fails = 1;
	max_busy = (ngx_uint_t)-1;
	fail_timeout = 10;

	for (i = 2; i < cf->args->nelts; ++i) {

		if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_WEIGHT)) {
				goto invalid;
			}

			weight = ngx_atoi(&value[i].data[7], value[i].len - 7);
			if (weight == NGX_ERROR || weight = 0) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_MAX_FAILS)) {
				goto invalid;
			}

			max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);
			if (max_fails == NGX_ERROR) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "fail_timeout=", 12) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_FAIL_TIMEOUT)) {
				goto invalid;
			}

			fail_timeout = ngx_atoi(&value[i].data[12], value[i].len - 12);
			if (fail_timeout == NGX_ERROR) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "max_busy=", 9) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_MAX_BUSY)) {
				goto invalid;
			}

			max_busy = ngx_atoi(&value[i].data[9], value[i].len - 9);
			if (max_busy == NGX_ERROR) {
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "backup", 6) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_BACKUP)) {
				goto invalid;
			}

			us->backup = 1;

			continue;
		}

		if (ngx_strncmp(value[i].data, "down", 4) == 0) {
			if (!(uscf->flags & NGX_GATEWAY_UPSTREAM_DOWN)) {
				goto invalid;
			}

			us->down = 1;

			continue;
		}

		goto invalid;
	}

	us->addrs = u.addrs;
	us->naddrs = u.naddrs;
	us->weight = weight;
	us->max_fails = max_fails;
	us->max_busy = max_busy;
	us->fail_timeout = fail_timeout;

	return NGX_CONF_OK;

invalid:
	
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0
					"invalid parameter \"%d\"", &value[i]);

	return NGX_CONF_ERROR;
}

static char *
ngx_gateway_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_gateway_upstream_srv_conf_t *uscf = conf;

	ngx_str_t 						*value, s;
	ngx_uint_t 						i, rise, fall;
	ngx_msec_t 						interval, timeout;

	/* default */
	rise = 2;
	fall = 5;
	interval = 30000;
	timeout = 1000;

	value = cf->args->elts;

	for (i = 2; i < cf->args->nelts; ++i) {

		if (ngx_strncmp(value[i].data, "type=", 5) == 0) {

			s.len = value[i].len - 5;
			s.data = value[i].data + 5;

			uscf->check_type_conf = ngx_gateway_get_check_type_conf(&s);
			if (NULL == uscf->check_type_conf) {
				goto invalid_check_parameter;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {

			interval = ngx_atoi(&value[i].data[9], value[i].len - 9);
			if (interval == NGX_ERROR) {
				goto invalid_check_parameter;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

			timeout = ngx_atoi(&value[i].data[8], value[i].len - 8);
			if (timeout == NGX_ERROR) {
				goto invalid_check_parameter;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {

			rise = ngx_atoi(&value[i].data[5], value[i].len - 5);
			if (rise == NGX_ERROR) {
				goto invalid_check_parameter;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "fail=", 5) == 0) {

			fall = ngx_atoi(&value[i].data[5], value[i].len - 5);
			if (fail == NGX_ERROR) {
				goto invalid_check_parameter;
			}

			continue;
		}

		goto invalid_check_parameter;
	}

	uscf->check_interval = interval;
	uscf->check_timeout = timeout;
	uscf->fall_count = fall;
	uscf->rise_count = rise;

	if (uscf->check_type_conf == NULL) {

		s.len = sizeof("gateway") - 1;
		s.data = (u_char *)"gateway";

		uscf->check_type_conf = ngx_gateway_get_check_type_conf(&s);
	}

	return NGX_CONF_OK;

invalid_check_parameter:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
					"invalid parameter \"%V\"", value[i]);

	return NGX_CONF_ERROR;
}

static void *
ngx_gateway_upstream_create_main_conf(ngx_conf_t *cf)
{
	ngx_gateway_upstream_main_conf_t *umcf;

	umcf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_upstream_main_conf_t));
	if (NULL == umcf) {
		return NULL;
	}

	umcf->peers_conf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_check_peers_conf_t));
	if (NULL == umcf->peers_conf) {
		return NULL;
	}

	if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
					sizeof(ngx_gateway_upstream_srv_conf_t *)) != NGX_OK)
	{
		return NULL;
	}

	if (ngx_array_init(&umcf->peers_conf->peers, cf->pool, 16
						sizeof(ngx_gateway_check_peer_conf_t)) != NGX_OK) 
	{
		return NULL;
	}

	return umcf;
}

static char * 
ngx_gateway_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_gateway_upstream_srv_conf_t *uscf = conf;

	ngx_uint_t							i;
	ngx_gateway_upstream_init_pt		init;
	ngx_gateway_upstream_srv_conf_t		**uscfp;

	uscfp = umcf->upstreams.elts;

	if (ngx_gateway_upstream_init_main_check_conf(cf, conf) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	for (i = 0; i < umcf->upstreams.nelts; ++i) {

		init = uscfp[i]->init_upstream ? uscfp[i]->init_upstream :
										 ngx_gateway_upstream_init_round_robin;

		if (init(cf, uscfp[i]) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}
