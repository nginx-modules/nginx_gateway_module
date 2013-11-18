
/*
 * Copyright (c) 2013 Zhuyx
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_gateway.h>

 typedef struct ngx_gateway_im_proxy_request_data_s {
 	ngx_uint_t 						version;
 	ngx_uint_t						session_id;
 	ngx_uint_t						return_code;
 	ngx_uint_t						seq;
 	ngx_uint_t						key;
 	ngx_uint_t 						len;
 }ngx_gateway_im_proxy_request_data_t;

 typedef struct ngx_gateway_im_proxy_s {
 	ngx_peer_connection_t			*upstream;
 	ngx_buf_t						*buffer;
 }ngx_gateway_im_proxy_ctx_t;

 typedef struct ngx_gateway_im_proxy_biz_conf_s {
 	ngx_gateway_upstream_conf_t 	upstream;

 	ngx_str_t 						url;
 	size_t							buffer_size;
 } ngx_gateway_im_proxy_biz_conf_t;

 static void ngx_gateway_im_proxy_init_session(ngx_gateway_session_t *s);
 static void ngx_gateway_im_proxy_init_protocol(ngx_event_t *ev);
 static void ngx_gateway_im_proxy_parse_protocol(ngx_event_t *ev); 
 static void ngx_gatway_im_proxy_init_upstream(ngx_connection_t *c, ngx_gateway_request_t *r);
 static void ngx_gateway_upstream_init_proxy_handler(ngx_gateway_request_t *t,
 		ngx_gateway_upstream_t *u);
 static char *ngx_gateway_im_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static void ngx_gateway_im_proxy_dummy_read_hander(ngx_event_t *ev);
 static void ngx_gateway_im_proxy_dummy_write_handler(ngx_event_t *ev);

 static im_proxy_request_parser_execute(ngx_gateway_session_t *s, ngx_gateway_request_t *r);

 static void ngx_gateway_im_proxy_handler(ngx_event_t *ev);

 static void *ngx_gateway_im_proxy_create_biz_conf(ngx_conf_t *cf);
 static char *ngx_gateway_proxy_merge_biz_conf(ngx_conf_t *cf, void *parent, void *child);

 static ngx_gateway_protocol_t ngx_gateway_im_proxy_protocol = {

 	ngx_string("im_proxy"),
 	{0, 0, 0, 0},
 	NGX_GATEWAY_IM_PROXY_PROTOCOL,
 	ngx_gateway_im_proxy_init_session,
 	ngx_gateway_im_proxy_init_protocol,
 	ngx_gateway_im_proxy_parse_protocol,
 	ngx_string("500 Internal server error" CRLF)
 }

 static ngx_command_t ngx_gateway_im_proxy_commands[] = {

 	{
 		ngx_string("im_proxy_pass"),
 		NGX_GATEWAY_BIZ_CONF|NGX_CONF_TAKE1,
 		ngx_gateway_im_proxy_pass,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("im_proxy_buffer"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_GATEWAY_BIZ_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_size_slot,
 		NGX_GATEWAY_BIZ_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_biz_conf_t, buffer_size),
 		NULL
 	},

 	{
 		 ngx_string("im_proxy_connect_timeout"),
 		 NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_GATEWAY_BIZ_CONF|NGX_CONF_TAKE1,
 		 ngx_conf_set_msec_slot,
 		 NGX_GATEWAY_BIZ_CONF_OFFSET,
 		 offsetof(ngx_gateway_im_proxy_biz_conf_t, upstream.connect_timeout),
 		 NULL
 	},

 	{
 		ngx_string("im_proxy_read_timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_GATEWAY_BIZ_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_BIZ_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_biz_conf_t, upstream.read_timeout),
 		NULL,
 	}

 	{
 		ngx_string("im_proxy_write_timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_GATEWAY_BIZ_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_BIZ_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_biz_conf_t, upstream.write_timeout),
 		NULL
 	},

 	ngx_null_command
 };

 static ngx_gateway_module_t  ngx_gateway_im_proxy_module_ctx = {
 	&ngx_gateway_im_proxy_protocol,					/* protocol */

 	NULL,											/* create main configuration */
 	NULL,											/* init main configuration */

 	NULL,											/* create srv configuration */
 	NULL,											/* merge srv configuration */

 	ngx_gateway_im_proxy_create_biz_conf,				/* create business configuration */
 	ngc_gateway_im_proxy_merge_biz_conf 				/* merge business configuration*/
 };

 ngx_module_t ngx_gateway_im_proxy_module = {
 	NGX_MODULT_V1,
 	&ngx_gateway_im_proxy_module_ctx,				/* module context */
 	ngx_gateway_im_proxy_commands,					/* module directives */
 	NGX_GATEWAY_MODULE,								/* module type */
 	NULL,											/* init master */
 	NULL,											/* init module */
 	NULL,											/* init process */
 	NULL,											/* init thread */
 	NULL,											/* exit thread */
 	NULL,											/* exit process */
 	NULL,											/* exit module */
 	NGX_MODULE_V1_PADDING
 };

 static void
 ngx_gateway_im_proxy_init_session(ngx_gateway_session_t *s)
 {
 	ngx_connection_t 					*c;
 	ngx_gateway_core_srv_conf_t			*cscf;
 	ngx_gateway_im_proxy_ctx_t			*iptx;

 	c = s->connection;

 	ngx_log_debug0(NGX_LOG_DEBUG_GATEWAY, c->log, 0, "im gateway proxy init session");

 	cscf = ngx_gateway_get_module_srv_conf(s, ngx_gateway_core_module);

/*
 	iptx = ngx_pcalloc(s->connection->pool, sizeof(ngx_gateway_im_proxy_ctx_t));
 	if (NULL == iptx) {
 		ngx_gateway_finalize_session(s);
 		return;
 	}

 	ngx_gateway_set_ctx(s, iptx, ngx_gateway_im_proxy_module);
*/
 	s->buffer = ngx_create_temp_buffer(s->connection->pool, cscf->buffer_size);
 	if (NULL == s->buffer) {
 		ngx_gateway_finalize_session(s);
 		return;
 	}

 	s->out.len = 0;

 	c->write->handler = ngx_gateway_im_proxy_dummy_write_handler;
 	c->read->handler = ngx_gateway_im_proxy_init_protocol;

 	ngx_add_timer(c->read, cscf->timeout);

 	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
 		ngx_gateway_finalize_session(s);
 		return;
 	}

 	if (c->read->ready) {
		ngx_gateway_im_proxy_init_protocol(c->read);
 	}

 	return;
 }

 static void
 ngx_gateway_im_proxy_dummy_write_handler(ngx_event_t *wev)
 {
 	ngx_connection_t 				*c;
 	ngx_gateway_session_t 			*s;

 	c = wev->data;
 	s = c->data;

 	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, wev->log, 0,
 				"gateway im proxy dummy write handler: %d", c->fd);

 	if (ngx_handle_write_event(wev, 0) != NGX_OK) {
 		ngx_gateway_finalize_session(s);
 	}
 }

 static void 
 ngx_gateway_im_proxy_dummy_read_hander(ngx_event_t *rev)
 {
 	ngx_connection_t 				*c;
 	ngx_gateway_session_t 			*s;

 	c = rev->data;
 	s = c->data;

 	ngx_log_debug1(NGX_LOG_DEBUG_GATEWAY, rev->log, 0,
 				"gateway im proxy dummy read handler: %d", c->fd);

 	if (ngx_handle_read_event(rev, 0) != NGX_OK) {
 		ngx_gateway_finalize_session(s);
 	}
 }

 static void 
 ngx_gateway_im_proxy_init_protocol(ngx_event_t *ev)
 {
 	ngx_connection_t 					*c;
 	ngx_gateway_session_t 				*s;
 	ngx_gateway_im_proxy_biz_conf_t 	*ipcf;

 	c = ev->data;
 	s = c->data;

 	ipcf = ngx_gateway_get_module_srv_conf(s, ngx_gateway_im_proxy_module);


 	c->read->handler = ngx_gateway_im_proxy_parse_protocol;

 	ngx_gateway_im_proxy_parse_protocol(ev);
 }

 static void 
 ngx_gateway_im_proxy_parse_protocol(ngx_event_t *ev)
 {
 	u_char								*new_buf;
 	ssize_t 							size, n;
 	ngx_int_t 							rc;
 	ngx_connection_t 					*c;
 	ngx_gateway_session_t				*s;
 	ngx_gateway_request_t 				*r;
 	ngx_gateway_im_proxy_biz_conf_t 	*ibcf;
 	ngx_gateway_core_srv_conf_t			*cscf;

 	c = ev->data;
 	s = c->data;

 	ibcf = ngx_gateway_get_module_biz_conf(s, ngx_gateway_im_proxy_module);

 	cscf = ngx_gateway_get_module_srv_conf(s, ngx_gateway_core_module);

 	while (1) {
 		n = s->buffer->end - s->buffer->last;
 		/* not enough buffer? Enlarge twice */
 		if (0 == n) {
 			size = s->buffer->end - s->buffer->start;

 			if ((size_t)size > cscf->buffer_size << 3) {

 				ngx_log_error(NGX_LOG_ERROR, ev->log, 0, 
 					"too large im packege "
 					"error whit client: %V #%d",
 					&c->addr_text, c->fd);

 				ngx_gateway_finalize_session(s);
 				return;
 			}

 			new_buf = ngx_palloc(c->pool, size *2);
 			if (NULL == new_buf) {
 				goto im_protocol_recv_fail;
 			}

 			n = s->buffer->pos - s->buffer->start;

 			ngx_memcpy(new_buf, s->buffer->pos, size - n);

 			
 			s->buffer->start = new_buf;
 			s->buffer->pos = new_buf;
 			s->buffer->last = new_buf + size;
 			s->buffer->end = new_buf + size * 2;

 			n = s->buffer->end - s->buffer->last;
 		}

 		size = c->recv(c, s->buffer->last, n);

 #if (NGX_DEBUG)
 		ngx_err_t 				err;

 		if (size >= 0 || size == NGX_AGAIN) {
 			err = 0;
 		} else {
 			err = ngx_socket_errno;
 		}

 		ngx_log_debug3(NGX_LOG_DEBUG_GATEWAY, ev->log, err,
 						"im proxy recv size: %d, client: %V #%d",
 						size, &c->addr_text, c->fd);
 #endif

 		if (size > 0) {
 			s->buffer->last += size;
 			continue;
 		} else if (size == 0 || size == NGX_AGAIN){
 			break;
 		} else {
 			c->error = 1;
 			goto im_protocol_recv_fail;
 		}
  	}

  	n = s->buffer->last - s->buffer->pos;

 	while (n > 0) {

 		r = ngx_gateway_create_request(s);
 		if (NULL == r) {
 			return;
 		}

 		rc = im_proxy_request_parser_execute(s, r);

 		switch (rc) {
 		case NGX_AGAIN:
 			ngx_gateway_close_request(r);
 			return;
 		case NGX_ERROR:
 			ngx_gateway_close_request(r);
 			goto im_protocol_recv_fail;
 		case NGX_OK:
 			ngx_gatway_im_proxy_init_upstream(c, r);
 		}

 		n = s->buffer->end - s->buffer->last;
 	}

 im_protocol_recv_fail:

 	ngx_log_error(NGX_LOG_ERR, ev->log, 0,
 		"recv im packet error with client: %V #%d",
 		&c->addr_text, c->fd);

 	ngx_gateway_finalize_session(s); 

 }

 static ngx_int_t
 im_proxy_request_parser_execute(ngx_gateway_session_t *s, ngx_gateway_request_t *r)
 {
 	ngx_gateway_im_proxy_request_data_t		*iprd;
 	ngx_int_t 								rc;
 	size_t 									n;

 	iprd = ngx_pcalloc(r->pool, sizeof(ngx_gateway_im_proxy_request_data_t));
 	if (NULL == iprd) {
 		return NGX_ERROR;
 	}

 	r->data = iprd;

 	rc = NGX_AGAIN;

 	while (1) {
 		n = s->buffer->last - s->buffer->pos;
 		if (0 == n) {
 			break;
 		}

 		rc = check_data(s->buffer->pos, n, iprd);
 		if (NGX_ERROR == rc) {
 			s->buffer->last += 1;
 		} else {
 			break;
 		}
 	}

 	return rc;
 }

 static void 
 ngx_gatway_im_proxy_init_upstream(ngx_connection_t *c, ngx_gateway_request_t *r)
 {
 	
 }

 static char *
 ngx_gateway_im_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
 {
 	ngx_gateway_im_proxy_biz_conf_t		*ibcf = conf;

 	u_short 							port = 10000;
 	ngx_str_t 							*value, *url = &ibcf->url;
 	ngx_url_t							u;
 	ngx_gateway_core_srv_conf_t			*cscf;

 	cscf = ngx_gateway_conf_get_module_srv_conf(cf, ngx_gateway_core_module);

 	if (cscf->protocol && ngx_strncmp(cscf->protocol->name.data, 
 									(u_char *)"im_proxy",
 									sizeof("im_proxy") - 1) != 0) {
 		return "the protocol should be im_proxy";
 	}

 	if (cscf->protocol == NULL) {
 		cscf->protocol = &ngx_gateway_im_proxy_protocol;
 	}

 	if (ibcf->upstream.upstream) {
 		return "is duplicate";
 	}

 	value = cf->args->elts;

 	url = &value[1];

 	ngx_memzero(u, sizeof(ngx_url_t));

 	u.url.len = url->len;
 	u.url.data = url->data;
 	u.default_port = port;
 	u.uri_part = 1;
 	u.no_resolve = 1;

 	ibcf->upstream.upstream = ngx_gateway_upstream_add(cf, &u, 0);
 	if (NULL == ibcf->upstream.upstream) {
 		return NGX_CONF_ERROR;
 	}

 	return NGX_CONF_OK;
 }

 static void *
 ngx_gateway_im_proxy_create_biz_conf(ngx_conf_t *cf)
 {
 	ngx_gateway_im_proxy_biz_conf_t *ibcf;

 	ibcf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_im_proxy_biz_conf_t));
 	if (NULL == ibcf) {
 		return NULL;
 	}

 	ibcf->buffer_size = NGX_CONF_UNSET_SIZE;

 	ibcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;i
 	ibcf->upstream.write_timeout = NGX_CONF_UNSET_MSEC;
 	ibcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

 	return ibcf;
 }

 static char *
 ngx_gateway_im_proxy_merge_biz_conf(ngx_conf_t *cf, void *parent, void *child)
 {
 	ngx_gateway_im_proxy_conf_t *prev = parent;
 	ngx_gateway_im_proxy_conf_t *conf = child;

 	ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, (size_t)ngx_pagesize);
 	ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000)
 	ngx_conf_merge_msec_value(conf->upstream.write_timeout, prev->upstream.write_timeout, 60000);
 	ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);

 	return NGX_CONF_OK;
 }




 