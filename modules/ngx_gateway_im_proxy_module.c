
/*
 * Copyright (c) 2013 Zhuyx
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_gateway.h>


 typedef struct ngx_gateway_im_proxy_s {
 	ngx_peer_connection_t			*upstream;
 	ngx_buf_t						*buffer;
 }ngx_gateway_im_proxy_ctx_t;

 typedef struct ngx_gateway_im_proxy_conf_s {
 	ngx_gateway_upstream_conf_t 	upstream;

 	ngx_str_t 						url;
 	size_t							buffer_size;
 } ngx_gateway_im_proxy_biz_conf_t;

 static void ngx_gateway_im_proxy_init_session(ngx_gateway_session_t *s);
 static void ngx_gateway_im_proxy_init_protocol(ngx_event_t *ev);
 static void ngx_gateway_im_proxy_parse_protocol(ngx_event_t *ev); 
 static void ngx_gatway_im_proxy_init_upstream(ngx_connection_t *c, ngx_gateway_session_t *s);
 static void ngx_gateway_upstream_init_proxy_handler(ngx_gateway_session_t *s,
 		ngx_gateway_upstream_t *u);
 static char *ngx_gateway_im_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static void ngx_gateway_im_proxy_dummy_read_hander(ngx_event_t *ev);
 static void ngx_gateway_im_proxy_dummy_write_handler(ngx_event_t *ev);

 static void ngx_gateway_im_proxy_handler(ngx_event_t *ev);

 static void *ngx_gateway_im_proxy_create_srv_conf(ngx_conf_t *cf);
 static char *ngx_gateway_im_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
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

 	iptx = ngx_pcalloc(s->connection->pool, sizeof(ngx_gateway_im_proxy_ctx_t));
 	if (NULL == iptx) {
 		ngx_gateway_finalize_session(s);
 		return;
 	}

 	ngx_gateway_set_ctx(s, iptx, ngx_gateway_im_proxy_module);

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
 	
 }

 static void *
 ngx_gateway_im_proxy_create_biz_conf(ngx_conf_t *cf)
 {
 	ngx_gateway_im_proxy_biz_conf_t *pbcf;

 	pbcf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_im_proxy_biz_conf_t));
 	if (NULL == pbcf) {
 		return NULL;
 	}

 	pbcf->buffer_size = NGX_CONF_UNSET_SIZE;

 	pbcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
 	pbcf->upstream.write_timeout = NGX_CONF_UNSET_MSEC;
 	pbcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

 	return pbcf;
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




 