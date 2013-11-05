
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
 } ngx_gateway_im_proxy_conf_t;

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
 static void *ngx_gateway_im_proxy_create_conf(ngx_conf_t *cf);
 static char *ngx_gateway_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child);

 static ngx_gateway_protocol_t ngx_gateway_im_proxy_protocol = {

 	ngx_string("im_proxy"),
 	{0, 0, 0, 0},
 	NGX_GATEWAY_IM_PROXY_PROTOCOL,
 	ngx_gateway_im_proxy_init_session,
 	ngx_gateway_im_proxy_init_protocol,
 	ngx_gateway_im_proxy_parse_protocol,
 	ngx_string("500 Internal server error" CRLF)
 }

 static ngx_command_t ngx_gateway_proxy_commands[] = {

 	{
 		ngx_string("proxy_pass"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_gateway_im_proxy_pass,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("proxy_buffer"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_size_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_conf_t, buffer_size),
 		NULL
 	},

 	{
 		 ngx_string("proxy_connect_timeout"),
 		 NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		 ngx_conf_set_msec_slot,
 		 NGX_GATEWAY_SRV_CONF_OFFSET,
 		 offsetof(ngx_gateway_im_proxy_conf_t, upstream.connect_timeout),
 		 NULL
 	},

 	{
 		ngx_string("proxy_read_timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_conf_t, upstream.read_timeout),
 		NULL,
 	}

 	{
 		ngx_string("proxy_write_timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_im_proxy_conf_t, upstream.write_timeout),
 		NULL
 	},

 	ngx_null_command
 };

 static ngx_gateway_module_t  ngx_gateway_im_proxy_module_ctx = {
 	
 }





 