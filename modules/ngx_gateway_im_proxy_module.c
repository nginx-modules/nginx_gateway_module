
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

 