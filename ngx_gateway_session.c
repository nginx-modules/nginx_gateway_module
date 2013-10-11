/*
 * Copyright (c) 2013 Zhuyx
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_event.h>
 #include <ngx_gateway.h>

 static void ngx_gateway_init_session(ngx_connection_t *c);
 static void ngx_gateway_set_session_socket(ngx_gateway_session_t *s);
 static void ngx_gateway_process_session(ngx_connection_t *c);

 void 
 ngx_gateway_init_connection(ngx_connection_t *c)
 {
 	
 }
