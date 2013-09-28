/*
 * Copyright (c) 2013 Zhuyx
 */


 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_evnet.h>
 #include <nginx.h>
 #include "ngx_gateway.h"


 static char *ngx_gateway_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static ngx_int_t ngx_gateway_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_gateway_listen_t *listen);
 static char *ngx_gateway_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
 static ngx_int_t ngx_gateway_add_addrs(ngx_conf_t *cf, ngx_gateway_port_t *mport, ngx_gateway_conf_addr_t *addr);

 #if (NGX_HAVE_INET6)
 static ngx_int_t ngx_gateway_add_addrs(ngx_conf_t *cf, ngx_gateway_port_t *mport, ngx_gateway_conf_addr_t *addr);
 #endif

 ngx_uint_t ngx_gateway_max_module;


 static ngx_command_t ngx_gateway_commands[] = {

 	{ ngx_string("gateway"),
 	  NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
 	  ngx_gateway_block,
 	  0,
 	  0,
 	  NULL },

 	  ngx_null_command
 };

 static ngx_core_module_t ngx_gateway_module_ctx = {
 	ngx_string("gateway"),
 	NULL,
 	NULL
 };

 ngx_module_t ngx_gateway_module = {
 	NGX_MODULE_V1,
 	&ngx_gateway_module_ctx,
 	ngx_gateway_commands,
 	NGX_CORE_MODULE,
 	NULL,
 	NULL,
 	NULL,
 	NULL,
 	NULL,
 	NULL,
 	NULL,
 	NGX_MODULE_V1_PADDING
 };

 static char *
 ngx_gateway_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
 	char						*rv;
 	ngx_uint_t					i, m, mi, s;
 	ngx_conf_t 					pcf;
 	ngx_array_t					ports;
 	ngx_gateway_listen_t		*listen;
 	ngx_gateway_module_t 		*module;
 	ngx_gateway_conf_ctx_t		*ctx;
 	ngx_gateway_core_main_conf_t	**cscfp;
 	ngx_gateway_core_main_conf_t	*cmcf;

 	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_conf_ctx_t));
 	if (NULL == ctx)
 	{
 		return NGX_CONF_ERROR;
 	}

 	*(ngx_gateway_conf_ctx_t **)conf = ctx;

 	ngx_gateway_max_module = 0;
 	for (int m = 0; ngx_modules[m]; ++m)
 	{
 		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE)
 		{
 			continue;
 		}

 		ngx_modules[m]->ctx_index = ngx_gateway_max_module++;
 	}

 	ctx->main_conf = ngx_pcalloc(cf->pool, sizeof(void*) * ngx_gateway_max_module);
 	if (NULL == ctx->main_conf)
 	{
 		return NGX_CONF_ERROR;
 	}

 	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_gateway_max_module);
 	if (NULL == ctx->srv_conf)
 	{
 		return NGX_CONF_ERROR;
 	}

 	ctx->biz_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_gateway_max_module);
 	if (NULL == ctx->biz_conf)
 	{
 		return NGX_CONF_ERROR;
 	}

 	for ( m = 0; ngx_modules[m]; ++m)
 	{
 		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 			continue;
 		}

 		module = ngx_modules[m]->ctx;
 		mi = ngx_modules[m]->ctx_index;

 		if (module->create_main_conf) {
 			ctx->main_conf[mi] = module->create_main_conf(cf);
 			if (NULL == ctx->main_conf[mi]){
 				return NGX_CONF_ERROR;
 			}
 		}

 		if (module->create_srv_conf) {
 			ctx->srv_conf[mi] = module->create_srv_conf(cf);
 			if (NULL == ctx->srv_conf[mi]) {
 				return NGX_CONF_ERROR;
 			}
 		}

 		if (module->create_biz_conf) {
 			ctx->biz_conf[mi] = module->create_biz_conf(cf);
 			if (NULL == ctx->biz_conf[mi]) {
 				return NGX_CONF_ERROR;
 			}
 		}
 	}

 	pcf = *cf;
 	cf->ctx = ctx;
 	cf->module_type = NGX_GATEWAY_MODULE;
 	cf->cmd_type = NGX_GATEWAY_MAIN_CONF;

 	rv = ngx_conf_parse(cf, NULL);
 	if (NGX_CONF_OK != rv) {
 		*cf = pcf;
 		return rv;
 	}

 	cmcf = ctx->main_conf[ngx_gateway_core_module.ctx_index];
 	cscfp = cmcf->servers.elts;

 	for (m = 0; ngx_modules[m]; ++m) {
 		if ()
 	}


 }


