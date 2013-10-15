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

 static ngx_gateway_cmp_conf_addr(const void *one, const void *two);

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
 		if ( ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 			continue;
 		}

 		module = ngx_modules[m];
 		mi = ngx_modules[m]->ctx_index;

 		cf->ctx = ctx;

 		if (module->init_main_conf) {
 			rv = module->init_main_conf(cf, ctx->main_conf[mi]);
 			if (rv != NGX_CONF_OK) {
 				*cf = pcf;
 				return rv;
 			}

 			for (s = 0; s < cmcf->servers.nelts; ++s) {

 				cf->ctx = cscfp[s]->ctx;

 				if (module->merge_srv_conf) {
 					rv = module->merge_srv_conf(cf, ctx->srv_conf[mi], cscfp[s]->ctx->srv_conf[mi]);
 					if (rv != NGX_CONF_OK) {
 						*cf = pcf;
 						return rv;
 					}
 				}

 				if (module->merge_biz_conf) {
 					rv = module->merge_biz_conf(cf, ctx->biz_conf[mi], cscfp[s]->ctx->biz_conf[mi]);
 					if (rv != NGX_CONF_OK) {
 						*cf = pcf;
 						return rv;
 					}
 				}

 				cscf = cscfp[s]->ctx->srv_conf[ngx_gateway_core_module.ctx_index];

 				rv = ngx_gateway_merge_business(cf, &cscf->businesses, cscf->biz_conf, module, mi);
 				if (rv != NGX_CONF_OK ) {
 					*cf = pcf;
 					return rv;
 				}
 			}
 		}
 	}

 	*cf = pcf;

 	if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_gateway_conf_port_t))
 		!= NGX_OK)
 	{
 		return NGX_CONF_ERROR;
 	}

 	listen = cmcf->listen.elts;

 	for (i = 0; i < cmcf->listen.nelts; ++i ) {
 		if (ngx_gateway_add_ports(cf, &ports, &listen[i]) != NGX_OK ) {
 			return NGX_CONF_ERROR;
 		} 
 	}

 	return ngx_gateway_optimize_servers(cf, cmcf, &ports);
 }


static char *
ngx_gateway_merge_business(ngx_conf_t *cf, ngx_array_t *businesses, void **biz_conf, 
						ngx_gateway_module_t *module, ngx_uint_t ctx_index)
{
	char							*rv;
	ngx_gateway_conf_ctx_t			*ctx, saved;
	ngx_gateway_core_biz_conf_t		**cbcfp;
	ngx_uint_t						n;
	ngx_gateway_core_biz_conf_t		*cbcf;

	if (NULL == businesses) {
		return NGX_CONF_OK;
	}

	ctx = (ngx_gateway_core_biz_conf_t *)cf->ctx;
	saved = *ctx;

	cbcfp = businesses->elts;
	for (n = 0; n < businesses->nelts; ++n, ++cbcfp) {

		ctx->biz_conf = (*cbcfp)->biz_conf[ctx_index];  /* ????????*/

		rv = module->merge_biz_conf(cf, biz_conf[ctx_index], (*cbcfp)->biz_conf[ctx_index]);
		if (rv != NGX_CONF_OK) {
			return rv;
		}

		cbcf = (*cbcfp)->biz_conf[ngx_gateway_core_module.ctx_index];

		rv = ngx_gateway_merge_business(cf, &cbcf->businesses, (*cbcfp)->biz_conf, module, ctx_index);
		if (rv != 	NGX_CONF_OK) {
			return rv;
		}

	} 

	*ctx = saved;

	return NGX_CONF_OK;

}

static ngx_uint_t 
ngx_gateway_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_gateway_listen_t *listen)
{
	in_port_t						p;
	ngx_uint_t						i;
	struct sockaddr					*sa;
	struct sockaddr_in				*sin;
	ngx_gateway_conf_port_t			*port;
	ngx_gateway_conf_addr_t			*addr;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6				*sin6;
#endif

	sa = (struct sockaddr *)&listen->sockaddr;

	switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
		p = sin6->sin6_port;
		break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
	case AF_UNIX:
		p = 0;
		break;
#endif

	default: /* AF_INET */
		sin = (struct sockaddr_in *)sa;
		p = sin->sin_port;
		break;
	}

	port = ports->elts;

	for (i = 0; i < ports->nelts; ++i) {
		if (p == port[i].port && sa->sa_family == port[i].sa_family) {
			port = &port[i];
			goto gound;
		}
	}

	port = ngx_array_push(ports);
	if (NULL == port) {
		return NGX_ERROR;
	}

	port->family = sa->sa_family;
	port->port = p;

	if (ngx_array_init(&port->addrs, cf->temp_pool, 2, sizeof(ngx_gateway_conf_port_t))
		!= NGX_OK )
	{
		return NGX_ERROR;
	}

FOUND:

	addr = ngx_array_push(&port->addrs);
	if (NULL == addr){
		return NGX_ERROR;
	}

	addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
	addr->socklen = listen->socklen;
	addr->ctx = listen->ctx;
	addr->bind = listen->bind;
	addr->wildcard = listen->wildcard;
	if (listen->default_port) {
		addr->default_ctx = listen->ctx;
	}
	addr->so_keeplive = listen->so_keeplive;
#if (NGX_HAVE_KEEPLIVE_TUNABLE)
	addr->tcp_keepidle = listen->tcp_keepidle;
	addr->tcp_keepintvl = listen->tcp_keepintvl;
	addr->tcp_keepcnt = listen->tcp_keepcnt;
#endif 

#if (NGX_HAVE_INT6 && defined IPV6_V6ONLY)
	addr->ipv6only = listen->ipv6only;
#endif

	return NGX_OK;
}

static char *
ngx_gateway_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
	ngx_uint_t					i, p, last, bind_wildcard;
	ngx_listening_t				*ls;
	ngx_gateway_port_t 			*mport;
	ngx_gateway_conf_port_t		*port;
	ngx_gateway_conf_addr_t		*addr;

	port = ports->elts;
	for (p = 0; p < ports->nelts; ++p) {
		ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts, 
			sizeof(ngx_gateway_conf_port_t), ngx_gateway_cmp_conf_addr);

		addr = port[p].addrs.elts;
		last = port[p].addrs.nelts;  

		/*
		 * if there is the binding to the "*:port" then we need to bind()
		 * to the "*:port" only and ignore the other bindings
		 */

		if (addr[last - 1].wildcard ) {
			addr[last - 1].bind = 1;
			bind_wildcard = 1;
		} else {
			bind_wildcard = 0;
		}

		i = 0;

		while (i < last) {
			if (bind_wildcard && !addr[i].bind) {
				i++;
				continue;
			}

			ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
			if (NULL == ls) {
				return NGX_CONF_ERROR;
			}

			ls->addr_ntop = 1;
			ls->handler = ngx_gateway_init_connection;
			ls->pool_size = 256;

			ls->logp = &cf->cycle->new_log;
			ls->log.data = &ls->addr_text;
			ls->log.handler = ngx_accept_log_error;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
			ls->ipv6only = addr[i].ipv6only;
#endif

			mport = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_port_t));
			if (NULL == mport) {
				return NGX_CONF_ERROR;
			}

			ls->servers = mport;

			if ( i == last -1) {
				mport->naddrs = last;
			} else {
				mport->naddrs = 1;
				i = 0;
			}

			switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
			case AF_INET6:
				if (ngx_gateway_add_addrs6(cf, mport, addr) != NGX_ERROR) {
					return NGX_CONF_ERROR;
				}
				break;
#endif
			default: /* AF_INET */
				if (ngx_gateway_add_addrs(cf, mport, addr) != NGX_ERROR ) {
					return NGX_CONF_ERROR;
				}
				break;
			}

			++addr;
			--last;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_gateway_add_addrs(ngx_conf_t *cf, ngx_gateway_port_t *mport, ngx_gateway_conf_addr_t *addr)
{
	u_char						*p;
	size_t						len;
	ngx_uint_t					i, j;
	ngx_gateway_in_addr_t		*addrs;
	struct sockaddr_in 			*sin, *sin_b;
	u_char						buf[NGX_SOCKADDR_STRLEN];

	mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(ngx_gateway_in_addr_t));
	if (NULL == mport->addrs) {
		return NGX_ERROR;
	}

	addrs = mport->addrs;

	for (i = 0; i < mport->naddrs; ++i) {
		sin = (struct sockaddr_in *)addr[i].sockaddr;
		addrs[i].addr = sin->sin_addr.s_addr;

		addrs[i].conf.ctx = addr[i].ctx;

		for (j = 0; j < mport->naddrs; ++j) {
			sin_b = (struct sockaddr_in *)addr[j].sockaddr;
			if ((sin->sin_addr.s_addr == sin_b->sin_addr.s_addr) &&
				addr[j].default_ctx) {
				addrs[i].conf.default_ctx = addr[j].default_ctx;
			}
		}

#if defined(nginx_version) && nginx_version >= 1005003
		len = ngx_sock_ntop(addr[i].sockaddr, addr[i].socklen, buf, NGX_SOCKADDR_STRLEN, 1);
#else
		len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);
#endif

		p = ngx_pcalloc(cf->pool, len);
		if (NULL == p) {
			return NGX_ERROR;
		}

		ngx_memcpy(p, buf, len);
		addrs[i].conf.addr_text.len = len;
		addrs[i].conf.addr_text.data = p;
	}

	return NGX_OK;
}

#if (NGX_HAVE_INET6)


static ngx_int_t 
ngx_gateway_add_addrs6(ngx_conf_t *cf, ngx_gateway_port_t *mport, ngx_gateway_conf_addr_t *addr)
{
	u_char						*p;
	size_t						len;
	ngx_uint_t					i, j;
	ngx_gateway_in6_addr_t		*addrs6;
	struct sockaddr_in6			*sin6, *sin6_b;
	u_char						buf[NGX_SOCKADDR_STRLEN];

	mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(ngx_gateway_in6_addr_t));
	if (mport->addrs == NULL) {
		return NGX_ERROR;
	}

	addrs6 = mport->addrs;

	for (i = 0; i < mport->naddrs; ++i) {

		sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
		addrs6[i].addr6 = sin6->sin6_addr;

		addrs6[i].conf.ctx = sin6.ctx;

		for (j = 0; j < mport->naddrs; ++j) {
			sin6_b = (struct sockaddr_in6 *) addr[j].sockaddr;

			if ((ngx_memcmp(&sin6->sin6_addr, &sin6_b->sin6_addr, 16) == 0) &&
				addr[j].default_ctx) {
				addrs[i].conf.default_ctx = addr[j].default_ctx;
			}
		}

#if defined(nginx_version) && nginx_version >= 1005003
		len = ngx_sock_ntop(addr[i].sockaddr, addr[i].socklen, buf, NGX_SOCKADDR_STRLEN, 1);
#else
		len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);
#endif

		p = ngx_pcalloc(cf->pool, len);
		if (NULL == p) {
			return NGX_ERROR;
		}

		ngx_memcpy(p, buf, len);
		addrs6[i].conf.addr_text.len = len;
		addrs6[i].conf.addr_text.data = p;
	}

	return NGX_OK;
}

#endif

static ngx_int_t
ngx_gateway_cmp_conf_addr(const void *one, const void *two)
{
	ngx_gateway_conf_port_t		*first, *second;

	first = (ngx_gateway_conf_port_t *)one;
	second = (ngx_gateway_conf_port_t *)two;

	if (first->wildcard) {
		return 1;
	}

	if (second->wildcard) {
		return -1;
	}

	if (first->bind && !second->bind) {
		return -1;
	}

	if (!first->bind && second->bind) {
		return 1;
	}

	return 0;
}

