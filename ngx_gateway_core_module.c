/*
 * Copyright (c) 2013 Zhuyx
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_event.h>
 #include <ngx_gateway.h>
 #include <nginx.h>


 static void *ngx_gateway_core_create_main_conf(ngx_conf_t *cf);
 static void *ngx_gateway_core_create_srv_conf(ngx_conf_t *cf);
 static void *ngx_gateway_core_create_biz_conf(ngx_conf_t *cf);
 static char *ngx_gateway_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
 static char *ngx_gateway_core_merge_biz_conf(ngx_conf_t *cf, void *parnet, void *child);

 static char *ngx_gateway_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_core_business(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_core_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_gateway_log_set_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

 static ngx_command_t ngx_gateway_core_commands[] = {

 	{
 		ngx_string("server"),
 		NGX_GATEWAY_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS.
 		ngx_gateway_core_server,
 		0,
 		0,
 		NULL
 	},

 	{
 		ngx_string("listen"),
 		NGX_GATEWAY_SRV_CONF|NGX_CONF_1MORE,
 		ngx_gateway_core_listen,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("business"),
 		NGX_GATEWAY_SRV_CONF|NGX_GATEWAY_BIZ_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
 		ngx_gateway_core_business,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("protocol"),
 		NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_gateway_core_protocol,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("so_keepalive"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_FLAG,
 		ngx_conf_set_flag_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_core_srv_conf_t,so_keepalive),
 		NULL
 	},

 	{
 		ngx_string("tcp_nodelay"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_FLAG,
 		ngx_conf_set_flag_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_core_srv_conf_t, tcp_nodelay),
 		NULL
 	},

 	{
 		ngx_string("timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		offsetof(ngx_gateway_core_srv_conf_t, timeout),
 		NULL
 	},

 	{
 		ngx_string("resolver"),
 #if defined(nginx_version) && (nginx_version >= 1001007)
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_1MORE,
 #else
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 #endif
 		ngx_gateway_core_resolver,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("resolver_timeout"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_conf_set_msec_slot,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("allow"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_gateway_core_access_rule,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("deny"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE1,
 		ngx_gateway_core_access_rule,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	{
 		ngx_string("access_log"),
 		NGX_GATEWAY_MAIN_CONF|NGX_GATEWAY_SRV_CONF|NGX_CONF_TAKE12,
 		ngx_gateway_log_set_access_rule,
 		NGX_GATEWAY_SRV_CONF_OFFSET,
 		0,
 		NULL
 	},

 	ngx_null_command

 };

 static ngx_gateway_module_t ngx_gateway_core_module_ctx = {
 	NULL,											/* protocol */

 	ngx_gateway_core_create_main_conf,				/* create main configuration */
 	NULL,											/* init main configuration */

 	ngx_gateway_core_create_srv_conf,				/* create srv configuration */
 	ngx_gateway_core_merge_srv_conf,				/* merge srv configuration */

 	ngx_gateway_core_create_biz_conf,				/* create biz configuration */
 	ngx_gateway_core_merge_biz_conf					/* merge biz configuration*/
 };

 ngx_module_t ngx_gateway_core_module = {
 	NGX_MODULE_V1,
 	&ngx_gateway_core_module_ctx,					/* module context */
 	ngx_gateway_core_commands,						/* module directives */
 	NGX_GATEWAY_MODULE,								/* module type */
 	NULL,											/* init master */
 	NULL,											/* init module */
 	NULL,											/* init process */
 	NULL,											/* init thread */
 	NULL,											/* exit thread */
 	NULL,											/* exit process */
 	NULL,											/* exit master */
 	NGX_MODULE_VI_PADDING
 };

 static void *
 ngx_gateway_core_create_main_conf(ngx_conf_t *cf)
 {
 	ngx_gateway_core_main_conf_t *cmcf;

 	cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_core_main_conf_t));
 	if (NULL == cmcf)
 	{
 		return NULL;
 	}

 	if (ngx_array_init(&cmcf->servers, cf->pool, 4,
 						sizeof(ngx_gateway_core_srv_conf_t *))
 		!= NGX_OK)
 	{
 		return NULL;
 	}

 	if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_gateway_listen_t))
 		!= NGX_OK )
 	{
 		return NULL;
 	}

 	return cmcf;
 }

 static void *
 ngx_gateway_core_create_srv_conf(ngx_conf_t *cf)
 {
 	ngx_gateway_core_srv_conf_t *cscf;

 	cscf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_core_srv_conf_t));
 	if (NULL == cscf)
 	{
 		return NULL;
 	}

 	if (ngx_array_init(&cscf->business, cf->pool, 4, sizeof(ngx_gateway_core_biz_conf_t* ))
 		!= NGX_OK)
 	{
 		return NULL;
 	}

 	cscf->timeout = NGX_CONF_UNSET_MSEC;
 	cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
 	cscf->so_keepalive = NGX_CONF_UNSET;
 	cscf->tcp_nodelay = NGX_CONF_UNSET;

 	cscf->resolver = NGX_CONF_UNSET_PTR;

 	cscf->file_name = cf->conf_file->file.name.data;
 	cscf->line = cf->conf_file->line;

 	cscf->access_log = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_log_srv_conf_t));
 	if (NULL == cscf->access_log)
 	{
 		return NULL;
 	}

 	cscf->access_log->open_file_cache = NGX_CONF_UNSET_PTR;

 	return cscf;
 }

 static char *
 ngx_gateway_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
 {
 	ngx_uint_t					m;
 	ngx_gateway_log_t 			*log;
 	ngx_gateway_module_t 		*module;
 	ngx_gateway_core_srv_conf_t	*prev = parent;
 	ngx_gateway_core_srv_conf_t *conf = child;
 	ngx_gateway_log_srv_conf_t	*plscf = prev->access_log;
 	ngx_gateway_log_srv_conf_t	*lscf = conf->access_log;

 	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
 	ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout, 30000);

 	ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);
 	ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

 	ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);
 	ngx_conf_merge_ptr_value(conf->rules, prev->rules, NULL);

 	if ( NULL == conf->protocol )
 	{
 		for (m = 0; ngx_modules[m]; ++m) {
 			if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 				continue;
 			}

 			module = ngx_modules[m]->ctx;

 			if (module->protocol && ngx_strcmp(module->protocol->name.data, "tcp_proxy_generic") == 0 )
 			{
 				conf->protocol = module->protocol;
 			}
 		}
 	}

 	if (lscf->open_file_cache == NGX_CONF_UNSET_PTR)
 	{
 		lscf->open_file_cache = plscf->open_file_cache;
 		lscf->open_file_cache_valid = plscf->open_file_cache_valid;
 		lscf->open_file_cache_min_uses = plscf->open_file_cache_min_uses;

 		if (lscf->open_file_cache == NGX_CONF_UNSET_PTR)
 		{
 			lscf->open_file_cache = NULL;
 		}
 	}

 	if (lscf->logs || lscf->off)
 	{
 		return NGX_CONF_OK;
 	}

 	lscf->logs = plscf->logs;
 	lscf->off = plscf->off;

 	if (lscf->logs || lscf->off)
 	{
 		return NGX_CONF_OK;
 	}

 	lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_gateway_log_t));
 	if (NULL == lscf->logs) {
 		return NGX_CONF_ERROR;
 	}

 	log = ngx_array_push(lscf->logs);
 	if (NULL == log) {
 		return NGX_CONF_ERROR;
 	}

 	log->file = ngx_conf_open_file(cf->cycle, &ngx_gateway_access_log);
 	if (NULL == log->file) {
 		return NGX_CONF_ERROR;
 	}

 	log->disk_full_time = 0;
 	log->error_log_time = 0;

 	return NGX_CONG_OK;
 }

 static void *
 ngx_gateway_core_create_biz_conf(ngx_conf_t *cf)
 {
 	ngx_gateway_core_biz_conf_t *cbcf;

 	cbcf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_core_biz_conf_t));
 	if (NULL == cbcf) {
 		return NULL;
 	}

 	if (ngx_array_init(&cbcf->business, cf->pool, 4, sizeof(ngx_gateway_core_biz_conf_t *))
 		!= NGX_OK)
 	{
 		return NULL;
 	}

 	return cbcf;
 }

 static char *
 ngx_gateway_core_merge_biz_conf(ngx_conf_t *cf, void *parent, void *child)
 {
 	ngx_gateway_core_biz_conf_t *prev = parent;
 	ngx_gateway_core_biz_conf_t *conf = child;

 	(void)prev;
 	(void)conf;

 	return NGX_CONF_OK;
 }

 static char *
 ngx_gateway_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
 	char							*rv;
 	void							*mconf;
 	ngx_uint_t						m;
 	ngx_conf_t 						pcf;  
 	ngx_gateway_modult_t			*module;
 	ngx_gateway_conf_ctx_t			*ctx, *gateway_ctx;
 	ngx_gateway_core_srv_conf_t		*cscf, **cfcfp;
 	ngx_gateway_core_main_conf_t	*cmcf;

 	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_conf_ctx_t));
 	if ( NULL == ctx ) {
 		return NGX_CONF_ERROR;
 	}

 	gateway_ctx = cf->ctx;
 	ctx->main_conf = gateway_ctx->main_conf;

 	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_core_srv_conf_t));
 	if (NULL == ctx->srv_conf) {
 		return NGX_CONF_ERROR;
 	}

 	for (m = 0; ngx_modules[m]; ++m) {
 		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 			continue;
 		}

 		module = ngx_modules[m];

 		if (module->create_srv_conf) {
 			mconf = module->create_srv_conf(cf);
 			if (NULL != mconf) {
 				return NGX_CONF_ERROR;
 			}

 			ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;

 		}

 		if (module->create_biz_conf) {
 			mconf = module->create_biz_conf(cf);
 			if (NULL == mconf) {
 				return NGX_CONF_ERROR;
 			}

 			ctx->biz[ngx_modules[m]->ctx_index] = mconf;
 		}
 	}

 	cscf = ctx->srv_conf[ngx_gateway_core_module.ctx_index];
 	cscf->ctx = ctx;

 	cmcf = ctx->main_conf[ngx_gateway_core_module.ctx_index];

 	cscfp = ngx_array_push(&cmcf->servers);
 	if (NULL == cscfp) {
 		return NGX_CONF_ERROR;
 	}

 	*cscfp = cscf;

 	pcf = *cf;
 	cf->ctx = ctx;
 	cf->cmd_type = NGX_GATEWAY_SRV_CONF;

 	rv = ngx_conf_parse(cf, NULL);

 	*cf = pcf;

 	return rv;
 }

 static char *
 ngx_gateway_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
 	ngx_gateway_core_srv_conf_t		*cscf = conf;

 	size_t							len, off;
 	in_port_t						port;
 	ngx_str_t						*value;
 	ngx_url_t						u;
 	ngx_uint_t						i, m;
 	ngx_gateway_module_t 			*module;
 	struct sockaddr					*sa;
 	ngx_gateway_listen_t			*ls;
 	struct sockaddr_in				*sin;
 	ngx_gateway_core_main_conf_t	cmcf;
#if (NGX_HAVE_INET6)
 	struct sockaddr_in6				*sin6;
#endif

 	value = cf->args->elts;

 	ngx_memzero(&u, sizeof(ngx_url_t));
 	u.url = value[1];
 	u.listen = 1;

 	if (ngx_parse_url(cf->pool, &u) != NGX_OK ) {
 		if (u.err) {
 			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in \"%V\" of the \"listen\" directives",
 			u.err, &u.url );
 		}

 		return NGX_CONF_ERROR;
 	}

 	cmcf = ngx_gateway_conf_get_module_main_conf(cf, ngx_gateway_core_module);

 	ls = cmcf->listen.elts;

 	for (i = 0; i < cmcf->listen.nelts; ++i) {
 		sa = (struct sockaddr *) ls[i].sockaddr;

 		if (sa->sa_family != u.family) {
 			continue;
 		}

 		switch (sa->sa_family) {

 #if (NGX_HAVE_INET6)
 		case AF_INET6:
 			off  = offsetof(struct sockaddr_in6, sin6_addr);
 			len = 16;
 			sin6 = (struct sockaddr_in6 *)sa;
 			port = sin6->sin6_port;
 			break;
 #endif

 		default:
 			off = offsetof(struct sockaddr_in, sin_addr);
 			len = 4;
 			sin = (struct sockaddr_in *)sa;
 			port = sin->sin6_port;
 			break;
 		}

 		if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
 			continue;
 		}

 		if (port != u.port) {
 			continue;
 		}

 		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate \"%V\" address and port pair", &u.url)
 		return NGX_CONF_ERROR;
 	}

 	ls = ngx_array_push(&cmcf->listen);
 	if (NULL == ls) {
 		return NGX_CONF_ERROR;
 	}

 	ngx_memzero(ls, sizeof(ngx_gateway_listen_t));

 	ngx_memcpy(ls, u.sockaddr, u.socklen);

 	ls->socklen = u.socklen;
 	ls.wildcard = u.wildcard;
 	ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
 	ls->ipv6only = 1;
#endif 

 	if (cscf->protocol == NULL ) {
 		for (m = 0; ngx_modules[m]; ++m) {
 			if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 				continue;
 			}

 			module = ngx_modules[m];

 			if (NULL == module->protocol) {
 				continue;
 			}

 			for (i = 0; module->protocol->port[i] == u.port) {
 				cscf->protocol = module->protocol;
 				break;
 			}
 		}
 	}

 	for (i = 2; i < cf->args->nelts; ++i) {

 		if (ngx_strcmp(value[i].data, "bind") == 0) {
 			ls->bind = 1;
 			continue;
 		}

 		if (ngx_strcmp(value[i].data, "default") == 0) {
 			ls->default_port = 1;
 		}

 		if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
 #if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
 			struct sockaddr *sa;
 			u_char			buf[NGX_SOCKADDR_STRLEN];

 			sa = (struct sockaddr *)ls->sockaddr; 

 			if (sa->sa_family == AF_INET6) {
 				if (ngx_strcmp(&value[i].data[10], "n") == 0 ) {
 					ls->ipv6only = 1;
 				} else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
 					ls->ipv6only = 2;
 				} else {
 					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
 						"invalid ipv6only flags \"%s\"", 
 						&value[i].data[9]);

 					return NGX_CONF_ERROR;
 				}

 				ls->bind = 1; /* ?????// */

 			}else {
 #if defined(nginx_version) && nginx_version > 1005003
 				len = ngx_sock_ntop(sa, ls->socklen, buf, NGX_SOCKADDR_STRLEN, 1);
 #else
 				len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);
 #endif

 				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
 					"ipv6only os not supported "
 					"on addr \"%*s\", ignored", len, buf);
 			}

 			continue;
 #else
 			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
 				"bind ipv6only is not supported"
 				"on this platform");

 			return NGX_CONF_ERROR;
 #endif
 		}

 		if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

 			if (ngx_strcmp(&value[i].data[13], "on") == 0) {
 				ls->so_keepalive = 1;
 			} else if (ngx_strcmp(&value[i].data[13], "off") == 0 ) {
 				ls->so_keepalive = 2;
 			} else {
 #if (NGX_HAVE_KEEPLIVE_TUNABLE) 
 				u_char		*p, *end;
 				ngx_str_t	s;

 				end = value[i].data + value[i].len;
 				s.data = value[i].data + 13;

 				p = ngx_strlchr(s.data, end, ':');
 				if (NULL == p ) {
 					p = end;
 				}

 				if ( p > s.data) {
 					s.len = p - s.data;

 					ls->tcp_keepidle = ngx_parse_time(&s, 1);
 					if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
 						goto invalid_so_keeplive;
 					}
 				}

 				s.data = (p < end) ? (p + 1) : end;

 				p = ngx_strlchr(s.data, end, ':');
 				if (NULL == p) {
 					p = end;
 				}

 				if ( p > s.data ) {
 					s.len = p - s.data;

 					ls->tcp_keepintvl = ngx_parse_time(&s, 1);
 					if (ls->tcp_keepintvl == (time_t) NGX_ERROR ) {
 						goto invalid_so_keeplive;
 					}
 				}

 				s.data = (p < end) ? (p + 1) : end;

 				if (s.data < end) {
 					s.len = end - s.data;

 					ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
 					if (NGX_ERROR == ls->tcp_keepcnt) {
 						goto invalid_so_keeplive;
 					}
 				}

 				if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0 && ls->tcp_keepcnt == 0) {
 					goto invalid_so_keeplive;
 				}

 				ls->so_keepalive = 1;

 #else
 				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
 								"the \"so_keeplive\" parameter accepts "
 								"only \"on\" or \"off\" on this platform");
 				return NGX_CONF_ERROR;
  			}
 #endif

  			ls->bind = 1;

  			continue;

 #if (NGX_HAVE_KEEPLIVE_TUNABLE)
  		invalid_so_keeplive:

  			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0
  				"invalid so_keeplive value: \"%s\"",
  				&value[i].data[13]);
 #endif
 		}

 		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
 			"the invalid \"%V\" parameter", &value[i]);
 		return NGX_CONF_ERROR;
 	}

 	return NGX_CONF_OK;
 }

 static char *
 ngx_gateway_core_business(ngx_conf_t *cf, ngx_command_t *cmf, void *conf)
 {
 	char 									*rv;
 	ngx_int_t 								m;
 	ngx_str_t								*value;
 	ngx_conf_t 								save;
 	ngx_gateway_module_t 					*module;
 	ngx_gateway_conf_ctx_t 					*ctx, *pctx;
 	ngx_gateway_core_srv_conf_t 			*cscf;
 	ngx_gateway_core_biz_conf_t 			*cbcf, **cbcfp;

 	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_conf_ctx_t));
 	if (NULL == ctx ) {
 		return NGX_CONF_ERROR;
 	}

 	pctx = cf->ctx;
 	ctx->main_conf = pctx->main_conf;
 	ctx->srv_conf = pctx->srv_conf;

 	ctx->biz_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_gateway_max_module);
 	if (NULL == ctx->biz_conf) {
 		return NGX_CONF_ERROR;
 	}

 	for (m = 0; ngx_modules[m]; ++m) {
 		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 			continue;
 		}

 		module = ngx_modules[m];

 		if (module->create_biz_conf) {
 			ctx->biz_conf[ngx_modules[m].ctx_index] = module->create_biz_conf(cf);
 			if (NULL == ctx->biz_conf[ngx_modules[m].ctx_index]) {
 				return NGX_CONF_ERROR;
 			}
 		}
 	}

 	cbcf = ctx->biz_conf[ngx_gateway_core_module.ctx_index];
 	cbcf->biz_conf = ctx->biz_conf;

 	value = cf->args->elts;

 	cbcf->name = value[1];
 	cscf = pctx->srv_conf[ngx_gateway_core_module.ctx_index];

 	cbcfp = ngx_array_push(&cscf->businesses);
 	if (NULL == cbcfp) {
 		return NGX_CONF_ERROR;
 	}

 	*cbcfp = cbcf;

 	save = *cf;
 	cf->ctx = ctx;
 	cf->cmd_type = NGX_GATEWAY_BIZ_CONF;

 	rv = ng_conf_parse(cf, NULL);

 	*cf = save;

 	return rv;
 }

 static char *
 ngx_gateway_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
 	ngx_gateway_core_srv_conf_t *cscf =  conf;

 	ngx_str_t					*value;
 	ngx_uint_t 					m;
 	ngx_gateway_module_t 		*module;

 	value = cf->args->elts;

 	for (m = 0; ngx_modules[m]; ++m) {
 		if (ngx_modules[m]->type != NGX_GATEWAY_MODULE) {
 			continue;
 		}

 		module = ngx_modules[m];

 		if (module->protocol
 			&& ngx_strcmp(module->protocol->name.data, value[1].data) == 0) {

 			cscf->protocol = module->protocol;

 			return NGX_CONF_OK;
 		}
 	}

 	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
 		"unknown protocol \"%V\"", &value[1]);

 	return NGX_CONF_ERROR;
 }

static char *
ngx_gateway_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_gateway_core_srv_conf_t		*cscf = conf;

#if defined(nginx_version) && nginx_version < 1001007
	ngx_url_t						u;
#endif

	ngx_str_t						*value;

	value = cf->args->elts;

	if (cscf->resolver != NGX_CONF_UNSET_PTR) {
		return “is duplicate”;
	}

	if (ngx_strcmp(value[1].data, "off") == 0) {
		cscf->resolver = NULL;
		return NGX_CONF_OK;
	}

#if defined(nginx_version) && nginx_version < 1001007
	ngx_memzero(&u, sizeof(ngx_url_t));

	u.host = value[1];
	u.port = 53;

	if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
						"%V: %s"), &u.host, u.err);
		return NGX_CONF_ERROR;
	}

	cscf->resolver = ngx_resolver_create(cf, &u.addr[0]);
	if (cscf->resolver == NULL) {
		return NGX_CONF_ERROR;
	}
#else

	cscf->resolver =  (cf, &value[1], cf->args->nelts - 1);
	if (cscf->resolver == NULL) {
		return NGX_CONF_ERROR;
	}
#endif

	return NGX_CONF_ERROR;
}

static char *
ngx_gateway_core_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_gateway_core_srv_conf_t			*cscf = conf;

	ngx_int_t 							rc;
	ngx_str_t 							*value;
	ngx_cidr_t							cidr;
	ngx_gateway_access_rule_t				*rule;

	if (NULL == cscf->rules) {
		cscf->rules = ngx_array_create(cf->pool, 4, sizeof(ngx_gateway_access_rule_t));

		if (NULL == cscf->rules) {
			return NGX_CONF_ERROR;
		}
	}

	rule = ngx_array_push(cscf->rules);
	if (NULL == rule) {
		return NGX_CONF_ERROR;
	}

	value = cf->args->elts;

	rule->deny = (value[0].data[0] == 'd') ? 1 : 0;

	if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0 ) {
		rule->mask = 0;
		rule->addr = 0;

		return NGX_CONF_OK;
	}

	rc = ngx_ptocidr(&value[1], &cidr);

	if (rc == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
		return NGX_CONF_ERROR;
	}

	if (cidr.family != AF_INET) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"allow\" supports IPV4 only");
		return NGX_CONF_ERROR;
	}

	if (NGX_DONE == rc) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
							"low address bits of %V are meaningless", &value[1]);
		return NGX_CONF_ERROR;
	}

	rule->mask = cidr.u.mask;
	rule->addr = cidr.u.addr;

	return NGX_CONF_OK;
}

static char *
ngx_gateway_log_set_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_gateway_core_srv_conf_t		*cscf = conf;
	ngx_gateway_log_srv_conf_t		*lscf = cscf->access_log;

	ssize_t							size;
	ngx_str_t						*value, name;
	ngx_gateway_log_t 				*log;
#if defined(nginx_version) && ((nginx_version) > 1003010 || (nginx_version) >= 1002007 && (nginx_version) < 1003000)
	ngx_gateway_log_buf_t			*buffer;
#endif

	value = cf->args->elts;

	if ( ngx_strcmp(value[1].data, "off") == 0) {
		lscf->off = 1;
		if (cf->args->nelts == 2) {
			return NGX_CONF_OK;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
		return NGX_CONF_ERROR;
	}

	if (lscf->logs == NULL) {
		lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_gateway_log_t));
		if (lscf->logs == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	log = ngx_array_push(lscf->logs);
	if (NULL == log) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(log, sizeof(ngx_gateway_log_t));

	log->file = ngx_conf_open_file(cf->cycle, &value[1]);
	if (NULL == log->file) {
		return NGX_CONF_ERROR;
	}

	if (cf->args->nelts == 3) {
		if (ngx_strncmp(value[2].data, "buffer=", 7) != 0) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
								"invalid parameter \"%V\"", &value[2]);
			return NGX_CONF_ERROR;
		}

		name.data = value[2].data + 7;
		name.len = value[2].len - 7;

		size = ngx_parse_size(&name);
		if (NGX_ERROR == size) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0
								"invalid parameter \"%V\"", &value[2]);
			return NGX_CONF_ERROR;
		}

#if defined(nginx_version) && ((nginx_version) >= 1003010 || (nginx_version) >= 1002007 && (nginx_version) < 100300)
		if (log->file->data) {

			buffer = log->file->data;

			if (buffer->last - buffer->pos != size) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
									"access_log \"%V\" already defined "
									"with different buffer size", &value[1]);
				return NGX_CONF_ERROR;
			}

			return NGX_CONF_OK;

		}

		buffer = ngx_pcalloc(cf->pool, sizeof(ngx_gateway_log_buf_t));
		if (NULL == buffer) {
			return NGX_CONF_ERROR;
		}

		buffer->start = ngx_palloc(cf->pool, size);
		if (NULL == buffer->start) {
			return NGX_CONF_ERROR;
		}

		buffer->pos = buffer->start;
		buffer->last = buffer->start + size;

		log->file->data = buffer;
#else
		if (log->file->buffer) {
			if (log->file->last - log->file->pos != size) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
									"access_log \"%V\" already defined "
									"with different buffer size", &value[2]);
				return NGX_CONF_ERROR;
			}

			return NGX_CONF_OK;
		}

		log->file->buffer = ngx_palloc(cf->pool, size);
		if (NULL == log->file->buffer) {
			return NGX_CONF_ERROR;
		}

		log->file->pos = log->file->buffer;
		log->file->last = log->file->buffer + size;
#endif
	}

	return NGX_CONF_OK;
}
