/*
 * Copyright (c) 2013 Zhuyx
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_gateway.h>

 ngx_int_t 
 ngx_gateway_access_handler(ngx_gateway_session_t *s)
 {
 	ngx_uint_t						i;
 	struct sockaddr_in				*sin;
 	ngx_gateway_access_rule_t		*rule;
 	ngx_gateway_core_srv_conf_t 	*cscf;

 	cscf = ngx_gateway_get_module_srv_conf(s, ngx_gateway_core_module);

 	if (NULL == cscf->rules) {
 		return NGX_DECLINED;
 	}

 	if (s->connection->sockaddr->sa_family != AF_INET) {
 		return NGX_DECLINED;
 	}

 	sin = (struct sockaddr_in *)s->connection->sockaddr;

 	rule = cscf->rules->elts;
 	for (i = 0; i < cscf->rules->nelts; ++i) {

 		ngx_log_debug3(NGX_LOG_DEBUG_GATEWAY, s->connection->log, 0,
 						"access: %08XD %08XD %08XD",
 						sin->sin_addr.s_addr, rule[i].mask, rule[i].addr);

 		if ((sin->sin_addr.s_addr & rule[i].mask) == rule[i].addr) {
 			if (rule[i].deny) {
 				ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0, 
 					"access forbidden by rule");

 				return NGX_ERROR;
 			}

 			return NGX_OK;
 		}
 	}

 	return NGX_DECLINED;
 }