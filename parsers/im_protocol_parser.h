
#ifndef _IM_PROTOCOL_PARSER_H_
#define _IM_PROTOCOL_PARSER_H_

#include <ngx_config.h>
#include <ngx_core.h>

#define IM_PACKAGE_HEAD_LEN		12
#define IM_PACKAGE_TAIL_LEN		2

#define IM_PACKAGE_HEAD_FLAG	0x5B
#define IM_PACKAGE_TAIL_FLAG 	0x5D

ngx_uint_t check_data(u_char *data, ngx_uint_t len, void *data);

#endif /* _IM_PROTOCOL_PARSER_H_ */