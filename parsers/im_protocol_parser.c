
#include <im_protocol_parser.h>
#include <ngx_gateway_im_proxy_module.h>


static u_char check_crc(u_char *data, ngx_uint_t len);

ngx_int_t 
check_data(u_char *data, ngx_uint_t len, void *data)
{
	ngx_gateway_im_proxy_request_data_t 	*iprd = data;

	ngx_uint_t 				package_len;
	u_char					*p;

	/* data len nor enough */
	if (len < IM_PACKAGE_HEAD_LEN + IM_PACKAGE_TAIL_LEN) {
		return NGX_AGAIN;
	}

	p = data;

	/* check head flag */
	if (*p != IM_PACKAGE_HEAD_FLAG) {
		return NGX_ERROR;
	}

	/* calc package length */
	p = data + 8;
	package_len = *(unsigned short *)p;

	/* data length not enough */
	if (package_len < IM_PACKAGE_HEAD_LEN + IM_PACKAGE_TAIL_LEN) {
		return NGX_ERROR;
	}

	if (package_len > len) {
		return NGX_AGAIN;
	}

	/* check tail flag */
	p = data + package_len - IM_PACKAGE_TAIL_LEN + 1;
	if (*p != IM_PACKAGE_TAIL_FLAG) {
		return NGX_ERROR;
	}

	/* check crc value */
	--p;
	if (check_crc(data, package_len - 2) != *p) {
		return NGX_ERROR;
	}

	p = data + 1;
	iprd->version = (*p)&0x7F;
	++p;
	iprd->key = *p;
	++p;
	iprd->return_code = *p;
	++p;
	iprd->session_id = *(ngx_uint_t *)p;
	p += 6;
	iprd->seq = *(unsigned short *)p;

	iprd->len = package_len;

	return NGX_OK;
}

static u_char 
check_crc(u_char *data, ngx_uint_t len) 
{
	u_char    	crc;
	u_char		*p;
	ngx_int_t 	i;

	p = data;
	for (i = 0; i < len; ++i)
	{
		crc += *p;
		++p;
	}

	return crc;
}