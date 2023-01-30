/*
 * Sanity Checks Module
 *
 * Copyright (C) 2006 iptelorg GbmH
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "sanity_mod.h"
#include "sanity.h"
#include "../../core/ut.h"
#include "../../core/trim.h"
#include "../../core/data_lump.h"
#include "../../core/data_lump_rpl.h"
#include "../../core/mem/mem.h"
#include "../../core/parser/parse_uri.h"
#include "../../core/parser/parse_expires.h"
#include "../../core/parser/parse_body.h"
#include "../../core/parser/parse_content.h"
#include "../../core/parser/digest/digest.h"
#include "../../core/parser/contact/parse_contact.h"
#include "../../core/parser/parse_to.h"
#include "../../core/parser/parse_from.h"

#define UNSUPPORTED_HEADER "Unsupported: "
#define UNSUPPORTED_HEADER_LEN (sizeof(UNSUPPORTED_HEADER) - 1)

extern int ksr_sanity_noreply;
extern int always_log_missed_content_length;

#define KSR_SANITY_REASON_SIZE 128
typedef struct ksr_sanity_info
{
	int code;
	char reason[KSR_SANITY_REASON_SIZE];
	unsigned int msgid;
	int msgpid;
} ksr_sanity_info_t;

static ksr_sanity_info_t _ksr_sanity_info = {0};

static char* strstri(char* string, int len, char* substring)
{
	str text = {string, len};
	str needle = {substring, strlen(substring)};
	return str_casesearch(&text, &needle);
}

static void _trim_end_of_str(str* string)
{
	char _c;
	while (string->len && ((_c=string->s[string->len-1])==0 || _c=='\r' || _c=='\n' || _c==' ' || _c=='\t' || _c=='>' )) {
		string->len--;
	}
}

/**
 *
 */
void ksr_sanity_info_init(void)
{
	memset(&_ksr_sanity_info, 0, sizeof(ksr_sanity_info_t));
}

/**
 *
 */
int ki_sanity_reply(sip_msg_t *msg)
{
	if(msg->first_line.type == SIP_REPLY) {
		return 1;
	}

	if(msg->REQ_METHOD == METHOD_ACK) {
		return 1;
	}

	if(ksr_sanity_noreply == 0) {
		return 1;
	}

	if(!(msg->msg_flags & FL_MSG_NOREPLY)) {
		if(_ksr_sanity_info.code == 0 || _ksr_sanity_info.reason[0] == '\0'
				|| msg->id != _ksr_sanity_info.msgid
				|| msg->pid != _ksr_sanity_info.msgpid) {
			LM_INFO("no sanity reply info set - sending 500\n");
			if(_sanity_slb.zreply(msg, 500, "Server Sanity Failure") < 0) {
				return -1;
			}
			return 1;
		}
		if(_sanity_slb.zreply(
				   msg, _ksr_sanity_info.code, _ksr_sanity_info.reason)
				< 0) {
			return -1;
		}
	}
	return 1;
}

/**
 * wrapper to SL send reply function
 * - check if it is the case for sending a reply before doing it
 */
int sanity_reply(sip_msg_t *msg, int code, char *reason)
{
	if(msg->first_line.type == SIP_REPLY) {
		return 1;
	}

	if(msg->REQ_METHOD == METHOD_ACK) {
		return 1;
	}

	if(ksr_sanity_noreply != 0) {
		_ksr_sanity_info.code = code;
		if(strlen(reason) >= KSR_SANITY_REASON_SIZE) {
			strncpy(_ksr_sanity_info.reason, reason,
					KSR_SANITY_REASON_SIZE - 1);
		} else {
			strcpy(_ksr_sanity_info.reason, reason);
		}
		_ksr_sanity_info.msgid = msg->id;
		_ksr_sanity_info.msgpid = msg->pid;
	} else {
		if(!(msg->msg_flags & FL_MSG_NOREPLY)) {
			if(_sanity_slb.zreply(msg, code, reason) < 0) {
				return -1;
			}
		}
	}

	return 0;
}

/* check if the given string is a valid unsigned int value */
int str2valid_uint(str *_number, unsigned int *_result)
{
	int i;
	int result = 0;
	int equal = 1;
	char mui[10] = "4294967296";

	*_result = 0;
	if(_number->len > 10) {
		LM_DBG("number is too long\n");
		return -1;
	}
	if(_number->len < 10) {
		equal = 0;
	}
	for(i = 0; i < _number->len; i++) {
		if(_number->s[i] < '0' || _number->s[i] > '9') {
			LM_DBG("number contains non-number char\n");
			return -1;
		}
		if(equal == 1) {
			if(_number->s[i] < mui[i]) {
				equal = 0;
			} else if(_number->s[i] > mui[i]) {
				LM_DBG("number exceeds uint\n");
				return -1;
			}
		}
		result *= 10;
		result += _number->s[i] - '0';
	}
	*_result = result;
	return 0;
}

static int str_list_size(str_list_t* _str_list) {
	int size = 0;

	while (_str_list) {
		++size;
		_str_list = _str_list->next;
	}

	return size;
}

static int str_list_total_length(str_list_t* _str_list) {
	int len = 0;

	while (_str_list) {
		len += _str_list->s.len;
		_str_list = _str_list->next;
	}
	return len;
}

/* parses the given comma separated string into a string list */
str_list_t *parse_str_list(str *_string)
{
	str input;
	str_list_t *parsed_list, *pl;
	char *comma;

	/* make a copy because we trim it */
	input.s = _string->s;
	input.len = _string->len;

	trim(&input);

	if(input.len == 0) {
		LM_DBG("list is empty\n");
		return NULL;
	}
	parsed_list = pkg_malloc(sizeof(str_list_t));
	if(parsed_list == NULL) {
		LM_ERR("OUT OF MEMORY for initial list element\n");
		return NULL;
	}
	memset(parsed_list, 0, sizeof(str_list_t));
	parsed_list->s.s = input.s;
	parsed_list->s.len = input.len;

	comma = q_memchr(input.s, ',', input.len);
	pl = parsed_list;
	while(comma != NULL) {
		pl->next = pkg_malloc(sizeof(str_list_t));
		if(pl->next == NULL) {
			LM_ERR("OUT OF MEMORY for further list element\n");
			return parsed_list;
		}
		memset(pl->next, 0, sizeof(str_list_t));
		pl->next->s.s = comma + 1;
		pl->next->s.len = pl->s.len - (pl->next->s.s - pl->s.s);
		pl->s.len = comma - pl->s.s;
		trim_trailing(&(pl->s));
		pl = pl->next;
		trim_leading(&(pl->s));
		comma = q_memchr(pl->s.s, ',', pl->s.len);
	}

	return parsed_list;
}

/* free the elements of the linked str list */
void free_str_list(str_list_t *_list)
{
	str_list_t *cur, *next;

	if(_list != NULL) {
		cur = _list;
		while(cur != NULL) {
			next = cur->next;
			pkg_free(cur);
			cur = next;
		}
	}
}

int parse_proxyrequire(struct hdr_field *_h)
{
	str_list_t *pr_l;

	if(_h->parsed) {
		return 0; /* Already parsed */
	}

	if((pr_l = parse_str_list(&(_h->body))) == NULL) {
		LM_ERR("Error while parsing\n");
		return -1;
	}

	_h->parsed = pr_l;
	return 0;
}

/* check the SIP version in the request URI */
int check_ruri_sip_version(sip_msg_t *msg)
{
	char *sep;
	str version;

	LM_DBG("check_ruri_sip_version entered\n");

	if(msg->first_line.u.request.version.len != 0) {
		sep = q_memchr(msg->first_line.u.request.version.s, '/',
				msg->first_line.u.request.version.len);
		if(sep == NULL) {
			LM_WARN("failed to find / in ruri version\n");
			return SANITY_CHECK_FAILED;
		}
		version.s = sep + 1;
		version.len = msg->first_line.u.request.version.len
					  - (version.s - msg->first_line.u.request.version.s);

		if(version.len != SIP_VERSION_TWO_POINT_ZERO_LENGTH
				|| (memcmp(version.s, SIP_VERSION_TWO_POINT_ZERO,
							SIP_VERSION_TWO_POINT_ZERO_LENGTH)
						!= 0)) {
			if(sanity_reply(msg, 505, "Version Not Supported (R-URI)") < 0) {
				LM_WARN("failed to send 505 via sl reply\n");
			}
			LM_DBG("check_ruri_sip_version failed\n");
			return SANITY_CHECK_FAILED;
		}
	}
	LM_DBG("check_ruri_sip_version passed\n");
	return SANITY_CHECK_PASSED;
}

/* check if the r-uri scheme */
int check_ruri_scheme(sip_msg_t *msg)
{

	LM_DBG("check_ruri_scheme entered\n");

	if(msg->parsed_uri_ok == 0 && parse_sip_msg_uri(msg) != 1) {
		/* unsupported schemes end up here already */
		LM_WARN("failed to parse request uri [%.*s]\n", GET_RURI(msg)->len,
				GET_RURI(msg)->s);
		if(sanity_reply(msg, 400, "Bad Request URI") < 0) {
			LM_WARN("failed to send 400 via sl reply (bad ruri)\n");
		}
		return SANITY_CHECK_FAILED;
	}
	if(msg->parsed_uri.type == ERROR_URI_T) {
		if(sanity_reply(msg, 416, "Unsupported URI Scheme in Request URI")
				< 0) {
			LM_WARN("failed to send 416 via sl reply\n");
		}
		LM_DBG("check_ruri_scheme failed\n");
		return SANITY_CHECK_FAILED;
	}
	LM_DBG("check_ruri_scheme passed\n");

	return SANITY_CHECK_PASSED;
}

#define SANITY_HDR_DUPCHECK(_hf, _hdr_flags, _hdr_type, _hdr_flag, _hdr_name) \
	do {                                                                      \
		if((_hf)->type == _hdr_type) {                                        \
			if(_hdr_flags & _hdr_flag) {                                      \
				LM_DBG("duplicated %s header\n", _hdr_name);                  \
				return SANITY_CHECK_FAILED;                                   \
			}                                                                 \
			_hdr_flags |= _hdr_flag;                                          \
		}                                                                     \
	} while(0)

/* check for the presence of the minimal required headers */
int check_required_headers(sip_msg_t *msg)
{
	hdr_field_t *hf;
	hdr_flags_t hdr_flags = 0;

	LM_DBG("check_required_headers entered\n");

	if(!check_transaction_quadruple(msg)) {
		msg->msg_flags |= FL_MSG_NOREPLY;
		LM_DBG("check_required_headers failed\n");
		return SANITY_CHECK_FAILED;
	}
	if(parse_headers(msg, HDR_EOH_F, 0) != 0) {
		LM_ERR("failed to parse headers\n");
		if(sanity_reply(msg, 400, "Bad Headers") < 0) {
			LM_WARN("failed to send 400 reply\n");
		}
		return SANITY_CHECK_FAILED;
	}
	for(hf = msg->headers; hf; hf = hf->next) {
		SANITY_HDR_DUPCHECK(hf, hdr_flags, HDR_FROM_T, HDR_FROM_F, "From");
		SANITY_HDR_DUPCHECK(hf, hdr_flags, HDR_TO_T, HDR_TO_F, "To");
		SANITY_HDR_DUPCHECK(
				hf, hdr_flags, HDR_CALLID_T, HDR_CALLID_F, "Call-Id");
		SANITY_HDR_DUPCHECK(hf, hdr_flags, HDR_CSEQ_T, HDR_CSEQ_F, "CSeq");
	}

	/* TODO: check for other required headers according to request type */
	LM_DBG("check_required_headers passed\n");

	return SANITY_CHECK_PASSED;
}

/* check if the SIP version in the Via header is 2.0 */
int check_via1_header(sip_msg_t *msg)
{
	LM_DBG("check via1 header\n");
	if(parse_headers(msg, HDR_VIA1_F, 0) != 0) {
		LM_WARN("failed to parse the Via1 header\n");
		msg->msg_flags |= FL_MSG_NOREPLY;
		return SANITY_CHECK_FAILED;
	}

	if(msg->via1->host.s == NULL || msg->via1->host.len < 0) {
		LM_WARN("failed to parse the Via1 host\n");
		msg->msg_flags |= FL_MSG_NOREPLY;
		return SANITY_CHECK_FAILED;
	}

	return SANITY_CHECK_PASSED;
}

/* check if the SIP version in the Via header is 2.0 */
int check_via_sip_version(sip_msg_t *msg)
{

	LM_DBG("this is a useless check"
		   " for now; check the source code comments for details\n");
	return SANITY_CHECK_PASSED;

	/* FIXME the Via parser fails already on non-2.0 versions
	 * thus this check makes no sense yet
	DBG("check_via_sip_version entered\n");

	// FIXME via parser fails on non 2.0 number
	if (parse_headers(msg, HDR_VIA1_F, 0) != 0) {
	LOG(L_WARN, "sanity_check(): check_via_sip_version():"
	" failed to parse the first Via header\n");
	return SANITY_CHECK_FAILED;
	}

	if (msg->via1->version.len != 3 ||
	memcmp(msg->via1->version.s, SIP_VERSION_TWO_POINT_ZERO,
	SIP_VERSION_TWO_POINT_ZERO_LENGTH ) != 0) {
	if (sanity_reply(msg, 505, "Version Not Supported (Via)") < 0) {
	LOG(L_WARN, "sanity_check(): check_via_sip_version():"
	" failed to send 505 via sl reply\n");
	}
	DBG("check_via_sip_version failed\n");
	return SANITY_CHECK_FAILED;
	}
DBG("check_via_sip_version passed\n");

return SANITY_CHECK_PASSED;
*/
}

/* compare the protocol string in the Via header with the transport */
int check_via_protocol(sip_msg_t *msg)
{

	LM_DBG("this is a useless check"
		   " for now; check the source code comment for details\n");
	return SANITY_CHECK_PASSED;

	/* FIXME as the Via parser fails already on unknown transports
	 * this function makes no sense yet
	DBG("check_via_protocol entered\n");

	// FIXME via parser fails on unknown transport
	if (parse_headers(msg, HDR_VIA1_F, 0) != 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to parse the first Via header\n");
	return SANITY_CHECK_FAILED;
	}
	if (msg->via1->transport.len != 3 &&
	msg->via1->transport.len != 4) {
	if (sanity_reply(msg, 400, "Unsupported Transport in Topmost Via")
	< 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to send 400 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
	}
	switch (msg->rcv.proto) {
	case PROTO_UDP:
	if (memcmp(msg->via1->transport.s, "UDP", 3) != 0) {
	if (sanity_reply(msg, 400,
	"Transport Missmatch in Topmost Via") < 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
	}
	break;
	case PROTO_TCP:
	if (memcmp(msg->via1->transport.s, "TCP", 3) != 0) {
	if (sanity_reply(msg, 400,
	"Transport Missmatch in Topmost Via") < 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
	}
	break;
	case PROTO_TLS:
	if (memcmp(msg->via1->transport.s, "TLS", 3) != 0) {
	if (sanity_reply(msg, 400,
	"Transport Missmatch in Topmost Via") < 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
	}
	break;
	case PROTO_SCTP:
	if (memcmp(msg->via1->transport.s, "SCTP", 4) != 0) {
	if (sanity_reply(msg, 400,
	"Transport Missmatch in Topmost Via") < 0) {
	LOG(L_WARN, "sanity_check(): check_via_protocol():"
	" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
}
break;
case PROTO_WS:
if (memcmp(msg->via1->transport.s, "WS", 2) != 0) {
	if (sanity_reply(msg, 400,
				"Transport Missmatch in Topmost Via") < 0) {
		LOG(L_WARN, "sanity_check(): check_via_protocol():"
				" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
}
break;
case PROTO_WSS:
if (memcmp(msg->via1->transport.s, "WSS", 3) != 0) {
	if (sanity_reply(msg, 400,
				"Transport Missmatch in Topmost Via") < 0) {
		LOG(L_WARN, "sanity_check(): check_via_protocol():"
				" failed to send 505 via sl reply\n");
	}
	DBG("check_via_protocol failed\n");
	return SANITY_CHECK_FAILED;
}
break;
default:
LOG(L_WARN, "sanity_check(): check_via_protocol():"
		" unknown protocol in received structure\n");
return SANITY_CHECK_FAILED;
}
DBG("check_via_protocol passed\n");

return SANITY_CHECK_PASSED;
*/
}

/* compare the method in the CSeq header with the request line value */
int check_cseq_method(sip_msg_t *msg)
{

	LM_DBG("check_cseq_method entered\n");

	if(parse_headers(msg, HDR_CSEQ_F, 0) != 0) {
		msg->msg_flags |= FL_MSG_NOREPLY;
		LM_WARN("failed to parse the CSeq header\n");
		return SANITY_CHECK_FAILED;
	}
	if(msg->cseq != NULL && msg->cseq->parsed != NULL) {
		if(((struct cseq_body *)msg->cseq->parsed)->method.len == 0) {
			if(sanity_reply(msg, 400, "Missing method in CSeq header") < 0) {
				LM_WARN("failed to send 400 via sl reply\n");
			}
			LM_DBG("check_cseq_method failed (missing method)\n");
			return SANITY_CHECK_FAILED;
		}

		if(((struct cseq_body *)msg->cseq->parsed)->method.len
						!= msg->first_line.u.request.method.len
				|| memcmp(((struct cseq_body *)msg->cseq->parsed)->method.s,
						   msg->first_line.u.request.method.s,
						   ((struct cseq_body *)msg->cseq->parsed)->method.len)
						   != 0) {
			if(sanity_reply(
					   msg, 400, "CSeq method does not match request method")
					< 0) {
				LM_WARN("failed to send 400 via sl reply 2\n");
			}
			LM_DBG("check_cseq_method failed (non-equal method)\n");
			return SANITY_CHECK_FAILED;
		}
	} else {
		LM_WARN("missing CSeq header\n");
		return SANITY_CHECK_FAILED;
	}
	DBG("check_cseq_method passed\n");

	return SANITY_CHECK_PASSED;
}

/* check the number within the CSeq header */
int check_cseq_value(sip_msg_t *msg)
{
	unsigned int cseq;

	LM_DBG("check_cseq_value entered\n");

	if(parse_headers(msg, HDR_CSEQ_F, 0) != 0) {
		LM_WARN("failed to parse the CSeq header\n");
		msg->msg_flags |= FL_MSG_NOREPLY;
		return SANITY_CHECK_FAILED;
	}
	if(msg->cseq != NULL && msg->cseq->parsed != NULL) {
		if(((struct cseq_body *)msg->cseq->parsed)->number.len == 0) {
			if(sanity_reply(msg, 400, "Missing number in CSeq header") < 0) {
				LM_WARN("failed to send 400 via sl reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
		if(str2valid_uint(
				   &((struct cseq_body *)msg->cseq->parsed)->number, &cseq)
				!= 0) {
			if(sanity_reply(msg, 400, "CSeq number is illegal") < 0) {
				LM_WARN("failed to send 400 via sl reply 2\n");
			}
			LM_DBG("check_cseq_value failed\n");
			return SANITY_CHECK_FAILED;
		}
	} else {
		LM_WARN("missing CSeq header\n");
		msg->msg_flags |= FL_MSG_NOREPLY;
		return SANITY_CHECK_FAILED;
	}
	LM_DBG("check_cseq_value passed\n");

	return SANITY_CHECK_PASSED;
}

/* compare the Content-Length value with the actual body length */
int check_cl(sip_msg_t *msg)
{
	char *body;

	LM_DBG("check_cl entered\n");

	if(parse_headers(msg, HDR_CONTENTLENGTH_F, 0) != 0) {
		LM_WARN("failed to parse content-length header\n");
		if(sanity_reply(msg, 400, "Content-Length Failure") < 0) {
			LM_WARN("failed to send 400 via sl reply\n");
		}
		return SANITY_CHECK_FAILED;
	}
	if(msg->content_length != NULL) {
		//dump_hdr_field(msg->content_length);
		if((body = get_body(msg)) == NULL) {
			LM_DBG("check_cl(): no body\n");
			if(sanity_reply(msg, 400, "Content-Length Body Failure") < 0) {
				LM_WARN("failed to send 400 via sl reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
		if((msg->len - (body - msg->buf)) != get_content_length(msg)) {
			if(sanity_reply(msg, 400, "Content-Length mis-match") < 0) {
				LM_WARN("failed to send 400 via sl reply\n");
			}
			LM_DBG("check_cl failed\n");
			return SANITY_CHECK_FAILED;
		}
		LM_DBG("check_cl passed\n");
	} else {
		if (SANITY_LOG_MISSED_CONTENT_LEN == always_log_missed_content_length || msg->rcv.proto != PROTO_UDP) {
			LM_WARN("content length header missing in request\n");
		}
	}

	return SANITY_CHECK_PASSED;
}

/* check the number within the Expires header */
int check_expires_value(sip_msg_t *msg)
{
	unsigned int expires;

	LM_DBG("check_expires_value entered\n");

	if(parse_headers(msg, HDR_EXPIRES_F, 0) < 0) {
		if(sanity_reply(msg, 400, "Bad Expires Header") < 0) {
			LM_WARN("failed to send 400 reply\n");
		}
		LM_WARN("failed to parse expires header\n");
		return SANITY_CHECK_FAILED;
	}
	if(msg->expires != NULL) {
		//dump_hdr_field(msg->expires);
		if(msg->expires->parsed == NULL && parse_expires(msg->expires) < 0) {
			LM_WARN("parse_expires failed\n");
			if(sanity_reply(msg, 400, "Bad Expires Header") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
		if(((struct exp_body *)msg->expires->parsed)->text.len == 0) {
			if(sanity_reply(msg, 400, "Missing number in Expires header") < 0) {
				LM_WARN("failed to send 400 via sl reply\n");
			}
			LM_DBG("check_expires_value failed\n");
			return SANITY_CHECK_FAILED;
		}
		if(str2valid_uint(
				   &((struct exp_body *)msg->expires->parsed)->text, &expires)
				!= 0) {
			if(sanity_reply(msg, 400, "Expires value is illegal") < 0) {
				LM_WARN("failed to send 400 via sl reply 2\n");
			}
			LM_DBG("check_expires_value failed\n");
			return SANITY_CHECK_FAILED;
		}
		LM_DBG("check_expires_value passed\n");
	} else {
		LM_DBG("no expires header found\n");
	}

	return SANITY_CHECK_PASSED;
}

/* check the content of the Proxy-Require header */
int check_proxy_require(sip_msg_t *msg)
{
	str_list_t *r_pr, *l_pr;
	char *u;
	int u_len;

	LM_DBG("checking proxy require\n");

	if(parse_headers(msg, HDR_PROXYREQUIRE_F, 0) != 0) {
		LM_WARN("failed to parse proxy require header\n");
		if(sanity_reply(msg, 400, "Bad Proxy Require Header") < 0) {
			LM_WARN("failed to send 400 reply\n");
		}
		return SANITY_CHECK_FAILED;
	}
	if(msg->proxy_require != NULL) {
		//dump_hdr_field(msg->proxy_require);
		if(msg->proxy_require->parsed == NULL
				&& parse_proxyrequire(msg->proxy_require) < 0) {
			LM_WARN("parse proxy require failed\n");
			if(sanity_reply(msg, 400, "Bad Proxy Require Header") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
		r_pr = msg->proxy_require->parsed;
		while(r_pr != NULL) {
			l_pr = proxyrequire_list;
			while(l_pr != NULL) {
				LM_DBG("comparing r='%.*s' l='%.*s'\n", r_pr->s.len, r_pr->s.s,
						l_pr->s.len, l_pr->s.s);
				if(l_pr->s.len == r_pr->s.len &&
						/* FIXME tokens are case in-sensitive */
						memcmp(l_pr->s.s, r_pr->s.s, l_pr->s.len) == 0) {
					break;
				}
				l_pr = l_pr->next;
			}
			if(l_pr == NULL) {
				LM_DBG("request contains unsupported extension: %.*s\n",
						r_pr->s.len, r_pr->s.s);
				u_len = UNSUPPORTED_HEADER_LEN + 2 + r_pr->s.len;
				u = pkg_malloc(u_len);
				if(u == NULL) {
					LM_ERR("failed to allocate memory for"
						   " Unsupported header\n");
				} else {
					memcpy(u, UNSUPPORTED_HEADER, UNSUPPORTED_HEADER_LEN);
					memcpy(u + UNSUPPORTED_HEADER_LEN, r_pr->s.s, r_pr->s.len);
					memcpy(u + UNSUPPORTED_HEADER_LEN + r_pr->s.len, CRLF,
							CRLF_LEN);
					add_lump_rpl(msg, u, u_len, LUMP_RPL_HDR);
				}

				if(sanity_reply(msg, 420, "Bad Proxy Require Extension") < 0) {
					LM_WARN("failed to send 420 via sl reply\n");
				}
				LM_DBG("checking proxy require failed\n");
				if(u)
					pkg_free(u);
				if(msg->proxy_require->parsed) {
					free_str_list(msg->proxy_require->parsed);
					msg->proxy_require->parsed = NULL;
				}
				return SANITY_CHECK_FAILED;
			} else {
				r_pr = r_pr->next;
			}
		}
		LM_DBG("checking proxy require passed\n");
		if(msg->proxy_require->parsed) {
			/* TODO we have to free it here, because it is not automatically
			 * freed when the message freed. Lets hope nobody needs to access
			 * this header again later on */
			free_str_list(msg->proxy_require->parsed);
			msg->proxy_require->parsed = NULL;
		}
	} else {
		LM_DBG("no proxy-require header found\n");
	}

	return SANITY_CHECK_PASSED;
}

/* check if the typical URI's are parseable */
int check_parse_uris(sip_msg_t *msg, int checks)
{

	struct sip_uri uri;

	LM_DBG("check_parse_uris entered\n");

	/* check R-URI */
	if(SANITY_URI_CHECK_RURI & checks) {
		LM_DBG("parsing ruri\n");
		if(msg->parsed_uri_ok == 0 && parse_sip_msg_uri(msg) != 1) {
			LM_WARN("failed to parse request uri\n");
			if(sanity_reply(msg, 400, "Bad Request URI") < 0) {
				LM_WARN("failed to send 400 via sl reply (bad ruri)\n");
			}
			return SANITY_CHECK_FAILED;
		}
		/* FIXME: would it make sense to check here for "mandatory"
		 * or "requested" parts of the URI? */
	}
	/* check From URI */
	if(SANITY_URI_CHECK_FROM & checks) {
		LM_DBG("looking up From header\n");
		if(parse_from_uri(msg) == NULL) {
			LM_WARN("invalid From header or uri\n");
			if(!msg->from || !msg->from->body.s) {
				msg->msg_flags |= FL_MSG_NOREPLY;
			} else {
				if(sanity_reply(msg, 400, "Invalid From Header") < 0) {
					LM_WARN("failed to send 400 via sl reply (missing From)\n");
				}
			}
			return SANITY_CHECK_FAILED;
		}
	}
	/* check To URI */
	if(SANITY_URI_CHECK_TO & checks) {
		LM_DBG("looking up To header\n");
		if(parse_to_uri(msg) == NULL) {
			LM_WARN("invalid To header or uri\n");
			if(!msg->to || !msg->to->body.s) {
				msg->msg_flags |= FL_MSG_NOREPLY;
			} else {
				if(sanity_reply(msg, 400, "Ivalid To Header") < 0) {
					LM_WARN("failed to send 400 via sl reply (missing To)\n");
				}
			}
			return SANITY_CHECK_FAILED;
		}
	}
	/* check Contact URI */
	if(SANITY_URI_CHECK_CONTACT & checks) {
		LM_DBG("looking up Contact header\n");
		if(parse_contact_headers(msg) < 0) {
			LM_WARN("failed to parse Contact headers\n");
			if(sanity_reply(msg, 400, "Bad Contact Header") < 0) {
				LM_WARN("failed to send 400 via send_reply (bad Contact)\n");
			}
			return SANITY_CHECK_FAILED;
		}
		if(msg->contact) {
			LM_DBG("parsing Contact header\n");
			if(parse_contact(msg->contact) < 0) {
				LM_WARN("failed to parse Contact header\n");
				if(sanity_reply(msg, 400, "Bad Contact Header") < 0) {
					LM_WARN("failed to send 400 via send_reply (bad "
							"Contact)\n");
				}
				return SANITY_CHECK_FAILED;
			}
			if(!((struct contact_body *)msg->contact->parsed)->star
					&& parse_uri(((struct contact_body *)msg->contact->parsed)
										 ->contacts->uri.s,
							   ((struct contact_body *)msg->contact->parsed)
									   ->contacts->uri.len,
							   &uri)
							   != 0) {
				LM_WARN("failed to parse Contact uri\n");
				if(sanity_reply(msg, 400, "Bad Contact URI") < 0) {
					LM_WARN("failed to send 400 via send_reply"
							" (bad Contact uri)\n");
				}
				return SANITY_CHECK_FAILED;
			}
		}
	}

	LM_DBG("check_parse_uris passed\n");
	return SANITY_CHECK_PASSED;
}

/* Make sure that username attribute in all digest credentials
 * instances has a meaningful value
 */
static int check_digest_only(sip_msg_t *msg, int checks)
{
	struct hdr_field *ptr;
	dig_cred_t *cred;
	int ret;
	int hf_type;

	if(parse_headers(msg, HDR_EOH_F, 0) != 0) {
		LM_ERR("failed to parse proxy require header\n");
		if(sanity_reply(msg, 400, "Bad Headers") < 0) {
			LM_WARN("failed to send 400 reply\n");
		}
		return SANITY_CHECK_FAILED;
	}

	if(!msg->authorization && !msg->proxy_auth) {
		LM_DBG("Nothing to check\n");
		return SANITY_CHECK_PASSED;
	}

	if(msg->authorization) {
		hf_type = HDR_AUTHORIZATION_T;
		ptr = msg->authorization;
	} else {
		hf_type = HDR_PROXYAUTH_T;
		ptr = msg->proxy_auth;
	}
	while(ptr) {
		if((ret = parse_credentials(ptr)) != 0) {
			if(ret == 1) {
				LM_DBG("Not a \"digest\" authorization\n");
				return SANITY_CHECK_NOT_APPLICABLE;
			} else {
				LM_DBG("Cannot parse credentials: %d\n", ret);
				if(sanity_reply(msg, 400, "Bad Auth Header") < 0) {
					LM_WARN("failed to send 400 reply\n");
				}
				return SANITY_CHECK_FAILED;
			}
		}

		cred = &((auth_body_t *)ptr->parsed)->digest;

		if(check_dig_cred(cred) != E_DIG_OK) {
			LM_DBG("Digest credentials malformed\n");
			if(sanity_reply(msg, 400, "Bad Auth Credentials") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}

		if(cred->username.whole.len == 0) {
			LM_DBG("Empty username\n");
			if(sanity_reply(msg, 400, "Auth Empty User") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}

		if(cred->nonce.len == 0) {
			LM_DBG("Empty nonce attribute\n");
			if(sanity_reply(msg, 400, "Auth Empty Nonce") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}

		if(cred->response.len == 0) {
			LM_DBG("Empty response attribute\n");
			if(sanity_reply(msg, 400, "Auth Empty Response") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}

		do {
			ptr = ptr->next;
		} while(ptr && ptr->type != hf_type);

		if(!ptr && hf_type == HDR_AUTHORIZATION_T) {
			hf_type = HDR_PROXYAUTH_T;
			ptr = msg->proxy_auth;
		}
	}

	return SANITY_CHECK_PASSED;
}

int check_authorization(sip_msg_t *msg, int checks)
{
	int ret;

	ret = check_digest_only(msg, checks);
	if(ret == SANITY_CHECK_PASSED || ret == SANITY_CHECK_NOT_APPLICABLE) {
		return SANITY_CHECK_PASSED;
	} else {
		return SANITY_CHECK_FAILED;
	}
}

int check_digest(sip_msg_t *msg, int checks)
{
	if(check_digest_only(msg, checks) == SANITY_CHECK_PASSED) {
		return SANITY_CHECK_PASSED;
	} else {
		return SANITY_CHECK_FAILED;
	}
}

/* check for the presence of duplicate tag parameters in To/From headers */
int check_duptags(sip_msg_t *msg)
{
	to_body_t *tb;
	to_param_t *tp;
	int n;

	if(parse_from_header(msg) < 0 || parse_to_header(msg) < 0) {
		LM_DBG("failed while parsing From or To headers\n");
		msg->msg_flags |= FL_MSG_NOREPLY;
		return SANITY_CHECK_FAILED;
	}
	tb = get_from(msg);
	if(tb->tag_value.s != NULL) {
		n = 0;
		for(tp = tb->param_lst; tp; tp = tp->next) {
			if(tp->type == TAG_PARAM)
				n++;
		}
		if(n > 1) {
			LM_DBG("failed for From header\n");
			if(sanity_reply(msg, 400, "Many From Tag Params") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
	}
	tb = get_to(msg);
	if(tb->tag_value.s != NULL) {
		n = 0;
		for(tp = tb->param_lst; tp; tp = tp->next) {
			if(tp->type == TAG_PARAM)
				n++;
		}
		if(n > 1) {
			LM_DBG("failed for To header\n");
			if(sanity_reply(msg, 400, "Many To Tag Params") < 0) {
				LM_WARN("failed to send 400 reply\n");
			}
			return SANITY_CHECK_FAILED;
		}
	}

	return SANITY_CHECK_PASSED;
}

static int find_cid_in_body(sip_msg_t* msg, str* hdr) {
	int found = 1;
	int content_length;
	str cid;
	char *content_body = NULL;
	char *cid_buf;
	char *quoted_cid_buf;
	int l = strlen("cid:");
	char *pos = strstri(hdr->s, hdr->len, "cid:");
	char *quote_pos = strstri(hdr->s, hdr->len, ">");

	// get Content-Id:
	cid.len = hdr->len - l - (pos - hdr->s) - (quote_pos ? hdr->len - (quote_pos - hdr->s) : 0);
	cid.s = pos + l;
	_trim_end_of_str(&cid);

	cid_buf = pkg_malloc(cid.len + 1);
	memcpy(cid_buf, cid.s, cid.len);
	cid_buf[cid.len] = 0;

	quoted_cid_buf = pkg_malloc(cid.len + 3);
	quoted_cid_buf[0] = '<';
	memcpy(quoted_cid_buf + 1, cid.s, cid.len);
	quoted_cid_buf[cid.len + 1] = '>';
	quoted_cid_buf[cid.len + 2] = 0;

	// get body part - filter => Content-Id
	content_body = get_body_part_by_filter(msg, 0, 0, quoted_cid_buf, NULL, &content_length);
	if (!content_body) {
		LM_WARN("Content-ID '%s' is not found in 'multipart/mixed' payload, searching for '%s'\n", quoted_cid_buf, cid_buf);
		content_body = get_body_part_by_filter(msg, 0, 0, cid_buf, NULL, &content_length);
		if (!content_body) {
			LM_WARN("Content-ID '%s' is not found in 'multipart/mixed' payload\n", cid_buf);
			found = 0;
		}
	}
	pkg_free(quoted_cid_buf);
	pkg_free(cid_buf);

	return found;
}

static int parse_cid_and_find_in_body(sip_msg_t* msg, struct hdr_field *hf) {
	str_list_t* cids = parse_str_list(&hf->body);
	if (cids == NULL) {
		LM_WARN("parse '%.*s' header failed\n", hf->name.len, hf->name.s);
		return SANITY_CHECK_FAILED;
	}

	str_list_t* cid_list = cids;
	while (cid_list) {
		LM_DBG("cid: '%.*s'\n", cid_list->s.len, cid_list->s.s);
		if (!find_cid_in_body(msg, &cid_list->s)) {
			free_str_list(cids);
			return SANITY_CHECK_FAILED;
		}
		cid_list = cid_list->next;
	}
	free_str_list(cids);

	return SANITY_CHECK_PASSED;
}

int check_cid(sip_msg_t* msg) {
	struct hdr_field *hf;

	if(parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse SIP headers\n");
		return SANITY_CHECK_FAILED;
	}

	if(!msg->content_type) {
		LM_WARN("The header Content-TYPE is absent!\n");
		return SANITY_CHECK_FAILED;
	}

	for(hf = msg->headers; hf; hf = hf->next) {
		if((hf->type == HDR_OTHER_T) && (hf->name.len == SANITY_GEOLOC_HEADER_SIZE - 2)) {
			/* possible hit */
			if(strncasecmp(hf->name.s, SANITY_GEOLOC_HEADER, SANITY_GEOLOC_HEADER_SIZE) == 0) {

				LM_DBG("found geolocation header [%.*s]\n", hf->body.len, hf->body.s);

				if (strstri(hf->body.s, hf->body.len, "cid:")) {
					str str_type;

					trim_len(str_type.len, str_type.s, msg->content_type->body);
					if(str_type.len >= 15 && !strncasecmp(str_type.s, "multipart/mixed", 15)) {
						if (!parse_cid_and_find_in_body(msg, hf)) {
							return SANITY_CHECK_FAILED;
						}
						LM_DBG("CID is OK\n");
					} else {
						LM_DBG("The header Content-TYPE is not 'multipart/mixed'\n");
						return SANITY_CHECK_FAILED;
					}
				}
			}
		} else if(hf->type == HDR_CALLINFO_T) {
			LM_DBG("Call-Info header [%.*s]\n", hf->body.len, hf->body.s);
			if (strstri(hf->body.s, hf->body.len, "cid:")) {
				str str_type;

				trim_len(str_type.len, str_type.s, msg->content_type->body);
				if(str_type.len >= 15 && !strncasecmp(str_type.s, "multipart/mixed", 15)) {
					if (!parse_cid_and_find_in_body(msg, hf)) {
						return SANITY_CHECK_FAILED;
					}
					LM_DBG("CID is OK\n");
				} else {
					LM_DBG("The header Content-TYPE is not 'multipart/mixed'\n");
					return SANITY_CHECK_FAILED;
				}
			}
		}
	}

	return SANITY_CHECK_PASSED;
}

static int remove_header(struct sip_msg* msg, struct hdr_field* hf) {
	if (!msg || !hf) {
		return -1;
	}

	LM_INFO("Removing header with broken 'cid:' identifier: '%.*s: %.*s'\n", hf->name.len, hf->name.s, hf->body.len, hf->body.s);
	struct lump* anchor = del_lump(msg, hf->name.s-msg->buf, hf->len, 0);
	if (anchor == 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	return 0;
}

static int insert_header(struct sip_msg *msg, const char *header, hdr_types_t type)
{
	struct lump* anchor = NULL;
	char *s = NULL;
	int len = 0;

	LM_DBG("Appending header: %s", header);

	if ((anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0, 0)) == 0) {
		LM_ERR("failed to get anchor to append header\n");
		return 1;
	}
	len = strlen(header);
	if ((s = (char *)pkg_malloc(len+1)) == 0) {
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return 1;
	}
	memcpy(s, header, len);
	s[len] = '\0';
	if (insert_new_lump_before(anchor, s, len, type) == 0) {
		LM_ERR("failed to insert lump\n");
		pkg_free(s);
		return 1;
	}
	LM_DBG("Done appending header successfully.\n");
	return 0;
}

static int find_remove_cid_header(struct sip_msg* msg, struct hdr_field* hf, int is_multipart_mixed) {
	if (!msg || !hf) {
		return -1;
	}

	if (strstri(hf->body.s, hf->body.len, "cid:")) {
		if (is_multipart_mixed) {
			str_list_t* cids = parse_str_list(&hf->body);
			if (cids == NULL) {
				LM_WARN("parse '%.*s' header failed\n", hf->name.len, hf->name.s);
				return SANITY_CHECK_FAILED;
			}

			str_list_t* cid_list = cids;
			str_list_t* res_cid_list = NULL;
			while (cid_list) {
				if (find_cid_in_body(msg, &cid_list->s)) {
					res_cid_list = str_list_block_add(&res_cid_list, cid_list->s.s, cid_list->s.len);
				}
				cid_list = cid_list->next;
			}

			cid_list = cids;
			if (str_list_size(res_cid_list) == 0) {
				LM_INFO("CID is broken, remove header '%.*s'\n", hf->name.len, hf->name.s);
				remove_header(msg, hf);
			} else if (str_list_size(res_cid_list) != str_list_size(cid_list)) {
				int hdr_len = str_list_total_length(res_cid_list) + str_list_size(res_cid_list) + strlen(hf->type == HDR_CALLINFO_T ? "Call-Info: " : SANITY_GEOLOC_HEADER) + strlen("\r\n");
				char* new_hdr = pkg_mallocxz(hdr_len);

				LM_INFO("Found broken CID in the header containing multiple CID values; '%.*s' will be modified\n", hf->name.len, hf->name.s);
				strcpy(new_hdr, hf->type == HDR_CALLINFO_T ? "Call-Info: " : SANITY_GEOLOC_HEADER);
				str_list_t* res_cid_list_1 = res_cid_list;
				while(res_cid_list_1) {
					strncpy(new_hdr + strlen(new_hdr), res_cid_list_1->s.s, res_cid_list_1->s.len);
					strcpy(new_hdr + strlen(new_hdr), ",");

					res_cid_list_1 = res_cid_list_1->next;
				}
				new_hdr[strlen(new_hdr) - 1] = 0;
				strcpy(new_hdr + strlen(new_hdr), "\r\n");

				//NOTE: append new 'Call-Info'/'Geolocation' header and then remove the old one.
				insert_header(msg, new_hdr, hf->type);
				remove_header(msg, hf);
			}

			free_str_list(res_cid_list);
			free_str_list(cids);

		} else {
			remove_header(msg, hf);
		}
	}

	return 0;
}

int cleanup_broken_cid(sip_msg_t* msg) {
	if(!msg->content_type) {
		LM_WARN("The header Content-TYPE is absent!\n");
		return 0;
	}

	str str_type;
	trim_len(str_type.len, str_type.s, msg->content_type->body);

	int is_multipart_mixed = (str_type.len >= 15 && !strncasecmp(str_type.s, "multipart/mixed", 15)) ? 1 : 0;
	struct hdr_field *hf;

	for(hf = msg->headers; hf; hf = hf->next) {
		if((hf->type == HDR_OTHER_T) && (hf->name.len == SANITY_GEOLOC_HEADER_SIZE - 2)) {
			/* possible hit */
			if(strncasecmp(hf->name.s, SANITY_GEOLOC_HEADER, SANITY_GEOLOC_HEADER_SIZE) == 0) {
				LM_DBG("found geolocation header [%.*s]\n", hf->body.len, hf->body.s);
				find_remove_cid_header(msg, hf, is_multipart_mixed);
			}
		} else if(hf->type == HDR_CALLINFO_T) {
			LM_DBG("Call-Info header [%.*s]\n", hf->body.len, hf->body.s);
			find_remove_cid_header(msg, hf, is_multipart_mixed);
		}
	}

	return 1;
}
