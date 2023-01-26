/*! \file
 * \ingroup ping_endpoint
 * \brief ping_endpoint :: ping_endpoint
 */

#ifndef _PING_ENDPOINT_H_
#define _PING_ENDPOINT_H_

#include "../../core/parser/msg_parser.h"

int pp_set_endpoint_list_updated(sip_msg_t* _msg, char* updated);

typedef struct endpoint_addr_list {
    int endpoint_info_id;
    str endpoint_id_str;
    str target_uri;
    str request_uri;
    str ip_addr;
    int port;
    int proto;
    int status;
    int status_by_ping;
    int reply_code;
    struct endpoint_addr_list* next;
} endpoint_addr_list_t;

typedef struct endpoint_info_list {
    int endpoint_info_id;
    endpoint_addr_list_t* addr_list;
    struct endpoint_info_list* next;
} endpoint_info_list_t;

endpoint_addr_list_t* endpoint_addr_list_block_add(endpoint_addr_list_t **head,
                                           int endpoint_info_id,
                                           char *_endpoint_id_str, int endpoint_id_str_len,
                                           char *_target_uri_str, int _target_uri_len,
                                           char *_request_uri_str, int _request_uri_len,
                                           char *_ip_addr_str, int _ip_addr_len,
                                           int port, char proto, int status);

endpoint_info_list_t* endpoint_info_list_block_add(endpoint_info_list_t **head, int endpoint_info_id);

void free_endpoint_addr_list(endpoint_addr_list_t *obj);

void free_endpoint_info_list(endpoint_info_list_t** ei_list);

int get_endpoint_status(endpoint_info_list_t* ei_list, int* changed);

char* create_reply_json(endpoint_info_list_t* ei_list);

unsigned int get_endpoint_info_count(endpoint_info_list_t* ei_list);

#endif
