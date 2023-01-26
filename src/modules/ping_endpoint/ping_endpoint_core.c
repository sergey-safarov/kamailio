#include <json.h>
#include "ping_endpoint.h"

endpoint_addr_list_t* endpoint_addr_list_block_add(endpoint_addr_list_t **head,
                                           int endpoint_info_id,
                                           char *_endpoint_id_str, int endpoint_id_str_len,
                                           char *_target_uri_str, int target_uri_len,
                                           char *_request_uri_str, int request_uri_len,
                                           char *_ip_addr_str, int ip_addr_len,
                                           int port, char proto, int status)
{
    endpoint_addr_list_t *ea_list;
    ea_list = shm_mallocxz(sizeof(endpoint_addr_list_t));
    if (!ea_list) {
        LM_ERR("no more memory.\n");
        return 0;
    }

    ea_list->endpoint_info_id = endpoint_info_id;

    if (_endpoint_id_str && endpoint_id_str_len > 0) {
        ea_list->endpoint_id_str.s = shm_mallocxz((endpoint_id_str_len+1)*sizeof(char));
        if (!ea_list->endpoint_id_str.s) {
            SHM_MEM_ERROR;
            return 0;
        }

        memcpy(ea_list->endpoint_id_str.s, _endpoint_id_str, endpoint_id_str_len);
        ea_list->endpoint_id_str.len = endpoint_id_str_len;
    } else {
        ea_list->endpoint_id_str.s = NULL;
        ea_list->endpoint_id_str.len = 0;
    }

    if (_target_uri_str && target_uri_len > 0) {
        ea_list->target_uri.s = shm_mallocxz((target_uri_len+1)*sizeof(char));
        if (!ea_list->target_uri.s) {
            shm_free(ea_list->endpoint_id_str.s);
            shm_free(ea_list);
            SHM_MEM_ERROR;
            return 0;
        }

        memcpy(ea_list->target_uri.s, _target_uri_str, target_uri_len);
        ea_list->target_uri.len = target_uri_len;
    } else {
        ea_list->target_uri.s = NULL;
        ea_list->target_uri.len = 0;
    }

    if (_request_uri_str && request_uri_len > 0) {
        ea_list->request_uri.s = shm_mallocxz((request_uri_len+1)*sizeof(char));
        if (!ea_list->request_uri.s) {
            shm_free(ea_list->endpoint_id_str.s);
            shm_free(ea_list->target_uri.s);
            shm_free(ea_list);
            SHM_MEM_ERROR;
            return 0;
        }

        memcpy(ea_list->request_uri.s, _request_uri_str, request_uri_len);
        ea_list->request_uri.len = request_uri_len;
    } else {
        ea_list->request_uri.s = NULL;
        ea_list->request_uri.len = 0;
    }

    if (_ip_addr_str && ip_addr_len > 0) {
        ea_list->ip_addr.s = shm_mallocxz((ip_addr_len+1)*sizeof(char));
        if (!ea_list->ip_addr.s) {
            shm_free(ea_list->endpoint_id_str.s);
            shm_free(ea_list->target_uri.s);
            shm_free(ea_list->request_uri.s);
            shm_free(ea_list);
            SHM_MEM_ERROR;
            return 0;
        }

        memcpy(ea_list->ip_addr.s, _ip_addr_str, ip_addr_len);
        ea_list->ip_addr.len = ip_addr_len;
    } else {
        ea_list->ip_addr.s = NULL;
        ea_list->ip_addr.len = 0;
    }

    ea_list->port = port;
    ea_list->proto = proto;
    ea_list->status = status;
    ea_list->next = *head;
    *head = ea_list;

    return ea_list;
}

endpoint_info_list_t* endpoint_info_list_block_add(endpoint_info_list_t **head, int endpoint_info_id)
{
    endpoint_info_list_t *ei_list;
    ei_list = shm_mallocxz(sizeof(endpoint_info_list_t));
    if (!ei_list) {
        SHM_MEM_ERROR;
        return 0;
    }

    ei_list->endpoint_info_id = endpoint_info_id;

    ei_list->next = *head;
    *head = ei_list;

    return ei_list;
}

void free_endpoint_addr_list(endpoint_addr_list_t *ea_list) {
    if (ea_list) {
        if (ea_list->endpoint_id_str.s) {
            shm_free(ea_list->endpoint_id_str.s);
        }
        if (ea_list->target_uri.s) {
            shm_free(ea_list->target_uri.s);
        }
        if (ea_list->request_uri.s) {
            shm_free(ea_list->request_uri.s);
        }
        if (ea_list->ip_addr.s) {
            shm_free(ea_list->ip_addr.s);
        }
        shm_free(ea_list);
    }
}

void free_endpoint_info_list(endpoint_info_list_t** ei_list) {
    if (ei_list && *ei_list) {
        endpoint_info_list_t *current_info = *ei_list;
        endpoint_info_list_t *next_info;
        while (current_info) {
            endpoint_addr_list_t *current_addr = current_info->addr_list;
            endpoint_addr_list_t *next_addr = NULL;
            while (current_addr) {
                next_addr = current_addr->next;
                free_endpoint_addr_list(current_addr);
                current_addr = next_addr;
            }
            next_info = current_info->next;
            shm_free(current_info);
            current_info = next_info;
        }
        *ei_list = NULL;
    }
}

int get_endpoint_status(endpoint_info_list_t* pi_obj, int* changed) {
    if (!pi_obj || !changed) {
        return -1;
    }

    int was_online = -1;
    int status = 0;
    endpoint_addr_list_t *current_addr = pi_obj->addr_list;

    while (current_addr) {
        if (current_addr->status >= 0) {
            if (was_online < 0) {
                was_online = 0;
            }
            was_online |= current_addr->status;
        }
        current_addr = current_addr->next;
    }

    current_addr = pi_obj->addr_list;
    while (current_addr) {
        status |= current_addr->status_by_ping;
        current_addr = current_addr->next;
    }

    *changed = was_online < 0 || was_online != status ? 1 : 0;

    return status;
}

static char *pe_string_dup(char *src)
{
    char *res;
    int sz;
    if (!src ) {
        return NULL;
    }

    sz = strlen(src);
    if (!(res = (char *) pkg_malloc(sz + 1))) {
        PKG_MEM_ERROR;
        return NULL;
    }
    strncpy(res, src, sz);
    res[sz] = 0;
    return res;
}

char* create_reply_json(endpoint_info_list_t* ei_list) {
    int count = get_endpoint_info_count(ei_list);
    if (!count) {
        return NULL;
    }

    char* json_str  = NULL;

    struct json_object *root = json_object_new_object();
    struct json_object *event_category = json_object_new_string("bigboard");
    struct json_object *event_name = json_object_new_string("ping_endpoint_resp");
    struct json_object *endpoint_list = json_object_new_array();

    json_object_object_add(root, "Event-Category", event_category);
    json_object_object_add(root, "Event-Name", event_name);

    endpoint_info_list_t *current_info = ei_list;
    char endpoint_name[512] = {0};

    while (current_info) {
        int changed = 0;
        int status = get_endpoint_status(current_info, &changed);
        if (changed) {
            struct json_object *pi = json_object_new_object();
            strncpy(endpoint_name, current_info->addr_list->endpoint_id_str.s, current_info->addr_list->endpoint_id_str.len);
            struct json_object *endpoint_id = json_object_new_string(endpoint_name);
            struct json_object *status_line = json_object_new_string(status ? "Online" : "Offline");

            json_object_object_add(pi, "Endpoint-Id", endpoint_id);
            json_object_object_add(pi, "Status", status_line);
            memset(endpoint_name, 0, sizeof(endpoint_name));

            json_object_array_add(endpoint_list, pi);
        }

        current_info = current_info->next;
    }

    if (json_object_array_length(endpoint_list) == 0) {
        json_object_put(endpoint_list);
    } else {
        json_object_object_add(root, "Endpoint-List", endpoint_list);
        json_str = pe_string_dup((char *)json_object_to_json_string(root));
    }

    json_object_put(root);
    return json_str;
}

unsigned int get_endpoint_info_count(endpoint_info_list_t* ei_list) {
    unsigned int count = 0;
    endpoint_info_list_t *current_info = ei_list;

    while (current_info) {
        ++count;
        current_info = current_info->next;
    }
    return count;
}
