#include "../../core/atomic_ops.h"
#include "../../core/sr_module.h"
#include "../../core/dns_cache.h"
#include "../../core/dset.h"
#include "../../core/trim.h"
#include "../../core/str.h"
#include "../../core/dprint.h"
#include "../../core/dns_wrappers.h"
#include "../../core/mod_fix.h"
#include "../../core/parser/parse_uri.h"
#include "../tm/tm_load.h"

#include "../../modules/ipops/api.h"
#include "../../modules/kazoo/kz_api.h"
#include "../../modules/sqlops/sql_api.h"

#include "ping_endpoint.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

MODULE_VERSION

#define PE_FIELD_SIZE 512

static int mod_init();
static void mod_destroy(void);

static ticks_t pp_check_timer(ticks_t ticks, struct timer_ln* tl, void* param);
static void pp_options_callback(struct cell *t, int type, struct tmcb_params *ps);
static int do_send_ping_option(endpoint_addr_list_t* addr_list);

static int update_endpoint_info_table(endpoint_info_list_t* ei_list);

static atomic_t *pe_endpoint_counter = NULL;
static atomic_t pe_endpoint_list_updated;
int pe_ping_interval = 30;
static int pe_ping_interval_ticks;
struct timer_ln *pe_timer = NULL;

str exec_conn = str_init("exec");
str cb_conn = str_init("cb");
str amqp_exchange = str_init("bigboard");
str amqp_routing_key = str_init("bigboard.ping_resp.kamailio.org");

static sqlops_api_t pe_sqlops;
static ipops_api_t pe_ipops;
static kazoo_api_t pe_kazoo_ops;
struct tm_binds tmb;

endpoint_info_list_t* ei_list = NULL;
str pp_ping_from = str_init("sip:ping_endpoint@nga911.com");

enum ENDPOINT_INFO_COLUMN {
    PI_ENDPOINT_ID_COLUMN       = 0,
    PI_ENDPOINT_ID_STR_COLUMN   = 1,
    PI_DEST_URI_COLUMN      = 2,
    PI_ROUTE_HEADERS_COLUMN = 3,
    PI_TARGET_URI_COLUMN    = 4,
    PI_COMMENT_COLUMN       = 5,
    PI_STATUS_COLUMN        = 6
};

enum ENDPOINT_ADDR_COLUMN {
    PA_ENDPOINT_INFO_ID_COLUMN = 0,
    PA_ENDPOINT_ID_STR_COLUMN  = 1,
    PA_TARGET_URI_COLUMN   = 2,
    PA_REQUEST_URI_COLUMN  = 3,
    PA_IP_ADDR_COLUMN      = 4,
    PA_PORT_COLUMN         = 5,
    PA_PROTOCOL_COLUMN     = 6,
    PA_STATUS_COLUMN       = 7
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
    {"ping_interval", PARAM_INT, &pe_ping_interval},
    {"ping_from", PARAM_STR, &pp_ping_from},
    {"sql_select_conn", PARAM_STR, &cb_conn},
    {"sql_insert_conn", PARAM_STR, &exec_conn},
    {"amqp_exchange", PARAM_STR, &amqp_exchange},
    {"amqp_routing_key", PARAM_STR, &amqp_routing_key},
	{0, 0, 0}
};

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
    {"set_endpoint_list_updated", (cmd_function)pp_set_endpoint_list_updated, 1, fixup_igp_null, fixup_free_igp_null, ANY_ROUTE },
	{0, 0, 0, 0, 0, 0}
};


struct module_exports exports = {
    "ping_endpoint",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,		 /* Exported commands */
	params,		 /* Exported parameters */
	0,		 /* RPC */
	0,		 /* pseudo-variables exports */
	0,		 /* response function*/
	mod_init,	 /* module initialization function */
    0,	 /* per-child init function */
	mod_destroy	 /* destroy function */
};


static int mod_init()
{
    LM_INFO("Initializing ping_endpoint module\n");

    atomic_set(&pe_endpoint_list_updated, 0);

    if (sqlops_load_api(&pe_sqlops) < 0) {
        LM_ERR("can't load sqlops API\n");
        return -1;
    }
    LM_DBG("loaded sqlops api\n");

    if (ipops_load_api(&pe_ipops) < 0) {
        LM_ERR("can't load ipops API\n");
        return -1;
    }
    LM_DBG("loaded ipops api\n");

    if (kazoo_load_api(&pe_kazoo_ops) < 0) {
        LM_ERR("can't load kazoo API\n");
        return -1;
    }
    LM_DBG("loaded kazoo api\n");

    if (load_tm_api(&tmb)!=0) {
        LM_ERR("can't load TM API\n");
        return -1;
    }
    LM_DBG("loaded TM API\n");

    pe_ping_interval_ticks = S_TO_TICKS((pe_ping_interval == 0 ? 30 : pe_ping_interval));

    pe_timer = timer_alloc();
    if (pe_timer == NULL) {
        LM_ERR("failed allocating timer\n");
        return -1;
    }

    timer_init(pe_timer, pp_check_timer, NULL, 0);

    if (timer_add(pe_timer, pe_ping_interval_ticks) < 0){
        LM_ERR("failed to start timer\n");
        return -1;
    }

    pe_endpoint_counter = shm_mallocxz(sizeof(atomic_t));
    if (!pe_endpoint_counter) {
        SHM_MEM_ERROR;
        return -1;
    }

	return 0;
}

static void mod_destroy(void)
{
    if (pe_timer) {
        timer_del(pe_timer);
        timer_free(pe_timer);
        pe_timer = NULL;
    }

    if (pe_endpoint_counter) {
        shm_free(pe_endpoint_counter);
    }
}

int pp_set_endpoint_list_updated(sip_msg_t* _msg, char* _updated)
{
    int updated = 0;

    if (fixup_get_ivalue(_msg, (gparam_p)_updated, &updated) != 0) {
        LM_ERR("invalid integer parameter\n");
        return -1;
    }
    LM_DBG("set endpoint list updated value: %d\n", updated);

    atomic_set(&pe_endpoint_list_updated, updated);

    return 1;
}

int resolve_dns_name(str* name, unsigned short* port, char* proto, endpoint_addr_list_t **slist)
{
    struct ip_addr ip;
    int dns_flags = DNS_TRY_NAPTR;
    struct dns_srv_handle dns_srv_h;

    if(slist == NULL) {
        LM_ERR("Error invalid 'slist' argument\n");
        return -1;
    }

    memset(&dns_srv_h, 0, sizeof(struct dns_srv_handle));

    dns_srv_handle_init(&dns_srv_h);
    int ret = 1;
    while (ret) {
        if (!(ret = dns_sip_resolve(&dns_srv_h, name, &ip, port, proto, dns_flags))) {
            char* ip_str = ip_addr2strz(&ip);
            int len = strlen(ip_str) + 128;

            char* target_uri=pkg_mallocxz(len);
            if (target_uri == NULL) {
                PKG_MEM_ERROR;
                return -1;
            }

            snprintf(target_uri, len, "sip:%s", ip_str);

            if (*port && *port != 5060) {
                snprintf(target_uri + strlen(target_uri), len - strlen(target_uri), ":%d", *port);
            }
            if (*proto != PROTO_UDP) {
                char _proto[8] = {0};
                str sproto = STR_NULL;
                if(get_valid_proto_string(*proto, 1, 0, &sproto) < 0) {
                    sproto.s = "udp";
                    sproto.len = 3;
                    *proto = PROTO_UDP;
                }
                memcpy(_proto, sproto.s, sproto.len);
                snprintf(target_uri + strlen(target_uri), len - strlen(target_uri), ";transport=%s", _proto);
            }

            *slist = endpoint_addr_list_block_add(slist, 0, NULL, 0, NULL, 0, target_uri, strlen(target_uri), ip_str, len, *port, *proto, -1);
            pkg_free(target_uri);
        }

        ret = dns_srv_handle_next(&dns_srv_h, ret);
    }
    dns_srv_handle_put(&dns_srv_h);

    return 0;
}

static int pp_str_copy(str *src, str *dest)
{
    if(src == NULL || dest == NULL) {
        return -1;
    }

    if(src->s == NULL) {
        dest->s = NULL;
        dest->len = 0;
        return 0;
    }

    dest->s = pkg_mallocxz(src->len * sizeof(char));
    if(dest->s == NULL) {
        LM_ERR("no more memory!\n");
        return -1;
    }

    strncpy(dest->s, src->s, src->len);
    dest->len = src->len;

    return 0;
}

static int send_ping_option() {

    static str endpoint_addr_query = str_init("SELECT * FROM endpoint_addr ORDER BY endpoint_info_id ASC");
    str res = str_init("pp_res_addr");

    if (pe_sqlops.query(&cb_conn, &endpoint_addr_query, &res) < 0) {
        LM_ERR("sql endpoint_addr query error\n");
        return -1;
    }

    int rows = pe_sqlops.nrows(&res);
    int columns = pe_sqlops.ncols(&res);

    if (rows < 0 || columns < 0) {
        LM_ERR("Error rows/columns count retrieving from SQL response\n");
        return -1;
    }

    if (ei_list) {
        free_endpoint_info_list(&ei_list);
        ei_list = NULL;
    }

    endpoint_info_list_t* current = ei_list;
    endpoint_addr_list_t* cur_addr = NULL;
    int row = 0;
    for (; row < rows; ++row) {
        int endpoint_info_id_val;
        str endpoint_id_str_val = STR_NULL;
        str target_uri_val = STR_NULL;
        str request_uri_val = STR_NULL;
        str ip_addr_val = STR_NULL;
        int port = 5060;
        int proto = PROTO_UDP;
        int status = -1;
        int column = 0;

        for (; column < columns; ++column) {
            sql_val_t* val = NULL;

            if (pe_sqlops.value(&res, row, column, &val) < 0) {
                LM_ERR("sql sqlops get value error\n");
                return -1;
            }

            switch (column) {
                case PA_ENDPOINT_INFO_ID_COLUMN:
                    endpoint_info_id_val = val->value.n;
                    break;
                case PA_ENDPOINT_ID_STR_COLUMN:
                    pp_str_copy(&val->value.s, &endpoint_id_str_val);
                    break;
                case PA_TARGET_URI_COLUMN:
                    pp_str_copy(&val->value.s, &target_uri_val);
                    break;
                case PA_REQUEST_URI_COLUMN:
                    pp_str_copy(&val->value.s, &request_uri_val);
                    break;
                case PA_IP_ADDR_COLUMN:
                    pp_str_copy(&val->value.s, &ip_addr_val);
                    break;
                case PA_PORT_COLUMN:
                    port = val->value.n;
                    break;
                case PA_PROTOCOL_COLUMN:
                    proto = val->value.n;
                    break;
                case PA_STATUS_COLUMN:
                    if (val->flags & PV_VAL_NULL) {
                    } else {
                        status = val->value.n;
                    }
                default:
                    break;
            }
        }

        if (current) {
            if (endpoint_info_id_val == current->endpoint_info_id) {
                cur_addr = endpoint_addr_list_block_add(&cur_addr,
                                                    endpoint_info_id_val,
                                                    endpoint_id_str_val.s, endpoint_id_str_val.len,
                                                    target_uri_val.s, target_uri_val.len,
                                                    request_uri_val.s, request_uri_val.len,
                                                    ip_addr_val.s, ip_addr_val.len,
                                                    port, proto, status);
                current->addr_list = cur_addr;
            } else {
                ei_list = endpoint_info_list_block_add(&ei_list, endpoint_info_id_val);
                current = ei_list;
                cur_addr = NULL;
                cur_addr = endpoint_addr_list_block_add(&cur_addr,
                                                    endpoint_info_id_val,
                                                    endpoint_id_str_val.s, endpoint_id_str_val.len,
                                                    target_uri_val.s, target_uri_val.len,
                                                    request_uri_val.s, request_uri_val.len,
                                                    ip_addr_val.s, ip_addr_val.len,
                                                    port, proto, status);
                current->addr_list = cur_addr;
            }
        } else {
            ei_list = endpoint_info_list_block_add(&ei_list, endpoint_info_id_val);
            current = ei_list;
            cur_addr = endpoint_addr_list_block_add(&cur_addr,
                                                endpoint_info_id_val,
                                                endpoint_id_str_val.s, endpoint_id_str_val.len,
                                                target_uri_val.s, target_uri_val.len,
                                                request_uri_val.s, request_uri_val.len,
                                                ip_addr_val.s, ip_addr_val.len,
                                                port, proto, status);
            current->addr_list = cur_addr;
        }

        pkg_free(endpoint_id_str_val.s);
        pkg_free(target_uri_val.s);
        pkg_free(request_uri_val.s);
        pkg_free(ip_addr_val.s);
    }

    atomic_set(pe_endpoint_counter, rows);
    current = ei_list;
    LM_DBG("Expected OPTIONS messages number is '%d'\n", atomic_get(pe_endpoint_counter));

    while (current) {
        LM_DBG("Handling the following endpoint_info_id=%d\n", current->endpoint_info_id);
        cur_addr = current->addr_list;
        while (cur_addr) {
            LM_DBG("OPTIONS send for  the following ENDPOINT: endpoint_info_id=%d endpoint_id_str='%.*s' target_uri='%.*s' request_uri='%.*s' ip_addr='%.*s' port=%d proto=%d status=%d\n",
                    current->endpoint_info_id,
                    cur_addr->endpoint_id_str.len, cur_addr->endpoint_id_str.s,
                    cur_addr->target_uri.len, cur_addr->target_uri.s,
                    cur_addr->request_uri.len, cur_addr->request_uri.s,
                    cur_addr->ip_addr.len, cur_addr->ip_addr.s,
                    cur_addr->port, cur_addr->proto, cur_addr->status);

            do_send_ping_option(cur_addr);
            cur_addr = cur_addr->next;
        }
        current = current->next;
    }

    return 0;
}

int do_send_ping_option(endpoint_addr_list_t* addr_list)
{
    str pp_ping_method = str_init("OPTIONS");
    uac_req_t uac_r;

    LM_DBG("Send params for ping endpoint iteration: target_uri='%.*s' request_uri='%.*s'\n", addr_list->target_uri.len, addr_list->target_uri.s, addr_list->request_uri.len, addr_list->request_uri.s);

    set_uac_req(&uac_r, &pp_ping_method, 0, 0, 0, TMCB_LOCAL_COMPLETED, pp_options_callback, (void *)addr_list);

    if (tmb.t_request(&uac_r, &addr_list->target_uri, &addr_list->target_uri, &pp_ping_from, &addr_list->request_uri) < 0) {
        LM_ERR("unable to ping [%.*s]\n", addr_list->target_uri.len, addr_list->target_uri.s);
        atomic_dec(pe_endpoint_counter);
        return -1;
    }

    return 0;
}

void pp_options_callback(struct cell *t, int type, struct tmcb_params *ps)
{
    endpoint_addr_list_t *addr_list = (endpoint_addr_list_t*)(*ps->param);

    LM_DBG("OPTIONS request has been finished with code %d (message sent to '%.*s')\n", ps->code, addr_list->ip_addr.len, addr_list->ip_addr.s);

    addr_list->reply_code = ps->code;
    addr_list->status_by_ping = ps->code >= 200 && ps->code <= 299 ? 1 : 0;

    if (atomic_dec_and_test(pe_endpoint_counter)) {
        LM_DBG("Last OPTIONS message handled\n");

        update_endpoint_info_table(ei_list);

        char *json = create_reply_json(ei_list);

        if (json) {
            LM_INFO("JSON to publish to kazoo: %s\n", json);

            str payload = {json, strlen(json) - 1};

            pe_kazoo_ops.kz_kazoo_publish(&amqp_exchange, &amqp_routing_key, &payload);

            pkg_free(json);
        }

        free_endpoint_info_list(&ei_list);
    }
}

int update_endpoint_info_table(endpoint_info_list_t* _ei_list) {
    endpoint_info_list_t *current_info = _ei_list;
    static const char* endpoint_addr_update = "UPDATE endpoint_addr SET status=%s WHERE endpoint_id_str='%.*s' AND target_uri='%.*s' AND request_uri='%.*s'";
    while (current_info) {
        endpoint_addr_list_t *current_addr = current_info->addr_list;
        while (current_addr) {
            if (current_addr->status != current_addr->status_by_ping) {
                int query_len = strlen(endpoint_addr_update) + current_addr->endpoint_id_str.len + current_addr->target_uri.len + current_addr->request_uri.len + 64;
                char *update_query = pkg_mallocxz(query_len);
                if (update_query == NULL) {
                    PKG_MEM_ERROR;
                    return -1;
                }
                snprintf(update_query,
                        query_len,
                        endpoint_addr_update,
                        current_addr->status_by_ping ? "TRUE" : "FALSE",
                        current_addr->endpoint_id_str.len, current_addr->endpoint_id_str.s,
                        current_addr->target_uri.len, current_addr->target_uri.s,
                        current_addr->request_uri.len, current_addr->request_uri.s);

                LM_DBG("UPDATE DB for the following addr: endpoint_info_id=%d; request_uri='%.*s' target_uri='%.*s'\n",
                       current_addr->endpoint_info_id,
                       current_addr->request_uri.len, current_addr->request_uri.s,
                       current_addr->target_uri.len, current_addr->target_uri.s);

                str update_query_str = {update_query, strlen(update_query)};
                if (pe_sqlops.query(&exec_conn, &update_query_str, NULL) < 0) {
                    LM_ERR("sql update endpoint_addr query error\n");
                }
                pkg_free(update_query);
            }
            current_addr = current_addr->next;
        }
        current_info = current_info->next;
    }
    return 0;
}

ticks_t pp_check_timer(ticks_t ticks, struct timer_ln* tl, void* param)
{
    str res = str_init("pp_res_info");
    int need_update = 0;

    if (atomic_get(&pe_endpoint_list_updated)) {
        static str delete_endpoint_addr_query = str_init("DELETE FROM endpoint_addr");
        atomic_set(&pe_endpoint_list_updated, 0);
        if (pe_sqlops.query(&exec_conn, &delete_endpoint_addr_query, &res) < 0) {
            LM_ERR("sql delete endpoint_addr query error\n");
            return -1;
        }
        need_update = 1;
    } else {
        static str need_update_query = str_init("SELECT CASE WHEN EXISTS(SELECT 1 FROM endpoint_info) AND NOT EXISTS(SELECT 1 FROM endpoint_addr) THEN 1 ELSE 0 END AS NeedUpdate");
        if (pe_sqlops.query(&exec_conn, &need_update_query, &res) < 0) {
            LM_ERR("sql delete endpoint_addr query error\n");
            return -1;
        }
        if (pe_sqlops.nrows(&res) > 0) {
            sql_val_t* val = NULL;
            if (pe_sqlops.value(&res, 0, 0, &val) < 0) {
                LM_ERR("sql sqlops get value error\n");
                return -1;
            }
            need_update = val->value.n;
        } else {
            LM_ERR("sql query error\n");
            return -1;
        }
    }

    if (need_update) {
        static str endpoint_info_query = str_init("SELECT * FROM endpoint_info");
        static const char* endpoint_addr_insert = "INSERT INTO endpoint_addr (endpoint_info_id, endpoint_id_str, target_uri, request_uri, ip_addr, port, protocol) VALUES (%d, '%.*s', '%.*s', '%.*s', '%.*s', %d, %d)";
        int cache_flushed = 0;

        if (pe_sqlops.query(&cb_conn, &endpoint_info_query, &res) < 0) {
            LM_ERR("sql endpoint_info query error\n");
            return -1;
        }

        int rows = pe_sqlops.nrows(&res);
        int columns = pe_sqlops.ncols(&res);

        if (rows < 0 || columns < 0) {
            LM_ERR("Error rows/columns count retrieving from SQL response\n");
            return -1;
        }

        int row = 0;
        for (; row < rows; ++row) {
            int column = 0;

            int endpoint_id_val;
            char _endpoint_id_str_val[PE_FIELD_SIZE] = {0};
            char _dest_uri_val[PE_FIELD_SIZE] = {0};
            char _target_uri_val[PE_FIELD_SIZE] = {0};
            str endpoint_id_str_val = {_endpoint_id_str_val, PE_FIELD_SIZE};
            str dest_uri_val = {_dest_uri_val, PE_FIELD_SIZE};
            str target_uri_val = {_target_uri_val, PE_FIELD_SIZE};
            int port = 5060;
            int proto = PROTO_UDP;

            struct sip_uri uri;

            for (; column < columns; ++column) {
                sql_val_t* val = NULL;
                if (pe_sqlops.value(&res, row, column, &val) < 0) {
                    LM_ERR("sql sqlops get value error\n");
                    return -1;
                }

                switch (column) {
                    case PI_ENDPOINT_ID_COLUMN:
                        endpoint_id_val = val->value.n;
                        break;
                    case PI_ENDPOINT_ID_STR_COLUMN:
                        strncpy(endpoint_id_str_val.s, val->value.s.s, val->value.s.len);
                        endpoint_id_str_val.len = val->value.s.len;
                        break;
                    case PI_DEST_URI_COLUMN:
                        strncpy(dest_uri_val.s, val->value.s.s, val->value.s.len);
                        dest_uri_val.len = val->value.s.len;
                        break;
                    case PI_TARGET_URI_COLUMN:
                        strncpy(target_uri_val.s, val->value.s.s, val->value.s.len);
                        target_uri_val.len = val->value.s.len;
                    default:
                        break;
                }
            }

            if (!parse_uri(target_uri_val.s, target_uri_val.len, &uri)) {
                str sproto = STR_NULL;
                if(PROTO_NONE == uri.proto || get_valid_proto_string(uri.proto, 1, 1, &sproto) < 0) {
                    LM_WARN("unknown transport protocol - fall back to udp\n");
                    sproto.s = "UDP";
                    sproto.len = 3;
                    proto = PROTO_UDP;
                } else {
                    proto = uri.proto;
                }
                LM_DBG("Successfully parsed URI: '%.*s'; hostname='%.*s'; protocol=%d; protocol_str='%.*s'; port_str='%.*s'; port=%d\n",
                        target_uri_val.len, target_uri_val.s,
                        uri.host.len, uri.host.s,
                        proto,
                        sproto.len, sproto.s,
                        uri.port.len, uri.port.s,
                        uri.port_no);
                if (uri.port_no) {
                    port = uri.port_no;
                }

            } else {
                LM_ERR("Error parse target URI: [%.*s]\n", target_uri_val.len, target_uri_val.s);
                continue;
            }

            endpoint_addr_list_t* addr_list = NULL;
            if (pe_ipops.is_ip(&uri.host) > 0) {
                int len = uri.host.len + 128;
                char* target_uri_str = pkg_mallocxz(len);
                if (target_uri_str == NULL) {
                    PKG_MEM_ERROR;
                    return -1;
                }

                memcpy(target_uri_str, "sip:", 4);
                memcpy(target_uri_str + strlen(target_uri_str), uri.host.s, uri.host.len);

                if (port && port != 5060) {
                    snprintf(target_uri_str + strlen(target_uri_str), len - strlen(target_uri_str), ":%d", port);
                }
                if (proto != PROTO_UDP) {
                    char _proto[8] = {0};
                    str sproto = STR_NULL;
                    if(get_valid_proto_string(proto, 1, 0, &sproto) < 0) {
                        sproto.s = "udp";
                        sproto.len = 3;
                    }
                    memcpy(_proto, sproto.s, sproto.len);
                    snprintf(target_uri_str + strlen(target_uri_str), len - strlen(target_uri_str), ";transport=%s", _proto);
                }
                addr_list = endpoint_addr_list_block_add(&addr_list, endpoint_id_val, endpoint_id_str_val.s, endpoint_id_str_val.len, target_uri_str, strlen(target_uri_str), dest_uri_val.s, dest_uri_val.len, uri.host.s, uri.host.len, port, proto, -1);
                pkg_free(target_uri_str);
            } else {
                if (!cache_flushed) {
                    dns_cache_flush(0);
                    cache_flushed = 1;
                }
                if (resolve_dns_name(&uri.host, (unsigned short*)&port, (char*)&proto, &addr_list) != 0) {
                    LM_ERR("Error DNS resolve for URI: [%.*s]\n", uri.host.len, uri.host.s);
                    continue;
                }
            }

            while (addr_list) {
                endpoint_addr_list_t* prev = addr_list;
                int query_len = strlen(endpoint_addr_insert) + endpoint_id_str_val.len + target_uri_val.len + addr_list->request_uri.len + addr_list->ip_addr.len + 128;
                char *insert_query = pkg_mallocxz(query_len);
                if (insert_query == NULL) {
                    PKG_MEM_ERROR;
                    return -1;
                }

                snprintf(insert_query,
                        query_len,
                        endpoint_addr_insert,
                        endpoint_id_val,
                        endpoint_id_str_val.len, endpoint_id_str_val.s,
                        target_uri_val.len, target_uri_val.s,
                        addr_list->request_uri.len, addr_list->request_uri.s,
                        addr_list->ip_addr.len, addr_list->ip_addr.s,
                        addr_list->port, addr_list->proto);

                LM_DBG("addr_list addr: '%.*s'; request_uri: '%.*s'; port=%d; proto=%d\n",
                       addr_list->ip_addr.len, addr_list->ip_addr.s,
                       addr_list->request_uri.len, addr_list->request_uri.s,
                       addr_list->port, addr_list->proto);

                str insert_query_str = {insert_query, strlen(insert_query)};
                if (pe_sqlops.query(&exec_conn, &insert_query_str, NULL) < 0) {
                    LM_ERR("sql insert endpoint_addr query error\n");
                    pkg_free(insert_query);
                    return -1;
                }
                addr_list = addr_list->next;
                free_endpoint_addr_list(prev);
                pkg_free(insert_query);
            }
        }
    }

    send_ping_option();

    return pe_ping_interval_ticks;
}
