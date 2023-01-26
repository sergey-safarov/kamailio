#ifndef __KAZOO_API_H_
#define __KAZOO_API_H_

#include "../../core/sr_module.h"

typedef int (*kz_kazoo_publish_f)(str* exchange, str* routing_key, str* payload);
int _kz_kazoo_publish(str* exchange, str* routing_key, str* payload);

typedef struct kazoo_api {
    kz_kazoo_publish_f kz_kazoo_publish;
} kazoo_api_t;

typedef int (*bind_kazoo_f)(kazoo_api_t *api);
int bind_kazoo(kazoo_api_t *api);

/**
 * @brief Load the kazoo API
 */
static inline int kazoo_load_api(kazoo_api_t *api)
{
    bind_kazoo_f bindkazoo;

    bindkazoo = (bind_kazoo_f)find_export("bind_kazoo", 0, 0);
    if(bindkazoo == 0) {
        LM_ERR("cannot find bind_kazoo\n");
		return -1;
	}

    if(bindkazoo(api) < 0) {
        LM_ERR("cannot bind kazoo api\n");
		return -1;
	}
	return 0;
}

#endif /* __KAZOO_API_H_ */
