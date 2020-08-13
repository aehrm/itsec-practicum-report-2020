#ifndef __RPC_H__
#define __RPC_H__ 1

#include "cjson/cJSON.h"

int rpc_call(char *url, char* method, cJSON *params, cJSON **out);

#endif
