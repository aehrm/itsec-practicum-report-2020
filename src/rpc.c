#include <stdlib.h>
#include <curl/curl.h>

#include "util.h"
#include "cjson/cJSON.h"
#include "libbtc/include/btc/cstr.h"

static size_t writefn(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  cstr_append_buf((cstring *) userp, contents, realsize);
 
  return realsize;
}

int rpc_call(char *url, char* method, cJSON *params, cJSON **out)
{
    CURLcode res;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;

    if (!curl) {
        fprintf(stderr, "Error: Curl_open failed\n");
        return 1;
    }

    headers = curl_slist_append(headers, "content-type: text/plain;");

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "method", method);
    cJSON_AddItemToObjectCS(req, "params", cJSON_Duplicate(params, true));
    char *postdata = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    cstring *response = cstr_new_sz(1024);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(postdata));
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    /*curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);*/
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writefn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
	res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        int len = strlen(errbuf);
        fprintf(stderr, "libcurl: (%d) ", res);
        if(len)
            fprintf(stderr, "%s%s", errbuf,
                    ((errbuf[len - 1] != '\n') ? "\n" : ""));
        else
            fprintf(stderr, "%s\n", curl_easy_strerror(res));

        return 1;
    }

    curl_easy_cleanup(curl);
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code != 200) {
        fprintf(stderr, "Response code was %d, expected 200: %s\n", response_code, response->str);
        fprintf(stderr, "input: %s\n", postdata);
        return 1;
    }

    free(postdata);

    // parse response
    /*fprintf(stderr, "%s\n", response->str);*/
    cJSON *resobj = cJSON_Parse(response->str);
    if (resobj == NULL) {
        fprintf(stderr, "Parse error: %s\n", cJSON_GetErrorPtr());
        return 1;
    }

    cJSON *err = cJSON_GetObjectItem(resobj, "error");
    if (!cJSON_IsNull(err)) {
        fprintf(stderr, "RPC error %d: %s\n",
                cJSON_GetObjectItem(err, "code")->valueint,
                cJSON_GetObjectItem(err, "message")->valuestring);
        return 1;
    }

    *out = cJSON_Duplicate(cJSON_GetObjectItem(resobj, "result"), true);
    return 0;
}
