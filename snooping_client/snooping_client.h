#ifndef __SNOOPING_CLIENT_H__
#define __SNOOPING_CLIENT_H__

#include <stdio.h>
#include <stdint.h>
#include "list.h"
#include "../cache_rule/cache_rule.h"

#define SNOOPING_CLIENT_DEBUG       1

#define SC_RETRIEVE_HANDLE_PORT     10006
#define SC_SPM_SND_RCV_BUFLEN       1024
#define SC_MAX_HOST_NAME_LEN        32
#define HTTP_URL_PREFIX             "http://"
#define HTTP_URL_PRE_LEN            7       /* strlen("http://") */

#define SC_WEB_SERVER_ROOT          "/data/local/html/"
#define SC_WEB_SERVER_ROOT_LEN      (sizeof(SC_WEB_SERVER_ROOT) - 1)
#define SC_RES_RECORD_FILE          "http-cache.txt"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/**********************************/
#define HTTP_SP_URL_LEN_MAX 600
#define HTTP_SP_URL_MAX (16*1024)

#define HTTP_LOCAL_FILE_ROOT_MAX 64

#define HTTP_SP_NGX_SERVER_MAX (4)
#define HTTP_SP2C_PORT (9999)
#define HTTP_C2SP_PORT (10000)
#define HTTP_C2SP_ACTION_GET (1)
#define HTTP_C2SP_ACTION_GETNEXT (2)
#define HTTP_C2SP_ACTION_ADD (3)
#define HTTP_C2SP_ACTION_DELETE (4)
#define HTTP_C2SP_ACTION_CACHE (5)
//#define HTTP_C2SP_ACTION_UPPARSE (6)
typedef struct http_c2sp_req_pkt_s {
    u32 session_id;
    u8 c2sp_action;
    u8 pad[3];
    u16 url_len;
    u8 usr_data[HTTP_SP_URL_LEN_MAX];
}http_c2sp_req_pkt_t;

typedef struct http_c2sp_res_pkt_s{
    u32 session_id;
    u8 status;
    u8 pad[3];
}http_c2sp_res_pkt_t;

#define HTTP_SP_STATUS_OK 0
#define HTTP_SP_STATUS_DEFAULT_ERROR 1

#define HTTP_SP2C_ACTION_PARSE 1
#define HTTP_SP2C_ACTION_DOWN 2
#define HTTP_SP2C_ACTION_GETNEXT 3
typedef struct http_sp2c_req_pkt_s
{
    u32 session_id;
    u8 sp2c_action;
    u8 pad[3];
    u16 url_len;
    u8 url_data[HTTP_SP_URL_LEN_MAX];
}http_sp2c_req_pkt_t;

typedef struct http_sp2c_res_pkt_s {
    u32 session_id;
    u8 status;
    u8 pad[3];
    u16 url_len;
    u8 url_data[HTTP_SP_URL_LEN_MAX];
}http_sp2c_res_pkt_t;

/**********************************/

typedef struct sc_res_info_s {
    struct list_head list;

    unsigned long flags;
    u32 sid;
    string_t url;
    char url_buf[HTTP_SP_URL_LEN_MAX];
} sc_res_info_t;

typedef struct sc_res_list_s {
    struct list_head list;
    int count;
} sc_res_list_t;

typedef struct sc_res_file_s {
    char *path;
    FILE *fp;
} sc_res_file_t;

#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define sc_dbg(fmt, arg...) \
    do { \
        if (SNOOPING_CLIENT_DEBUG) { \
            fprintf(stderr, "[DBG]%20.19s: " fmt "\n", __func__, ##arg); \
        } \
    } while (0)

#define sc_print(fmt, arg...) \
    do { \
        fprintf(stdout, fmt "\n", ##arg); \
    } while (0)

#endif /* __SNOOPING_CLIENT_H__ */

