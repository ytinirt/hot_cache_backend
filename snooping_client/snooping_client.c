#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>

#include <curl/curl.h>

#include "snooping_client.h"

#define SC_IPADDR_STR_BUFLEN_MAX   (sizeof("xxx.xxx.xxx.xxx"))

char g_sc_sp_module_ipaddr_str[SC_IPADDR_STR_BUFLEN_MAX] = {0};

int g_sc_spm_serve_sockfd = -1;         /* UDP */
int g_sc_retrieve_handle_sockfd = -1;   /* UDP */
fd_set g_sc_master_read_fd_set;
int g_sc_max_read_fd = -1;

sc_res_list_t g_sc_res_free_list;
sc_res_list_t g_sc_res_retrieving_list;
sc_res_list_t g_sc_res_stored_list;

cache_rule_ctx_t *g_sc_cache_rule_ctx = NULL;

static int sc_retrieve_inform(string_t *url);

/*
 * Not copy "http://", omitting parameter in o_url or not, is depending on with_para.
 */
static void sc_res_copy_url(char *url, char *o_url, unsigned int len, char with_para)
{
    char *start = o_url, *p, *q;

    if (url == NULL || o_url == NULL) {
        return;
    }

    if (strncmp(start, HTTP_URL_PREFIX, HTTP_URL_PRE_LEN) == 0) {
        start = start + HTTP_URL_PRE_LEN;
    }

    if (with_para) {
        for (p = url, q = start; *q != '\0'; p++, q++) {
            *p = *q;
        }
    } else {
        for (p = url, q = start; *q != '?' && *q != '\0'; p++, q++) {
            *p = *q;
        }
    }

    if (url + len < p) {
        sc_dbg("Overflow, buffer len %u, but copied %u", len, (unsigned int)(p - url));
    }
}

/* 必须根据key值查找，只有key值是url(资源)的唯一标识符 */
static sc_res_info_t *sc_res_find_by_key(struct list_head *head, string_t *key)
{
    sc_res_info_t *ri, *ret = NULL;

    list_for_each_entry(ri, head, list, sc_res_info_t) {
        if (cache_rule_str_is_equal(&ri->key, key)) {
            ret = ri;
            break;
        }
    }

    return ret;
}

static sc_res_info_t *sc_res_find_stored(string_t *url)
{
    sc_res_info_t *ret = NULL;
    cache_rule_t *cache_rule;
    string_t key;
    char key_tmp_buf[HTTP_SP_URL_LEN_MAX];

    cache_rule = cache_rule_get_rule(g_sc_cache_rule_ctx, url);
    if (cache_rule == NULL) {
        sc_dbg("Not find cache rule: %*s", url->len, url->data);
        goto out;
    }

    key.data = key_tmp_buf;
    key.len = HTTP_SP_URL_LEN_MAX;
    if (cache_rule_url2local_key(url, cache_rule, &key) != 0) {
        sc_dbg("Key generate failed: %*s", url->len, url->data);
        goto out;
    }

    ret = sc_res_find_by_key(&g_sc_res_stored_list.list, &key);

out:
    return ret;
}

/* 必须根据key值查找，只有key值是url(资源)的唯一标识符 */
static sc_res_info_t *sc_res_find_retrieving(string_t *url)
{
    sc_res_info_t *ret = NULL;
    cache_rule_t *cache_rule;
    string_t key;
    char key_tmp_buf[HTTP_SP_URL_LEN_MAX];

    cache_rule = cache_rule_get_rule(g_sc_cache_rule_ctx, url);
    if (cache_rule == NULL) {
        sc_dbg("Not find cache rule: %*s", url->len, url->data);
        goto out;
    }

    key.data = key_tmp_buf;
    key.len = HTTP_SP_URL_LEN_MAX;
    if (cache_rule_url2local_key(url, cache_rule, &key) != 0) {
        sc_dbg("Key generate failed: %*s", url->len, url->data);
        goto out;
    }

    ret = sc_res_find_by_key(&g_sc_res_retrieving_list.list, &key);

out:
    return ret;
}

static sc_res_info_t *sc_res_alloc()
{
    sc_res_info_t *ri = NULL;
    struct list_head *plist;

    if (!list_empty(&g_sc_res_free_list.list)) {
        plist = g_sc_res_free_list.list.next;
        list_del_init(plist);
        ri = list_entry(plist, sc_res_info_t, list);
        g_sc_res_free_list.count--;
    }

    if (g_sc_res_free_list.count < 0) {
        sc_dbg("BUG: g_sc_res_free_list.count = %d", g_sc_res_free_list.count);
    }

    return ri;
}

static int sc_res_record_url(string_t *url)
{
    FILE *fp;
    int ret = 0;

    fp = fopen(SC_WEB_SERVER_ROOT SC_RES_RECORD_FILE, "a");
    if (fp == NULL) {
        sc_dbg("Open file %s%s failed", SC_WEB_SERVER_ROOT, SC_RES_RECORD_FILE);
        return -1;
    }

    fprintf(fp, "@@@@+%*s\r\n", (int)(url->len), url->data);

    fclose(fp);

    return ret;
}

static void sc_res_load_url(string_t *url)
{
    string_t file_str;
    cache_rule_t *rule;
    char file_buf[HTTP_SP_URL_LEN_MAX + HTTP_LOCAL_FILE_ROOT_MAX];
    int ret;
    struct stat file_stat;
    sc_res_info_t *ri, *ri_already = NULL;
    string_t key_str;
    char key_buf[HTTP_SP_URL_LEN_MAX];

    rule = cache_rule_get_rule(g_sc_cache_rule_ctx, url);
    if (rule == NULL) {
        sc_dbg("Not find rule: %*s", (int)(url->len), url->data);
        return;
    }

    key_str.data = key_buf;
    key_str.len = sizeof(key_buf);
    ret = cache_rule_url2local_key(url, rule, &key_str);
    if ((ret != 0) || (key_str.len >= HTTP_SP_KEY_LEN_MAX)) {
        sc_dbg("Url to key failed: %*s", url->len, url->data);
        return;
    }

    memcpy(file_buf, SC_WEB_SERVER_ROOT, SC_WEB_SERVER_ROOT_LEN);
    file_str.data = file_buf + SC_WEB_SERVER_ROOT_LEN;
    file_str.len = sizeof(file_buf) - SC_WEB_SERVER_ROOT_LEN;
    ret = cache_rule_url2local_file(url, rule, &file_str);
    if (ret != 0) {
        sc_dbg("Url to local file name failed: %*s", (int)(url->len), url->data);
        return;
    }

    if (stat(file_buf, &file_stat) != 0) {
        sc_dbg("File not exists: %*s", (int)(url->len), url->data);
        return;
    }

    ri_already = sc_res_find_by_key(&g_sc_res_stored_list.list, &key_str);
    if (ri_already != NULL) {
        sc_dbg("URL already exists: %*s", ri_already->url.len, ri_already->url.data);
        return;
    }

    ri = sc_res_alloc();
    if (ri == NULL) {
        sc_dbg("Allocate ri failed.");
        return;
    }

    ri->flags = 0;
    ri->sid = 0;
    memset(ri->url_buf, 0, HTTP_SP_URL_LEN_MAX);
    memcpy(ri->url_buf, url->data, url->len);
    ri->url.data = ri->url_buf;
    ri->url.len = url->len;
    memset(ri->key_buf, 0, HTTP_SP_KEY_LEN_MAX);
    memcpy(ri->key_buf, key_str.data, key_str.len);
    ri->key.data = ri->key_buf;
    ri->key.len = key_str.len;

    list_add(&ri->list, &g_sc_res_stored_list.list);
    g_sc_res_stored_list.count++;

    return;
}

static void sc_res_free(sc_res_info_t *ri)
{
    list_add_tail(&ri->list, &g_sc_res_free_list.list);
    g_sc_res_free_list.count++;
}

static int sc_res_init(int total)
{
    size_t alloc_size;
    int i;
    sc_res_info_t *mem, *ri;

    alloc_size = total * sizeof(sc_res_info_t);
    mem = malloc(alloc_size);
    if (mem == NULL) {
        sc_dbg("Allocate failed: %zu", alloc_size);
        return -1;
    }

    memset(mem, 0, alloc_size);
    g_sc_res_free_list.count = 0;
    INIT_LIST_HEAD(&g_sc_res_free_list.list);
    for (i = 0; i < total; i++) {
        ri = mem + i;
        INIT_LIST_HEAD(&ri->list);
        list_add_tail(&ri->list, &g_sc_res_free_list.list);
        g_sc_res_free_list.count++;
    }

    g_sc_res_retrieving_list.count = 0;
    INIT_LIST_HEAD(&g_sc_res_retrieving_list.list);

    g_sc_res_stored_list.count = 0;
    INIT_LIST_HEAD(&g_sc_res_stored_list.list);

    return 0;
}

static int sc_spm_do_action(u8 act, u32 sid, char *url)
{
    int err = 0, nsend, nrecv;
    int sockfd;
    struct sockaddr_in sa;
    socklen_t salen;
    char buf[SC_SPM_SND_RCV_BUFLEN];
    http_c2sp_req_pkt_t *req;
    http_c2sp_res_pkt_t *res;

    if (url == NULL) {
        sc_dbg("invalid input");
        return -1;
    }

    if (act != HTTP_C2SP_ACTION_ADD && act != HTTP_C2SP_ACTION_DELETE) {
        sc_dbg("non-support action %u", act);
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)HTTP_C2SP_PORT);
    sa.sin_addr.s_addr = inet_addr(g_sc_sp_module_ipaddr_str);
    salen = sizeof(struct sockaddr_in);
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        sc_dbg("Socket failed: %s", strerror(errno));
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    if (SC_SPM_SND_RCV_BUFLEN < sizeof(http_c2sp_req_pkt_t)) {
        sc_dbg("small buf(%d) can not hold c2sp_req(%u)", SC_SPM_SND_RCV_BUFLEN, sizeof(http_c2sp_req_pkt_t));
        err = -1;
        goto out;
    }
    req = (http_c2sp_req_pkt_t *)buf;
    req->session_id = sid;
    req->c2sp_action = act;
    req->url_len = htons(strlen(url));
    sc_res_copy_url((char *)req->usr_data, url, HTTP_SP_URL_LEN_MAX, 1);

    if ((nsend = sendto(sockfd, req, sizeof(http_c2sp_req_pkt_t), 0, (struct sockaddr *)&sa, salen)) < 0) {
        sc_dbg("sendto failed: %s", strerror(errno));
        err = -1;
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    nrecv = recvfrom(sockfd, buf, SC_SPM_SND_RCV_BUFLEN, 0, NULL, NULL);
    if (nrecv < 0) {
        sc_dbg("recvfrom %d, is not valid to %u: %s",
                    nrecv, sizeof(http_c2sp_res_pkt_t), strerror(errno));
        err = -1;
        goto out;
    }
    res = (http_c2sp_res_pkt_t *)buf;
    if (res->session_id != sid) {
        sc_dbg("send id %u, not the same as response id %u", sid, res->session_id);
        err = -1;
        goto out;
    }

    if (res->status == HTTP_SP_STATUS_OK) {
        ;
    } else {
        sc_dbg("response status is failed %u", res->status);
        err = -1;
        goto out;
    }

out:
    close(sockfd);

    return err;
}

static int sc_spm_add_url(u32 sid, char *url)
{
    int ret;

    ret = sc_spm_do_action(HTTP_C2SP_ACTION_ADD, sid, url);
    sc_dbg("%-120s", url);

    return ret;
}

static int sc_spm_del_url(u32 sid, char *url)
{
    int ret;

    ret = sc_spm_do_action(HTTP_C2SP_ACTION_DELETE, sid, url);
    sc_dbg("%120s", url);

    return ret;
}

static int sc_spm_response(int sockfd,
                           struct sockaddr *sa,
                           socklen_t salen,
                           http_sp2c_req_pkt_t *req,
                           const u8 status)
{
    http_sp2c_res_pkt_t *resp;
    u8 old;
    int nsend;

    if (status != HTTP_SP_STATUS_OK && status != HTTP_SP_STATUS_DEFAULT_ERROR) {
        sc_dbg("unknown status code %u", status);
        return -1;
    }

    /* zhaoyao XXX FIXME: http_sp2c_req_pkt_t and http_sp2c_res_pkt_t almost the same, reuse req */
    resp = (http_sp2c_res_pkt_t *)req;
    old = req->sp2c_action; /* zhaoyao XXX FIXME: change req's value directly maybe dangerous */
    resp->status = status;
    resp->url_len = htons(resp->url_len);
    nsend = sendto(sockfd, (void *)resp, sizeof(http_sp2c_res_pkt_t), 0, sa, salen);

    req->url_len = ntohs(req->url_len);
    req->sp2c_action = old; /* zhaoyao XXX: keep it untouched */

    if (nsend < 0) {
        sc_dbg("sendto failed, %s", strerror(errno));
        return -1;
    }

    return 0;
}

static u8 sc_spm_serve_parse(http_sp2c_req_pkt_t *req)
{
    sc_print("Not support sc_spm_serve_parse now.");

    return HTTP_SP_STATUS_OK;
}

static u8 sc_spm_serve_down(http_sp2c_req_pkt_t *req)
{
    int ret;
    sc_res_info_t *ri;
    string_t url_str;
    u8 status = HTTP_SP_STATUS_OK;
    cache_rule_t *cache_rule;
    string_t key;
    char key_buf[HTTP_SP_URL_LEN_MAX];

    url_str.data = (char *)req->url_data;
    url_str.len = req->url_len;

    ri = sc_res_find_stored(&url_str);
    if (ri != NULL) {
        sc_dbg("BUG: URL already stored: %s", req->url_data);
        goto out;
    }

    ri = sc_res_find_retrieving(&url_str);
    if (ri != NULL) {
        sc_dbg("URL is retrieving: %s", req->url_data);
        goto out;
    }

    cache_rule = cache_rule_get_rule(g_sc_cache_rule_ctx, &url_str);
    if (cache_rule == NULL) {
        sc_dbg("Not find rule: %s", req->url_data);
        status = HTTP_SP_STATUS_DEFAULT_ERROR;
        goto out;
    }
    key.data = key_buf;
    key.len = sizeof(key_buf);
    ret = cache_rule_url2local_key(&url_str, cache_rule, &key);
    if ((ret != 0) || (key.len >= HTTP_SP_KEY_LEN_MAX)) {
        sc_dbg("Key generate failed: %s", req->url_data);
        status = HTTP_SP_STATUS_DEFAULT_ERROR;
        goto out;
    }

    ri = sc_res_alloc();
    if (ri == NULL) {
        sc_dbg("URL allocate failed: %s", req->url_data);
        status = HTTP_SP_STATUS_DEFAULT_ERROR;
        goto out;
    }

    ri->flags = 0;
    ri->sid = req->session_id;
    memcpy(ri->url_buf, req->url_data, req->url_len + 1); /* 附加尾部的'\0' */
    ri->url.data = ri->url_buf;
    ri->url.len = req->url_len;
    memcpy(ri->key_buf, key.data, key.len + 1);
    ri->key.data = ri->key_buf;
    ri->key.len = key.len;

    ret = sc_retrieve_inform(&ri->url);
    if (ret != 0) {
        sc_dbg("Inform to retrieve failed: %s", req->url_data);
        status = HTTP_SP_STATUS_DEFAULT_ERROR;
        goto errout1;
    }

    list_add_tail(&ri->list, &g_sc_res_retrieving_list.list);
    g_sc_res_retrieving_list.count++;

out:
    return status;

errout1:
    sc_res_free(ri);

    return status;
}

static void sc_spm_serve(const int sockfd)
{
    int nrecv;
    struct sockaddr sa;
    socklen_t salen;
    char buf[SC_SPM_SND_RCV_BUFLEN];
    http_sp2c_req_pkt_t *sp2c_req;
    u8 status = HTTP_SP_STATUS_DEFAULT_ERROR;
#if SNOOPING_CLIENT_DEBUG
    struct sockaddr_in *in_sa;
    char ip_addr[SC_MAX_HOST_NAME_LEN];
#endif

    salen = sizeof(struct sockaddr);
    memset(&sa, 0, salen);
    memset(buf, 0, sizeof(buf));
    if ((nrecv = recvfrom(sockfd, buf, SC_SPM_SND_RCV_BUFLEN, 0, &sa, &salen)) < 0) {
        sc_dbg("recvfrom error: %s", strerror(errno));
        return;
    }
#if SNOOPING_CLIENT_DEBUG
    in_sa = (struct sockaddr_in *)&sa;
    sc_dbg("client port %u, ip %s",
                ntohs(in_sa->sin_port), inet_ntop(AF_INET, &in_sa->sin_addr, ip_addr, SC_MAX_HOST_NAME_LEN));
#endif

    if (nrecv < sizeof(http_sp2c_req_pkt_t)) {
        sc_dbg("recvfrom invalid %d bytes, less than %u", nrecv, sizeof(http_sp2c_req_pkt_t));
        goto reply;
    }

    sp2c_req = (http_sp2c_req_pkt_t *)buf;
    sp2c_req->url_len = ntohs(sp2c_req->url_len);
    if (sp2c_req->url_len >= HTTP_SP_URL_LEN_MAX) {
        sc_dbg("sp2c_req's url (%u) is longer than %d", sp2c_req->url_len, HTTP_SP_URL_LEN_MAX);
        goto reply;
    }

    switch (sp2c_req->sp2c_action) {
    case HTTP_SP2C_ACTION_PARSE:
        status = sc_spm_serve_parse(sp2c_req);
        break;
    case HTTP_SP2C_ACTION_DOWN:
        status = sc_spm_serve_down(sp2c_req);
        break;
    case HTTP_SP2C_ACTION_GETNEXT:
        sc_dbg("HTTP_SP2C_ACTION_GETNEXT %u not support now", sp2c_req->sp2c_action);
        break;
    default:
        sc_dbg("unknown sp2c_action %u", sp2c_req->sp2c_action);
    }

reply:
    sc_spm_response(sockfd, &sa, salen, sp2c_req, status);

    return;
}

static int sc_create_full_path(string_t *dir, unsigned int access)
{
    char *p, ch;
    int err = 0;

    p = dir->data + 1;

    for ( /* void */ ; p < dir->data + dir->len; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (mkdir(dir->data, access) != 0) {
            err = errno;

            switch (err) {
            case EEXIST:
                err = 0;
            case EACCES:
                break;

            default:
                return err;
            }
        }

        *p = '/';
    }

    return err;
}

static void sc_retrieve_ret_result(string_t *url, int success)
{
    int nsend;
    int sockfd;
    struct sockaddr_in sa;
    socklen_t salen;
    char buf[SC_SPM_SND_RCV_BUFLEN];

    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)SC_RETRIEVE_HANDLE_PORT);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    salen = sizeof(sa);
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        sc_dbg("Socket failed: %s", strerror(errno));
        return;
    }

    memset(buf, 0, sizeof(buf));
    if (success) {
        sprintf(buf, "S %*s", (int)(url->len), url->data);
    } else {
        sprintf(buf, "F %*s", (int)(url->len), url->data);
    }

    if ((nsend = sendto(sockfd, buf, url->len + 2, 0, (struct sockaddr *)&sa, salen)) < 0) {
        sc_dbg("sendto failed: %s", strerror(errno));
        goto out;
    }

out:
    close(sockfd);
}

static size_t sc_retrieve_write(void *buffer, size_t size, size_t nmemb, void *stream)
{
    sc_res_file_t *f;

    if (stream == NULL) {
        sc_dbg("user data of stream is NULL");
        return -1;
    }

    f = (sc_res_file_t *)stream;
    if (f->fp == NULL) {
        f->fp = fopen(f->path, "wb");
        if (f->fp == NULL) {
            sc_dbg("fopen() failed: %s", f->path);
            return -1;
        }
    }

    return fwrite(buffer, size, nmemb, f->fp);
}

static int sc_retrieve_download(string_t *url, string_t *file)
{
    char url_buf[HTTP_SP_URL_LEN_MAX + 1];
    char file_buf[HTTP_SP_URL_LEN_MAX + HTTP_LOCAL_FILE_ROOT_MAX + 1];
    sc_res_file_t f;
    CURL *curl;
    CURLcode rc;
    int ret = 0;
    long resp_code;
    double speed;

    memcpy(url_buf, url->data, url->len);
    url_buf[url->len] = '\0';
    memcpy(file_buf, file->data, file->len);
    file_buf[file->len] = '\0';

    f.path = file_buf;
    f.fp = NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl == NULL) {
        sc_dbg("curl_easy_init() failed");
        goto out1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sc_retrieve_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &f);

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        sc_dbg("curl_easy_perform() failed: %s", curl_easy_strerror(rc));
        goto out3;
    }

    rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
    if (rc != CURLE_OK) {
        sc_dbg("curl_easy_getinfo() RESPONSE_CODE failed: %s", curl_easy_strerror(rc));
        goto out3;
    }
    if (resp_code != 200) {
        sc_dbg("HTTP download response code error: %ld", resp_code);
        goto out3;
    }

    rc = curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &speed);
    if (rc != CURLE_OK) {
        sc_dbg("curl_easy_getinfo() SPEED_DOWNLOAD failed: %s", curl_easy_strerror(rc));
        goto out3;
    }
    speed = speed / 1000;

    sc_print("Success download @ %.2fKB/s: %s", speed, file_buf);
    ret = 1;

out3:
    if (f.fp != NULL) {
        fclose(f.fp);
        f.fp = NULL;
        if (ret == 0) {
            /* 异常情况下的文件会被删除 */
            sc_dbg("Delete innormal file: %s", file_buf);
            remove(file_buf);
        }
    }
out2:
    curl_easy_cleanup(curl);
out1:
    curl_global_cleanup();
out:
    return ret;
}

static void sc_retrieve_process(string_t *url, string_t *file)
{
    int success = 0;

    sc_print("Inform  ---\n\tURL:  %*s\n\tFile: %*s",
                    (int)(url->len), url->data, (int)(file->len), file->data);
    sc_create_full_path(file, 0777);

    success = sc_retrieve_download(url, file);

    if (success) {
        sc_retrieve_ret_result(url, 1);
    } else {
        sc_dbg("download failed.");
        sc_retrieve_ret_result(url, 0);
    }
}

static int sc_retrieve_inform(string_t *url)
{
    string_t file_str;
    cache_rule_t *rule;
    char file_buf[HTTP_SP_URL_LEN_MAX + HTTP_LOCAL_FILE_ROOT_MAX];
    int ret;
    pid_t pid;

    rule = cache_rule_get_rule(g_sc_cache_rule_ctx, url);
    if (rule == NULL) {
        sc_dbg("Not find rule: %*s", (int)(url->len), url->data);
        return -1;
    }

    memcpy(file_buf, SC_WEB_SERVER_ROOT, SC_WEB_SERVER_ROOT_LEN);
    file_str.data = file_buf + SC_WEB_SERVER_ROOT_LEN;
    file_str.len = sizeof(file_buf) - SC_WEB_SERVER_ROOT_LEN;
    ret = cache_rule_url2local_file(url, rule, &file_str);
    if (ret != 0) {
        sc_dbg("Url to local file name failed: %*s", (int)(url->len), url->data);
        return -1;
    }

    if ((pid = fork()) < 0) {
        sc_dbg("Fork process to download failed: %*s", (int)(url->len), url->data);
        return -1;
    } else if (pid == 0) {
        /* 子进程 */
        file_str.data = file_buf;
        file_str.len += SC_WEB_SERVER_ROOT_LEN;
        sc_retrieve_process(url, &file_str);
        /* 子进程处理完毕后直接终止进程 */
        exit(0);
    } else {
        /* 父进程无任何操作 */
    }

    return 0;
}

static void sc_retrieve_handle(const int sockfd)
{
    int nrecv, success, ret;
    struct sockaddr sa;
    socklen_t salen;
    char buf[SC_SPM_SND_RCV_BUFLEN];
    string_t url;
    sc_res_info_t *ri;

    salen = sizeof(struct sockaddr);
    memset(&sa, 0, salen);
    memset(buf, 0, sizeof(buf));

    if ((nrecv = recvfrom(sockfd, buf, SC_SPM_SND_RCV_BUFLEN, 0, &sa, &salen)) < 0) {
        sc_dbg("recvfrom error: %s", strerror(errno));
        return;
    }

    if (nrecv >= SC_SPM_SND_RCV_BUFLEN || nrecv == 0) {
        sc_dbg("recvfrom %d", nrecv);
        return;
    }

    if (buf[0] == 'S' && buf[1] == ' ') {
        success = 1;
    } else if (buf[0] == 'F' && buf[1] == ' ') {
        success = 0;
    } else {
        sc_dbg("Warning message: %s", buf);
        return;
    }

    url.data = buf + 2;
    url.len = strlen(url.data);
    ri = sc_res_find_retrieving(&url);
    if (ri == NULL) {
        sc_dbg("BUG: URL not in retrieving list: %*s", (int)(url.len), url.data);
        return;
    }

    if (!success) {
        sc_dbg("Download failed, un-chain: %*s", (int)(url.len), url.data);
        goto un_chain;
    }

    ret = sc_res_record_url(&url);
    if (ret != 0) {
        sc_dbg("Record url failed: %*s", (int)(url.len), url.data);
    }

    ret = sc_spm_add_url(ri->sid, url.data);
    if (ret != 0) {
        sc_dbg("Add url failed: %*s", (int)(url.len), url.data);
        goto un_chain;
    }

    list_del_init(&ri->list);
    g_sc_res_retrieving_list.count--;
    list_add(&ri->list, &g_sc_res_stored_list.list);
    g_sc_res_stored_list.count++;

    return;

un_chain:
    if (ri != NULL) {
        list_del_init(&ri->list);
        g_sc_res_retrieving_list.count--;
        sc_res_free(ri);
    }

    return;
}

static int sc_load_local_resource()
{
    FILE *fp;
    char buf[HTTP_SP_URL_LEN_MAX + 5 + 1]; /* 多出 "@@@@+" 和'\0' */
    string_t url;
    sc_res_info_t *ri, *ri_next;

    fp = fopen(SC_WEB_SERVER_ROOT SC_RES_RECORD_FILE, "r");
    if (fp == NULL) {
        sc_dbg("Open file %s%s failed", SC_WEB_SERVER_ROOT, SC_RES_RECORD_FILE);
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strncmp(buf, "@@@@+", 5) != 0) {
            sc_dbg("Wrong format: %s", buf);
            continue;
        }

        url.data = buf + 5;
        url.len = strlen(url.data) - 2;
        url.data[url.len] = '\0';
        if (url.len == HTTP_SP_URL_LEN_MAX) {
            sc_dbg("URL too long: %*s", (int)(url.len), url.data);
            continue;
        }

        sc_res_load_url(&url);
    }

    fclose(fp);

    list_for_each_entry_safe(ri, ri_next, &g_sc_res_stored_list.list, list, sc_res_info_t) {
        /* 一次性通知所有stored列表中的url给设备 */
        if (sc_spm_add_url(0, ri->url_buf) != 0) {
            sc_dbg("Add url failed, un-chain from stored list: %s", ri->url_buf);
            list_del_init(&ri->list);
            g_sc_res_stored_list.count--;
            sc_res_free(ri);
        }
    }

    return 0;
}

static int sc_sock_init_server(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
    int fd;

    if ((fd = socket(addr->sa_family, type, 0)) < 0) {
        perror("Socket");
        return -1;
    }

    if (bind(fd, addr, alen) < 0) {
        perror("Bind");
        goto errout;
    }

    if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
        if (listen(fd, qlen) < 0) {
            perror("Listen");
            goto errout;
        }
    }

    return fd;

errout:
    close(fd);
    return -1;
}

static int sc_init_listen_sockfd()
{
    int sockfd;
    struct sockaddr_in sa;
    socklen_t salen;

    salen = sizeof(struct sockaddr_in);

    memset(&sa, 0, salen);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)HTTP_SP2C_PORT);
    sockfd = sc_sock_init_server(SOCK_DGRAM, (struct sockaddr *)&sa, salen, 0);
    if (sockfd < 0) {
        goto errout;
    }
    g_sc_spm_serve_sockfd = sockfd;

    memset(&sa, 0, salen);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)SC_RETRIEVE_HANDLE_PORT);
    sockfd = sc_sock_init_server(SOCK_DGRAM, (struct sockaddr *)&sa, salen, 0);
    if (sockfd < 0) {
        goto errout1;
    }
    g_sc_retrieve_handle_sockfd = sockfd;

    return 0;

errout1:
    close(g_sc_spm_serve_sockfd);
    g_sc_spm_serve_sockfd = -1;
errout:
    return -1;
}

static int sc_uninit_listen_sockfd()
{
    int err = 0;

    if (close(g_sc_spm_serve_sockfd) != 0) {
        sc_dbg("close() spm serve sockfd %d failed.", g_sc_spm_serve_sockfd);
        err = -1;
    }
    if (close(g_sc_retrieve_handle_sockfd) != 0) {
        sc_dbg("close() retrieve handle sockfd %d failed.", g_sc_retrieve_handle_sockfd);
        err = -1;
    }

    return err;
}

static int sc_exec_core_proc()
{
    fd_set work_read_fd_set;
    int ready, nready;

    while (1) {
        work_read_fd_set = g_sc_master_read_fd_set;

        ready = select(g_sc_max_read_fd + 1, &work_read_fd_set, NULL, NULL, NULL);  /* 阻塞在这里 */

        if (ready <= 0) {
            sc_dbg("select() failed.");
            return -1;
        }

        nready = 0;

        if (FD_ISSET(g_sc_spm_serve_sockfd, &work_read_fd_set)) {
            nready++;
            sc_spm_serve(g_sc_spm_serve_sockfd);
        }

        if (FD_ISSET(g_sc_retrieve_handle_sockfd, &work_read_fd_set)) {
            nready++;
            sc_retrieve_handle(g_sc_retrieve_handle_sockfd);
        }

        if (ready != nready) {
            sc_dbg("Error: select ready != process: %d:%d", ready, nready);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int err = 0;
    int rules_num;
    struct sockaddr_in sa;

    if (argc < 3) {
        printf("Usage: %s spm-ipaddr hot-cache-rule\n", argv[0]);
        return -1;
    }

    if (inet_pton(AF_INET, argv[1], &(sa.sin_addr)) != 1) {
        printf("%s is invalid IP address.\n", argv[1]);
        return -1;
    }
    strncat(g_sc_sp_module_ipaddr_str, argv[1], SC_IPADDR_STR_BUFLEN_MAX - 1);

    rules_num = cache_rule_load(argv[2], &g_sc_cache_rule_ctx);
    if (rules_num < 0) {
        printf("Load rules failed: %s\n", argv[2]);
    } else {
        printf("Loaded %d rules\n", rules_num);
    }

    /* TODO: 启动Nginx */
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        sc_dbg("Ignore SIGCHLD failed.");
        return -1;
    }

    err = sc_res_init(HTTP_SP_URL_MAX);
    if (err != 0) {
        sc_dbg("Resource initialize %d failed.", HTTP_SP_URL_MAX);
        return -1;
    }

    err = sc_load_local_resource();
    if (err != 0) {
        sc_dbg("Load local stored resource failed.");
    }

    err = sc_init_listen_sockfd();
    if (err != 0) {
        sc_print("Initialize listen socket fd failed.");
        return -1;
    }

    FD_ZERO(&g_sc_master_read_fd_set);
    FD_SET(g_sc_spm_serve_sockfd, &g_sc_master_read_fd_set); /* 添加监听端口到读事件集合 */
    FD_SET(g_sc_retrieve_handle_sockfd, &g_sc_master_read_fd_set); /* 添加监听端口到读事件集合 */
    g_sc_max_read_fd = MAX(g_sc_spm_serve_sockfd, g_sc_retrieve_handle_sockfd);

    err = sc_exec_core_proc();

    err = sc_uninit_listen_sockfd();
    if (err != 0) {
        sc_dbg("Uninitialize listen socket fd failed.");
    }

    return 0;
}


