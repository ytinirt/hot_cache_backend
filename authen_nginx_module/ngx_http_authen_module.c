#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_AUTHEN_REQUEST_BODY_MAX    256
#define NGX_HTTP_AUTHEN_BUF_MAX             256
#define NGX_HTTP_AUTHEN_PORT_DEFAULT        10001

typedef struct {
    ngx_str_t addr;
    ngx_int_t port;
} ngx_http_authen_conf_t;

static char *ngx_http_authen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_authen_handler(ngx_http_request_t *r);
static char *ngx_conf_set_authen_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_authen_create_loc_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_authen_commands[] = {
    {
        ngx_string("authen"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_authen,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },
    {
        ngx_string("authen_svr"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
        ngx_conf_set_authen_config,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },

    ngx_null_command,
};

static char *ngx_http_authen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_authen_handler;

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_authen_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_authen_create_loc_conf,
    NULL,
};

ngx_module_t ngx_http_authen_module = {
    NGX_MODULE_V1,
    &ngx_http_authen_module_ctx,
    ngx_http_authen_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING,
};

static char *ngx_conf_set_authen_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_authen_conf_t *authencf = conf;
    ngx_str_t *value = cf->args->elts;

    if (cf->args->nelts > 1) {
        authencf->addr = value[1];
        if (ngx_inet_addr(authencf->addr.data, authencf->addr.len) == INADDR_NONE) {
            return "Invalid: Authen IP address";
        }
    }
    if (cf->args->nelts > 2) {
        authencf->port = ngx_atoi(value[2].data, value[2].len);
        if (authencf->port == NGX_ERROR) {
            return "Invalid: Authen UDP port";
        }
    }

    return NGX_CONF_OK;
}

static void *ngx_http_authen_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_authen_conf_t *authencf;

    authencf = (ngx_http_authen_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_authen_conf_t));
    if (authencf == NULL) {
        return NULL;
    }

    authencf->addr.data = NULL;
    authencf->addr.len = 0;
    authencf->port = NGX_CONF_UNSET;

    return authencf;
}

static void ngx_http_authen_pass_do(const struct sockaddr_in *sa, const char *address)
{
    int nsend, nrecv, msglen;
    int sockfd;
    socklen_t salen;
    char buf[NGX_HTTP_AUTHEN_BUF_MAX];

    salen = sizeof(struct sockaddr_in);
    sockfd = ngx_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        ngx_log_stderr(NGX_OK, "socket() failed");
        return;
    }

    memset(buf, 0, sizeof(buf));
    msglen = sprintf(buf, "PASS %s", address);
    nsend = sendto(sockfd, buf, msglen, 0, (struct sockaddr *)sa, salen);
    if (nsend != msglen) {
        ngx_log_stderr(NGX_OK, "sendto() failed: %d", nsend);
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    nrecv = recvfrom(sockfd, buf, NGX_HTTP_AUTHEN_BUF_MAX - 1, 0, NULL, NULL);
    if (nrecv < 0) {
        ngx_log_stderr(NGX_OK, "recvfrom() failed: %d", nrecv);
        goto out;
    }
    if (strncmp(buf, "OK", 2) != 0) {
        ngx_log_stderr(NGX_OK, "authen failed: %s", buf);
        goto out;
    }

out:
    ngx_close_socket(sockfd);

    return;
}

static void ngx_http_authen_pass(ngx_http_authen_conf_t *cf, ngx_str_t *addr)
{
    pid_t pid;
    char address[64];
    struct sockaddr_in sa;
    socklen_t salen;

    if (cf->addr.len == 0 || cf->addr.data == NULL) {
        ngx_log_stderr(NGX_OK, "Missing Authen IP address");
        return;
    }

    if (addr->len >= sizeof(address)) {
        ngx_log_stderr(NGX_OK, "%V too long", addr);
        return;
    }
    ngx_memcpy(address, (char *)addr->data, addr->len);
    address[addr->len] = '\0';

    salen = sizeof(sa);
    ngx_memzero(&sa, salen);
    sa.sin_family = AF_INET;
    if (cf->port == NGX_CONF_UNSET) {
        sa.sin_port = htons((uint16_t)NGX_HTTP_AUTHEN_PORT_DEFAULT);
    } else {
        sa.sin_port = htons((uint16_t)cf->port);
    }
    sa.sin_addr.s_addr = ngx_inet_addr(cf->addr.data, cf->addr.len);

    if ((pid = fork()) < 0) {
        ngx_log_stderr(NGX_OK, "Fork() failed.");
        return;
    } else if (pid == 0) {
        /* 子进程，通知设备开启认证 */
        ngx_http_authen_pass_do(&sa, address);
        exit(0);
    } else {
        /* 父进程无操作 */
    }

    return;
}

static void ngx_http_authen_post_handler(ngx_http_request_t *r)
{
    ngx_http_authen_conf_t *authencf;

    authencf = (ngx_http_authen_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_authen_module);

    ngx_log_stderr(NGX_OK, "Authen request from: %V", &(r->connection->addr_text));
    ngx_http_authen_pass(authencf, &(r->connection->addr_text));

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));

    return;
}

static ngx_int_t ngx_http_authen_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    if (!(r->method & NGX_HTTP_POST)) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if (r->headers_in.content_length_n > NGX_HTTP_AUTHEN_REQUEST_BODY_MAX) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_authen_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

