
#include "cache_rule.h"

int cache_rule_str_is_equal(string_t *str1, string_t *str2)
{
    if (str1 == NULL || str2 == NULL) {
        return 0;
    }

    if (str1->len != 0 && str1->data == NULL) {
        return 0;
    }
    if (str2->len != 0 && str2->data == NULL) {
        return 0;
    }

    return string_is_equal(str1, str2);
}

string_t same_as_host = string_init("SAME_AS");
string_t default_host = string_init("default");
static cache_host_t *cache_rule_load_host(cache_rule_ctx_t *ctx, char *host_name)
{
    cache_host_t *h = NULL;
    char *p, *pp;
    string_t para = NULL_STR, name = NULL_STR;
    int same_as = 0;

    for (p = host_name; *p != '\0'; ) {
        if (*p == ' ') {
            p++;
            continue;
        }
        for (pp = p; *pp != ' ' && *pp != '\0'; pp++) {
            (void)0;
        }

        para.data = p;
        para.len = pp - p;

        /* XXX: 要处理配置参数，从这里开始 */
        if (string_is_equal(&same_as_host, &para)) {
            same_as = 1;
            p = pp;
            continue;
        }

        name.len = para.len;
        name.data = para.data;
        p = pp;
        continue;
    }

    if (name.len == 0 || name.len > CACHE_HOST_NAME_MAX_LEN) {
        return NULL;
    }

    if (string_is_equal(&default_host, &name)) {
        h = &ctx->hosts.default_host;
        if (h->host.data != NULL) {
            /* 已经配置过默认host */
            return NULL;
        }
        if (symtab_add(&ctx->symtab, &name, &h->host) != 0) {
            return NULL;
        }
        h->flags = CACHE_HOST_DEFAULT;
    } else {
        h = cache_host_new(&ctx->hosts, &name);
        if ((h != NULL) && (same_as != 0)) {
            h->flags = CACHE_HOST_SAME_AS;
        }
    }

    return h;
}

string_t token_upstream = string_init("UPSTREAM");
string_t token_spwrite = string_init("SPWRITE");
string_t token_cache_sp = string_init("CACHE_SP");
string_t token_redirect_para = string_init("REDIRECT_PARA");
string_t token_dbg_print = string_init("DBG_PRINT");
static int cache_rule_load_action_arg(cache_rule_t *r, string_t *arg)
{
    if (string_is_equal(&token_upstream, arg)) {
        r->action_flags |= CACHE_ACTION_UPSTREAM;
        return 0;
    }

    if (string_is_equal(&token_spwrite, arg)) {
        r->action_flags |= CACHE_ACTION_SPWRITE;
        return 0;
    }

    if (string_is_equal(&token_cache_sp, arg)) {
        r->action_flags |= CACHE_ACTION_CACHE_SP;
        return 0;
    }

    if (string_is_equal(&token_redirect_para, arg)) {
        r->action_flags |= CACHE_ACTION_REDIRECT_PARA;
        return 0;
    }

    if (string_is_equal(&token_dbg_print, arg)) {
        r->action_flags |= CACHE_ACTION_DBG_PRINT;
        return 0;
    }

    return 0;
}

/* 解析rule中操作action信息 */
static int cache_rule_load_action_rule(cache_rule_t *r, string_t *rule)
{
    char *p, *pp;
    string_t arg;

    for (p = rule->data; p < rule->data + rule->len; ) {
        if (*p == ' ') {
            p++;
            continue;
        }
        for (pp = p; *pp != ' ' && pp < rule->data + rule->len; pp++) {
            (void)0;
        }

        arg.data = p;
        arg.len = (size_t)pp - (size_t)p;

        if (cache_rule_load_action_arg(r, &arg) != 0) {
            return -1;
        }

        p = pp + 1;
    }

    if (r->action_flags & CACHE_ACTION_DBG_PRINT) {
        /* debug打印时，忽略其它所有操作action。 */
        r->action_flags = CACHE_ACTION_DBG_PRINT;
        return 0;
    }

    /* 检查操作是否符合要求 */
    if (!(r->action_flags & (CACHE_ACTION_SPWRITE | CACHE_ACTION_UPSTREAM))) {
        return -1;
    }
    /* 目前默认关闭连接 */
    r->action_flags |= CACHE_ACTION_CON_CLOSE;

    return 0;
}

string_t token_key_all_slash = string_init("KEY_SALL");
string_t token_key_file = string_init("KEY_FILE");
string_t token_key_para = string_init("KEY_PARA");
static int _cache_rule_load_key_arg(cache_rule_ctx_t *ctx, cache_rule_t *r, string_t *arg)
{
    int index = 0, i;
    char *p;
    string_t *kp;
    string_t val;

    if (string_is_equal(&token_key_para, arg)) {
        r->key_flags |= CACHE_KEY_PARA;
        return 0;
    }

    if (strncmp(arg->data, "PARA=", 5) == 0) {
        if (!(r->key_flags & CACHE_KEY_PARA)) {
            /* 在KEY_PARA之前的所有PARA值都是错误的 */
            goto err_out;
        }
        if (arg->len <= 5) {
            goto err_out;
        }
        for (i = 0; i < CACHE_RULE_PARA_MAX_COUNT; i++) {
            /* 只会有前CACHE_RULE_PARA_MAX_COUNT个生效 */
            kp = r->key_para + i;
            if (kp->data != NULL) {
                continue;
            }
            val.data = arg->data + 5;
            val.len = arg->len - 5;
            if (symtab_add(&ctx->symtab, &val, kp) != 0) {
                goto err_out;
            }
            break;
        }
        return 0;
    }

    if (string_is_equal(&token_key_file, arg)) {
        r->key_flags |= CACHE_KEY_FILE;
        return 0;
    }

    if (strncmp(arg->data, "KEY_S", 5) != 0) {
        goto err_out;
    }

    if (string_is_equal(&token_key_all_slash, arg)) {
        r->key_flags |= CACHE_KEY_ALL_SLASH;
        return 0;
    }

    if (arg->len >= token_key_all_slash.len) {
        /* XXX: 目前斜杠的有效索引最多只有两位，KEY_Sxx */
        goto err_out;
    }

    for (p = arg->data + 5; p < arg->data + arg->len; p++) {
        if (!isdigit(*p)) {
            goto err_out;
        }
        index = (index * 10) + (*p - '0');
    }
    if (index >= CACHE_RULE_SLASH_MAX_COUNT) {
        goto err_out;
    }

    r->key_flags |= (0x1 << index);

    return 0;

err_out:
    return -1;
}

static int cache_rule_load_key_arg(cache_rule_ctx_t *ctx, cache_rule_t *r, string_t *arg)
{
    string_t val;

    if ((strncmp(arg->data, "KEY_", 4) == 0)
        || (strncmp(arg->data, "PARA=", 5) == 0)) {
        return _cache_rule_load_key_arg(ctx, r, arg);
    }

    if (strncmp(arg->data, "LS=.", 4) == 0) {
        /* 当关注URL中参数作为key值时，可以选择指定保存到本地的文件拓展名 */
        if (!(r->key_flags & CACHE_KEY_PARA)) {
            /* 不能随便指定本地文件拓展名 */
            return -1;
        }
        if (arg->len <= 4) {
            return -1;
        }
        val.data = arg->data + 3;
        val.len = arg->len - 3;
        if (symtab_add(&ctx->symtab, &val, &r->local_suffix) != 0) {
            return -1;
        }
        return 0;
    }

    return 0;
}

/* 解析rule中生成key值信息 */
static int cache_rule_load_key_rule(cache_rule_ctx_t *ctx, cache_rule_t *r, string_t *rule)
{
    char *p, *pp;
    string_t arg;

    for (p = rule->data; p < rule->data + rule->len; ) {
        if (*p == ' ') {
            p++;
            continue;
        }
        for (pp = p; *pp != ' ' && pp < rule->data + rule->len; pp++) {
            (void)0;
        }

        arg.data = p;
        arg.len = (size_t)pp - (size_t)p;

        if (cache_rule_load_key_arg(ctx, r, &arg) != 0) {
            return -1;
        }

        p = pp + 1;
    }

    /* 检查key值生成方式是否符合要求 */
    if (r->key_flags == 0) {
        return -1;
    }

    return 0;
}

/*
 * 返回值-1表示不是匹配相关的配置；
 *        0表示相同项已经配置过，此次仅更新了内容，不需再累加有效的字符串数量值；
 *        1表示新的配置项，需要累加字符串的数量值。
 */
static int cache_rule_parse_match_arg(string_t *arg,
                                      string_t slash_and_suffix[CACHE_RULE_MATCH_STR_COUNT],
                                      int *end_index)
{
    int ret = -1, index = 0;
    string_t *dst_ptr, src = NULL_STR;
    char *p;

    if (strncmp(arg->data, "S=", 2) == 0) {
        dst_ptr = &slash_and_suffix[CACHE_RULE_SUFFIX_INDEX];
        index = CACHE_RULE_SUFFIX_INDEX;
        if (arg->len <= 2) {
            /* 不携带后缀 */
            src.len = BTRIE_NO_VALUE_MAGIC_LEN;
            src.data = NULL;
        } else {
            src.data = arg->data + 2;
            src.len = arg->len - 2;
        }
        ret = 0;
    } else if ((strncmp(arg->data, "T=/", 3) == 0) && (arg->len > 3)) {
        dst_ptr = &slash_and_suffix[CACHE_RULE_TAIL_SLASH_INDEX];
        index = CACHE_RULE_TAIL_SLASH_INDEX;
        src.data = arg->data + 2;
        src.len = arg->len - 2;
        ret = 0;
    } else {
        for (p = arg->data; (p < arg->data + arg->len) && isdigit(*p); p++) {
            index = index * 10 + ((*p) - '0');
        }
        if ((p == arg->data)
                || (*p != '=')
                || (p > arg->data + 2) /* 目前斜杠的索引值最多两位 */
                || (index >= CACHE_RULE_SLASH_MAX_COUNT)) {
            goto out;
        }
        dst_ptr = &slash_and_suffix[index];
        src.data = p + 1;
        src.len = arg->data + arg->len - src.data;
        if (src.len <= 0) {
            /* 形如 RULE 1=/hehe 2= S=.xixi，表示只能有slash1，不能有slash2 */
            src.len = BTRIE_NO_VALUE_MAGIC_LEN;
            src.data = NULL;
        } else if (src.data[0] != '/' || src.len <= 1) {
            goto out;
        }
        ret = 0;
    }

    if (ret != -1) {
        if (dst_ptr->len == 0) {
            /* 新的配置项，需要增加btrie node */
            ret = 1;
        } else {
            /* 再次配置，不需要增加btrie node */
            ret = 0;
        }

        if (*end_index < index) {
            *end_index = index;
        }

        dst_ptr->data = src.data;
        dst_ptr->len = src.len;
    }

out:
    return ret;
}

/*
 * 初步消化rule中匹配信息，并判断有效性
 * 注意: 成功时返回有效的字符串数量，值大于0；
 *       失败时返回0或-1，调用者不需要区分0和-1的区别。
 */
static int cache_rule_parse_match_rule(string_t *rule,
                                       string_t slash_and_suffix[CACHE_RULE_MATCH_STR_COUNT],
                                       int *end_index)
{
    char *p, *pp;
    int count = 0;
    string_t arg;

    for (p = rule->data; p < rule->data + rule->len; ) {
        if (*p == ' ') {
            p++;
            continue;
        }
        for (pp = p; *pp != ' ' && pp < rule->data + rule->len; pp++) {
            (void)0;
        }

        arg.data = p;
        arg.len = (size_t)pp - (size_t)p;

        if (cache_rule_parse_match_arg(&arg, slash_and_suffix, end_index) == 1) {
            count++;
        }

        p = pp + 1;
    }

    return count;
}

/* 解析rule中匹配信息 */
static btrie_node_t *cache_rule_load_match_rule(cache_rule_ctx_t *ctx,
                                                cache_host_t *h,
                                                string_t *rule)
{
    int end_index = -1, valids;
    string_t slash_and_suffix[CACHE_RULE_MATCH_STR_COUNT]; /* 存放rule中匹配斜杠、尾斜杠和后缀 */
    btrie_node_t *ret = NULL;

    memset(slash_and_suffix, 0, sizeof(slash_and_suffix));
    valids = cache_rule_parse_match_rule(rule, slash_and_suffix, &end_index);
    if (valids <= 0) {
        NOTICE();
        return NULL;
    }

    ret = btrie_insert(&ctx->btrie,
                       &h->rule_root,
                       CACHE_RULE_MATCH_STR_COUNT,
                       slash_and_suffix,
                       valids,
                       end_index);

    return ret;
}

static int cache_rule_load_rule_do(cache_rule_ctx_t *ctx,
                                   cache_host_t *h,
                                   cache_rule_t *r,
                                   string_t *rule)
{
    btrie_node_t *rule_attach_node;
    int ret;

    /* 首先，解析rule中操作action信息 */
    ret = cache_rule_load_action_rule(r, rule);
    if (ret != 0) {
        NOTICE();
        return -1;
    }

    /* 然后，解析rule中生成key值信息 */
    ret = cache_rule_load_key_rule(ctx, r, rule);
    if (ret != 0) {
        NOTICE();
        return -1;
    }

    /* 最后，解析rule中匹配信息 */
    rule_attach_node = cache_rule_load_match_rule(ctx, h, rule);
    if (rule_attach_node == NULL) {
        /* 添加匹配信息失败 */
        return -1;
    }

    rule_attach_node->data = r;

    return 0;
}

static cache_rule_t *cache_rule_alloc(cache_rule_ctx_t *ctx)
{
    cache_rule_t *rule;

    if (ctx->free_num == 0) {
        return NULL;
    }

    rule = ctx->free_list;
    ctx->free_list = (cache_rule_t *)(rule->action_flags);
    ctx->free_num--;

    memset(rule, 0, sizeof(cache_rule_t));

    return rule;
}

static void cache_rule_free(cache_rule_ctx_t *ctx, cache_rule_t *r)
{
    if (r == NULL) {
        return;
    }

    r->action_flags = (unsigned long)ctx->free_list;
    ctx->free_list = r;
    ctx->free_num++;

    return;
}

static int cache_rule_load_rule(cache_rule_ctx_t *ctx, cache_host_t *h, char *rule_buf)
{
    string_t rule;
    cache_rule_t *r;

    rule.data = rule_buf;
    rule.len= strlen(rule_buf);
    if (rule.len == 0 || rule.len > CACHE_RULE_LINE_MAX_LEN) {
        NOTICE();
        return -1;
    }

    r = cache_rule_alloc(ctx);
    if (r == NULL) {
        NOTICE();
        return -1;
    }

    if (cache_rule_load_rule_do(ctx, h, r, &rule) != 0) {
        goto err_out;
    }

    /* 所有处理都正常后，该rule符合规定，host的规则数量才增加 */
    h->rule_num++;

    return 0;

err_out:
    cache_rule_free(ctx, r);
    return -1;
}

/*
 * 负责所有资源的分配和初始化
 */
static cache_rule_ctx_t *cache_rule_init()
{
    int ret, i;
    size_t total_alloc = 0, alloc_size;
    char *mem_symtab;
    cache_rule_ctx_t *ctx;
    cache_rule_t *mem_rule, *r;

    alloc_size = sizeof(cache_rule_ctx_t);
    ctx = (cache_rule_ctx_t *)malloc(alloc_size);
    if (ctx == NULL) {
        goto err_out;
    }
    memset(ctx, 0, alloc_size);
    total_alloc += alloc_size;

    ctx->symtab.capacity = CACHE_RULE_SYMTAB_LEN;
    alloc_size = CACHE_RULE_SYMTAB_LEN;
    mem_symtab = malloc(alloc_size);
    if (mem_symtab == NULL) {
        goto err_out1;
    }
    memset(mem_symtab, 0, alloc_size);
    ctx->symtab.mem_base = mem_symtab;
    ctx->symtab.free_start = ctx->symtab.mem_base;
    total_alloc += alloc_size;

    ctx->btrie.symtab = &ctx->symtab;
    ctx->btrie.node_capacity = CACHE_RULE_BTRIE_NODE_MAX_COUNT;
    ret = btrie_init(&ctx->btrie, &alloc_size);
    if (ret != 0) {
        goto err_out2;
    }
    total_alloc += alloc_size;

    ctx->hosts.symtab = &ctx->symtab;
    ctx->hosts.btrie = &ctx->btrie;
    ctx->hosts.host_capacity = CACHE_HOST_CFG_MAX_COUNT;
    ctx->hosts.hte_capacity = CACHE_HOST_HTE_MAX_COUNT;
    ret = cache_host_init(&ctx->hosts, &alloc_size);
    if (ret != 0) {
        goto err_out3;
    }
    total_alloc += alloc_size;

    alloc_size = sizeof(cache_rule_t) * CACHE_RULE_MAX_COUNT;
    mem_rule = (cache_rule_t *)malloc(alloc_size);
    if (mem_rule == NULL) {
        goto err_out4;
    }
    memset(mem_rule, 0, alloc_size);
    ctx->mem_base = mem_rule;
    ctx->free_num = CACHE_RULE_MAX_COUNT;
    ctx->capacity = CACHE_RULE_MAX_COUNT;
    ctx->free_list = &ctx->mem_base[0];
    for (i = 1; i < ctx->free_num; i++) {
        r = &ctx->mem_base[i];
        r->action_flags = (unsigned long)ctx->free_list;
        ctx->free_list = r;
    }
    total_alloc += alloc_size;

    ctx->total_alloc_mem = total_alloc;

    return ctx;

err_out4:
    cache_host_uninit(&ctx->hosts);
err_out3:
    btrie_uninit(&ctx->btrie);
err_out2:
    free(mem_symtab);
err_out1:
    free(ctx);
err_out:
    return NULL;
}

static void cache_rule_uninit(cache_rule_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->mem_base != NULL) {
        free(ctx->mem_base);
        ctx->mem_base = NULL;
    }

    cache_host_uninit(&ctx->hosts);

    btrie_uninit(&ctx->btrie);

    if (ctx->symtab.mem_base != NULL) {
        free(ctx->symtab.mem_base);
        ctx->symtab.mem_base = NULL;
    }

    free(ctx);

    return;
}

#define CACHE_RULE_READLINE_LEN 1024
int cache_rule_load(const char *rule_file, cache_rule_ctx_t **context)
{
    FILE *fp;
    char buf[CACHE_RULE_READLINE_LEN];
    int readlen;
    char *end;
    cache_host_t *h, *prev_h;
    int rule_loaded = 0;
    cache_rule_ctx_t *ctx;

    if (context == NULL || rule_file == NULL || strstr(rule_file, ".rule") == NULL) {
        goto err_out;
    }

    ctx = cache_rule_init();
    if (ctx == NULL) {
        /* 资源初始化失败 */
        goto err_out;
    }
    fp = fopen(rule_file, "r");
    if (fp == NULL) {
        goto err_out1;
    }

    h = NULL;
    prev_h = NULL;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        readlen = strlen(buf);
        /* 干掉结尾的"\r\n"或者'\n' */
        end = buf + readlen - 1;
        if (*end == '\n') {
            if (*(end - 1) == '\r') {
                end--;
            }
            *end = '\0';
        } else {
            /* 行超过buffer长度 */
            h = NULL;
            prev_h = NULL;
            continue;
        }

        if (strncmp(buf, "HOST ", 5) == 0) {
            h = cache_rule_load_host(ctx, (buf + 5));
            if (h == NULL) {
                /* host已经用完或者出现其它错误，停止加载规则 */
                NOTICE();
                break;
            }
            if (h->flags & CACHE_HOST_SAME_AS) {
                /* 本host是前面host的镜像 */
                if (prev_h == NULL) {
                    NOTICE();
                    break;
                }
                h->same_as = prev_h;
                h->rule_root = prev_h->rule_root;
            } else {
                /* 普通host */
                prev_h = h;
            }
        } else if (strncmp(buf, "RULE ", 5) == 0) {
            if ((h == NULL) || (h->flags & CACHE_HOST_SAME_AS)) {
                h = NULL;
                prev_h = NULL;
                continue;
            }
            if (cache_rule_load_rule(ctx, h, buf + 5) == 0) {
                rule_loaded++;
            }
        } else {
            h = NULL;
            prev_h = NULL;
            continue;
        }
    }

    fclose(fp);
    *context = ctx;

    return rule_loaded;

err_out1:
    cache_rule_uninit(ctx);
err_out:
    return -1;
}

static int cache_rule_parse_url(string_t *url, cache_rule_url_part_t *part)
{
    int i, s;

    memset(part, 0, sizeof(cache_rule_url_part_t));

    part->host.data = url->data;
    s = 0;

    for (i = 0; i < url->len; i++) {
        if (url->data[i] == '/') {
            part->tail_slash.data = url->data + i;

            if (s > CACHE_RULE_SLASH_MAX_COUNT) {
                s++;
                continue;
            } else if (s == CACHE_RULE_SLASH_MAX_COUNT) {
                part->slash[s-1].len = url->data + i - part->slash[s-1].data;
                s++;
                continue;
            }

            part->slash[s].data = url->data + i;
            if (s == 0) {
                part->host.len = i;
            } else {
                part->slash[s-1].len = part->slash[s].data - part->slash[s-1].data;
            }
            s++;
        } else if (url->data[i] == '.') {
            part->suffix.data = url->data + i;
        } else if (url->data[i] == CACHE_RULE_PARA_TOKEN) {
            /* 一旦遇到参数符号，则结束url的walk，因此参数中'.'不会造成困扰 */
            part->para.data = url->data + i;
            part->para.len = url->len - i;
            break; /* 解析完毕 */
        }
    }

    if (s == 0) {
        return -1;
    }

    if (s <= CACHE_RULE_SLASH_MAX_COUNT) {
        if (part->para.data == NULL) {
            part->slash[s-1].len = url->data + url->len - part->slash[s-1].data;
        } else {
            part->slash[s-1].len = part->para.data - part->slash[s-1].data;
        }
    }

    if (part->para.data == NULL) {
        part->tail_slash.len = url->data + url->len - part->tail_slash.data;
    } else {
        part->tail_slash.len = part->para.data - part->tail_slash.data;
    }

    if (part->slash[0].len == 0) {
        /* 192.168.1.1/ */
        return -1;
    }

    if (part->suffix.data != NULL) {
        if (part->suffix.data < part->tail_slash.data
             || part->suffix.data > part->tail_slash.data + part->tail_slash.len) {
            /*
             * 针对这种情况: 
             * 192.168.1.1/he.he/xixi?val=1
             * 或者 192.168.1.1/hehe/xixi?val=1.2
             * 纠正suffix为NULL_STR.
             */
            part->suffix.len = 0;
            part->suffix.data = NULL;
        } else {
            part->suffix.len = part->tail_slash.data + part->tail_slash.len - part->suffix.data;
        }
    }

    return 0;
}

static cache_rule_t *cache_rule_find(cache_host_t *h, cache_rule_url_part_t *part)
{
    cache_rule_t *ret;

    /* part中slash, tail_slash和suffix是连续的，可以避免数据copy，直接传递 */
    ret = btrie_find(h->rule_root, CACHE_RULE_MATCH_STR_COUNT, (string_t *)(&part->slash));

    return ret;
}

cache_rule_t *cache_rule_get_rule(cache_rule_ctx_t *ctx, string_t *url)
{
    cache_rule_url_part_t part;
    cache_host_t *h;
    cache_rule_t *r;

    if (ctx == NULL || url == NULL || url->data == NULL || url->len == 0) {
        return NULL;
    }

    if (cache_rule_parse_url(url, &part) != 0) {
        return NULL;
    }

    h = cache_host_find(&ctx->hosts, &part.host);
    if (h == NULL) {
        if (ctx->hosts.default_host.host.data != NULL) {
            /* 默认host有效，指向它 */
            h = &ctx->hosts.default_host;
        } else {
            return NULL;
        }
    }

    r = cache_rule_find(h, &part);

    return r;
}

static void cache_rule_parse_para(string_t *para, string_t key[], string_t para_and_val[])
{
    int i, j;
    string_t *ks;
    char *p, *q;
    char tmp;

    /* 临时将para的结尾改成'\0'，确保strstr()能正确操作 */
    tmp = para->data[para->len];
    para->data[para->len] = '\0';

    for (i = 0, j = 0; i < CACHE_RULE_PARA_MAX_COUNT; i++) {
        if (key[i].data != NULL) {
            ks = &key[i];
        } else {
            continue;
        }

        p = strstr(para->data, ks->data);
        if (p == NULL) {
            continue;
        }
        q = p - 1;
        if (*q != '?' && *q != '&') {
            continue;
        }
        q = p + ks->len;
        if (*q != '=') {
            continue;
        }
        /* p即是关心参数的开始，q即是关心参数的结尾 */
        q = strchr(p, '&');
        if (q == NULL || q > (para->data + para->len)) {
            q = para->data + para->len;
        }
        para_and_val[j].data = p;
        para_and_val[j].len = q - p;
        j++;
    }

    para->data[para->len] = tmp;
}

int cache_rule_url2local_key(string_t *url, cache_rule_t *rule, string_t *key)
{
    int s, i, first_para;
    cache_rule_url_part_t part;
    string_t para_and_val[CACHE_RULE_PARA_MAX_COUNT];
    char *curr;
    int need_key_file = 0;

    if (url == NULL || rule == NULL || key == NULL) {
        return -1;
    }
    if (url->data == NULL || url->len == 0 || key->data == NULL || key->len == 0) {
        return -1;
    }

    if (cache_rule_parse_url(url, &part) != 0) {
        return -1;
    }
    /* key不包括host */
    if (key->len <= url->len - part.host.len) {
        return -1;
    }

    if (rule->key_flags & CACHE_KEY_FILE) {
        /* 当置了KEY_FILE时，可能需要显示的执行记录文件名(末尾斜杠内容)到key中 */
        need_key_file = 1;
    }

    memset(key->data, 0, key->len);
    curr = key->data;
    for (s = 0; s < CACHE_RULE_SLASH_MAX_COUNT; s++) {
        /* 如果要求s3后面的内容做key，但part中s3没有，则key中不会有s3。 */
        if ((rule->key_flags & (0x1 << s)) && (part.slash[s].data != NULL)) {
            memcpy(curr, part.slash[s].data, part.slash[s].len);
            curr = curr + part.slash[s].len;
            if (need_key_file
                 && (part.slash[s].data == part.tail_slash.data)) {
                /* 文件名(末尾斜杠内容)已经记录到key中，不需要再记录 */
                need_key_file = 0;
            }
        }
    }

    if (need_key_file) {
        memcpy(curr, part.tail_slash.data, part.tail_slash.len);
        curr = curr + part.tail_slash.len;
    }

    if ((rule->key_flags & CACHE_KEY_PARA) && (part.para.data != NULL)) {
        first_para = 1;
        memset(para_and_val, 0, sizeof(para_and_val));
        /* para不是必须，所以不需判断结果 */
        cache_rule_parse_para(&part.para, rule->key_para, para_and_val);
        for (i = 0; i < CACHE_RULE_PARA_MAX_COUNT; i++) {
            if (para_and_val[i].data != NULL) {
                if (first_para) {
                    first_para = 0;
                    *curr = '?';
                } else {
                    *curr = '&';
                }
                curr++;
                memcpy(curr, para_and_val[i].data, para_and_val[i].len);
                curr = curr + para_and_val[i].len;
            }
        }
    }

    key->len = curr - key->data;

    return 0;
}

static void cache_rule_url2local_file_trans(string_t *key)
{
    int i;

    /* 跳过第一个字符'/' */
    for (i = 1; i < key->len; i++) {
        if (key->data[i] == '/'
                || key->data[i] == CACHE_RULE_PARA_TOKEN) {
            key->data[i] = '_';
        }
    }
}

int cache_rule_url2local_file(string_t *url, cache_rule_t *rule, string_t *file)
{
    int i, hostlen;
    string_t key;
    char *curr;

    if (url == NULL || rule == NULL || file == NULL) {
        return -1;
    }
    if (url->data == NULL || url->len == 0 || file->data == NULL || file->len == 0) {
        return -1;
    }
    /* 预留后缀的位置 */
    if (file->len <= url->len + rule->local_suffix.len) {
        return -1;
    }

    memset(file->data, 0, file->len);
    for (i = 0; i < url->len; i++) {
        if (url->data[i] == '/') {
            break;
        }
        if (url->data[i] == ':') {
            file->data[i] = '_';
        } else {
            file->data[i] = url->data[i];
        }
    }
    hostlen = i;
    key.data = file->data + hostlen;
    key.len = file->len - hostlen;
    if (cache_rule_url2local_key(url, rule, &key) != 0) {
        return -1;
    }
    cache_rule_url2local_file_trans(&key);
    curr = key.data + key.len;
    if (rule->local_suffix.data != NULL) {
        memcpy(curr, rule->local_suffix.data, rule->local_suffix.len);
        curr = curr + rule->local_suffix.len;
    }

    file->len = curr - file->data;

    return 0;
}

void cache_rule_walk_host(cache_rule_ctx_t *ctx, cache_host_walk_func_t func)
{
    if (ctx == NULL || func == NULL) {
        return;
    }

    cache_host_walk(&ctx->hosts, func);

    return;
}

int cache_rule_hit_host(cache_rule_ctx_t *ctx, string_t *host)
{
    if (ctx == NULL || host == NULL || host->len == 0 || host->data == NULL) {
        return 0;
    }

    return cache_host_hit(&ctx->hosts, host);
}

void cache_rule_get_stats(cache_rule_ctx_t *ctx, cache_rule_stats_t *stats)
{
    if (ctx == NULL || stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(cache_rule_stats_t));
    stats->mem_total = ctx->total_alloc_mem;
    stats->host_capacity = ctx->hosts.host_capacity;
    stats->host_in_use = ctx->hosts.host_capacity - ctx->hosts.host_free_num;
    if (ctx->hosts.default_host.host.data != NULL) {
        stats->host_default_exist = 1;
    }
    stats->rule_capacity = ctx->capacity;
    stats->rule_in_use = ctx->capacity - ctx->free_num;
    stats->symtab_limit = ctx->symtab.capacity;
    stats->symtab_used = ctx->symtab.free_start - ctx->symtab.mem_base;
    stats->btrie_node_capacity = ctx->btrie.node_capacity;
    stats->btrie_node_in_use = ctx->btrie.node_used_count;
    stats->host_hte_capacity = ctx->hosts.hte_capacity;
    stats->host_hte_in_use = ctx->hosts.hte_capacity - ctx->hosts.hte_free_num;
    return;
}

void cache_rule_dump_host_hash(cache_rule_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    cache_host_dump_hash(&ctx->hosts);
}

void cache_rule_dump_symtab(cache_rule_ctx_t *ctx)
{
    int cnt;
    char *p;
    symtab_ctx_t *symtab;

    if (ctx == NULL) {
        return;
    }

    symtab = &ctx->symtab;
    if (symtab->mem_base == NULL || symtab->free_start == NULL) {
        return;
    }

    printf("====== SYMBOL TABLE ======\n");
    cnt = 0;
    for (p = symtab->mem_base; p < symtab->free_start; p++, cnt++) {
        if ((cnt != 0) && ((cnt % 64) == 0)) {
            printf("\n");
        }
        if (*p == '\0') {
            printf(" ");
        } else {
            printf("%c", *p);
        }
    }
    if ((cnt % 64) != 0) {
        printf("\n");
    }
    printf("==========================\n");

    return;
}

