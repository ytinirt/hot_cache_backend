
#include "cache_rule.h"

/* ��������(���)����Country Code */
#define CC_cn   0x636e
#define CC_us   0x7573
#define CC_uk   0x756b
#define CC_kr   0x6b72
#define CC_jp   0x6a70
#define CC_eu   0x6575
#define CC_fr   0x6672
#define CC_hk   0x686b
#define CC_tw   0x7477
#define CC_io   0x696f
#define CC_it   0x6974
#define CC_mo   0x6d6f
/* ��������(���)����Generic Code */
#define GC_com  0x636f6d00
#define GC_net  0x6e657400
#define GC_org  0x6f726700
#define GC_gov  0x676f7600
#define GC_edu  0x65647500
#define GC_biz  0x62697a00

string_t host_wildcard = string_init("*");
/*
 * ���host��label�������������Ϳ��ܴ��ڵ�һ��generic�����ϲ���һ��label
 * �����label������2���label_count >= 2.
 */
static inline int cache_host_parse_deep(string_t label[], int label_count)
{
    int i, ret = -1;
    uint16_t country_code = 0;
    uint32_t generic_code = 0;
    char *p_cc, *p_gc;
    int need_check = 0, need_merge = 0;

    /*
     * ���ȣ�������������label[0]��
     * XXX: ֻ�е����������ǹ�������ʱ���ſ�����Ҫ�ϲ�label[0]��label[1]��
     * TODO: �Ƿ����еĹ�����������2�ֽڳ��ȣ����������Ը��ݳ��Ⱦ����ж���
     */
    if (label[0].len == 2) {
        p_cc = (char *)&country_code;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ /* Little Endian, eg. x86, x64 */
        p_cc[0] = label[0].data[1];
        p_cc[1] = label[0].data[0];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ /* Big Endian */
        p_cc[0] = label[0].data[0];
        p_cc[1] = label[0].data[1];
#else
#error "CPU ENDIAN is not defined"
#endif
        switch (country_code) {
        case CC_cn: case CC_us: case CC_uk: case CC_kr: case CC_jp: case CC_eu:
        case CC_fr: case CC_hk: case CC_tw: case CC_io: case CC_it: case CC_mo:
            need_check = 1;
            break;
        default:
            break;
        }
    }

    /*
     * Ȼ��������������ǹ������������һ������label[1]������Ϊͨ������Generic������Ҫ�ϲ���
     * TODO: ֧�ֵ�ͨ���������ȶ���3���ܷ�ֱ������Ϊ�жϱ�׼��
     */
    if (need_check && (label[1].len == 3)) {
        p_gc = (char *)&generic_code;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ /* Little Endian, eg. x86, x64 */
        // p_gc[0] = 0;
        p_gc[1] = label[1].data[2];
        p_gc[2] = label[1].data[1];
        p_gc[3] = label[1].data[0];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ /* Big Endian */
        p_gc[0] = label[1].data[0];
        p_gc[1] = label[1].data[1];
        p_gc[2] = label[1].data[2];
        // p_gc[3] = 0;
#else
#error "CPU ENDIAN is not defined"
#endif
        switch (generic_code) {
        case GC_com: case GC_net: case GC_org: case GC_gov: case GC_edu: case GC_biz:
            need_merge = 1;
            break;
        default:
            break;
        }
    }

    if (need_merge) {
        /* �ϲ�label[1]��label[0]�� */
        label[0].data = label[1].data;
        label[0].len = label[0].len + label[1].len + 1; /* �����м�����'.'������com.cn */
        /* ��ʣ���label��������λ */
        for (i = 1; i < label_count - 1; i++) {
            if (label[i + 1].len == 0) {
                goto out;
            }
            label[i].data = label[i + 1].data;
            label[i].len = label[i + 1].len;
            if (string_is_equal(&label[i], &host_wildcard)) {
                /* ����ͨ���label���滻����ֵ */
                label[i].len = BTRIE_WILDCARD_MAGIC_LEN;
            }
        }
        label[label_count - 1].data = NULL;
        label[label_count - 1].len = 0;

        ret = label_count - 1;
        goto out;
    } else {
        for (i = 0; i < label_count; i++) {
            if (label[i].len == 0) {
                goto out;
            }
            if (string_is_equal(&label[i], &host_wildcard)) {
                /* ����ͨ���label���滻����ֵ */
                label[i].len = BTRIE_WILDCARD_MAGIC_LEN;
            }
        }

        ret = label_count;
        goto out;
    }

    if (ret < 2) {
        /* ��ʹ�ϲ���label��Ҳ������ڵ���2 */
        ret = -1;
    }
out:
    return ret;
}

/*
 * ���ݺϲ�������label��ȷ�������㷨��hash�������ֵ��
 * �����(δ)ʹ��hash����٣��򷵻���Чֵhost_ht_max��
 */
string_t tld_com = string_init("com");
string_t tld_cn = string_init("cn");
string_t tld_com_cn = string_init("com.cn");
static inline host_htable_index cache_host_trans_ht_index(string_t *top_label)
{
    if (string_is_equal(top_label, &tld_com)) {
        return host_ht_com;
    } else if (string_is_equal(top_label, &tld_cn)) {
        return host_ht_cn;
    } else if (string_is_equal(top_label, &tld_com_cn)) {
        return host_ht_com_cn;
    } else {
        return host_ht_max;
    }
}

/*
 * host���������������
 * �ɹ��󷵻�label�������򷵻�-1
 */
static int cache_host_parse(string_t *host,
                            string_t label[CACHE_HOST_LABEL_MAX_COUNT],
                            host_htable_index *ht_index)
{
    int dot, ret;
    char *p;

    /* TODO: ����host�Ϸ��Լ�飬Ӧ����ǰ */
    if (host->len < 3 || host->data[0] == '.' || host->data[host->len - 1] == '.') {
        /* XXX: �ų��쳣���������host̫�̣���Ϊ.a.b.com. */
        return -1;
    }

    dot = 0;
    for (p = host->data + host->len - 1; p > host->data; p--) {
        if (*p == '.') {
            if (dot >= CACHE_HOST_DOT_MAX_COUNT) {
                /* host������'.'�Ѿ�����֧�ֵ����ֵ */
                return -1;
            }
            label[dot].data = p + 1;
            if (dot == 0) {
                label[dot].len = host->data + host->len - label[dot].data;
            } else {
                label[dot].len = label[dot-1].data - 1 - label[dot].data;
            }
            dot++;
        }
    }

    if (dot == 0) {
        return -1;
    }

    label[dot].data = host->data;
    label[dot].len = label[dot-1].data - 1 - label[dot].data;

    ret = cache_host_parse_deep(label, (dot + 1));

    if (ret > 0) {
        *ht_index = cache_host_trans_ht_index(&label[0]);
    }

    return ret;
}

/*
 * ���host�����й�˾(��֯)������hash
 * ʹ��ELFlash-x1�㷨ʵ�֡�
 */
static inline int cache_host_hash(string_t *str)
{
    char *p;
    unsigned long h = 0, g;

    for (p = str->data; p < str->data + str->len; p++) {
        h = (h << 4) + (*p);
        g = h & 0xF000000UL; /* 0xF������6��0������7��0�� */
        if (g != 0) {
            h ^= (g >> 24);
        }
        h &= (~g);
    }

    return (h & CACHE_HOST_HT_MASK);
}

static btrie_node_t *cache_host_hash_find_root(void *hash_table[], string_t *str)
{
    int index;
    cache_host_hte_t *hte;
    btrie_node_t *ret = NULL;

    index = cache_host_hash(str);
    for (hte = hash_table[index]; hte != NULL; hte = hte->next) {
        if (string_is_equal(&hte->str, str)) {
            ret = hte->host_root;
            break;
        }
    }

    return ret;
}

/*
 * ƥ��ģ���ڲ����̣�����Ҫ������
 */
cache_host_t *cache_host_find(cache_host_ctx_t *ctx, string_t *host)
{
    cache_host_t *h;
    string_t label[CACHE_HOST_LABEL_MAX_COUNT], *match_label;
    host_htable_index ht_index;
    btrie_node_t *host_root;
    int count, valids;

    memset(label, 0, sizeof(label));
    valids = cache_host_parse(host, label, &ht_index);
    if (valids < 0) {
        return NULL;
    }

    /* Ĭ������£�ֱ��ʹ��normal_host_root���� */
    host_root = ctx->normal_host_root;
    count = CACHE_HOST_LABEL_MAX_COUNT;
    match_label = label;

    if (ht_index < host_ht_max) {
        NOTICE("ht_index %d, %*s", ht_index, label[1].len, label[1].data);
        host_root = cache_host_hash_find_root(ctx->hash_table[ht_index], &label[1]);
        count -= 2;
        match_label = &label[2];
    }

    if (host_root == NULL) {
        return NULL;
    }

    h = btrie_find(host_root, count, match_label);

    return h;
}

static cache_host_hte_t *cache_host_hash_alloc_entry(cache_host_ctx_t *ctx)
{
    cache_host_hte_t *hte;

    if (ctx->hte_free_num == 0) {
        return NULL;
    }

    hte = ctx->hte_free_list;
    ctx->hte_free_list = hte->next;
    ctx->hte_free_num--;

    memset(hte, 0, sizeof(cache_host_hte_t));

    return hte;
}

static void cache_host_hash_free_entry(cache_host_ctx_t *ctx, cache_host_hte_t *hte)
{
    if (hte == NULL) {
        return;
    }

    hte->next = ctx->hte_free_list;
    ctx->hte_free_list = hte;
    ctx->hte_free_num++;

    return;
}

static btrie_node_t **cache_host_hash_add_root(cache_host_ctx_t *ctx,
                                               void *hash_table[],
                                               string_t *str)
{
    int index;
    cache_host_hte_t **ptr_hte, *hte;

    index = cache_host_hash(str);
    ptr_hte = (cache_host_hte_t **)&hash_table[index];
    hte = hash_table[index];
    for ( ; hte != NULL; ptr_hte = &hte->next, hte = hte->next) {
        if (string_is_equal(&hte->str, str)) {
            break;
        }
    }
    if (hte == NULL) {
        /* ��Ҫ�½�hash table entry */
        hte = cache_host_hash_alloc_entry(ctx);
        if (hte == NULL) {
            goto err_out;
        }
        if (symtab_add(ctx->symtab, str, &hte->str) != 0) {
            goto err_out1;
        }
        /* ��hte��ӵ�hash������β�� */
        *ptr_hte = hte;
        hte->next = NULL;
    }

    return &hte->host_root;

err_out1:
    cache_host_hash_free_entry(ctx, hte);
err_out:
    return NULL;
}

static btrie_node_t *cache_host_add(cache_host_ctx_t *ctx, string_t *name)
{
    int valids, end_index;
    string_t label[CACHE_HOST_LABEL_MAX_COUNT], *match_label;
    btrie_node_t *ret = NULL;
    host_htable_index ht_index;
    btrie_node_t **ptr_host_root;
    int count;

    memset(label, 0, sizeof(label));
    valids = cache_host_parse(name, label, &ht_index);
    if (valids < 2) {
        NOTICE();
        return NULL;
    }

    ptr_host_root = &ctx->normal_host_root;
    count = CACHE_HOST_LABEL_MAX_COUNT;
    match_label = label;

    if (ht_index < host_ht_max) {
        NOTICE("ht_index %d, %*s", ht_index, label[1].len, label[1].data);
        ptr_host_root = cache_host_hash_add_root(ctx, ctx->hash_table[ht_index], &label[1]);
        if (ptr_host_root == NULL) {
            return NULL;
        }
        count -= 2;
        match_label = &label[2];
        valids -= 2;
        /*
         * ��host��baidu.com���ϲ������������baidu.com.cn��valids��Ϊ2��
         * Ҫ������������host����Ҫ�ֶ����BTRIE_NO_VALUE_MAGIC_LEN��label��ָ��btrie���롣
         */
        if (valids == 0) {
            match_label[0].len = BTRIE_NO_VALUE_MAGIC_LEN;
            valids++;
        }
    }

    end_index = valids - 1;
    ret = btrie_insert(ctx->btrie,
                       ptr_host_root,
                       count,
                       match_label,
                       valids,
                       end_index);

    return ret;
}

static cache_host_t *cache_host_alloc(cache_host_ctx_t *ctx)
{
    cache_host_t *h;

    if (ctx->host_free_num == 0) {
        return NULL;
    }

    h = ctx->host_free_list;
    ctx->host_free_list = (cache_host_t *)(h->flags);
    ctx->host_free_num--;

    memset(h, 0, sizeof(cache_host_t));

    return h;
}

static void cache_host_free(cache_host_ctx_t *ctx, cache_host_t *h)
{
    if (h == NULL) {
        return;
    }

    /* XXX: �ڱ���hostʱ����h->host��Ϊhost�Ƿ���Ч�ı�׼����Ȼfree�˾͵ó�ʼ�� */
    h->host.data = NULL;
    h->host.len = 0;

    h->flags = (unsigned long)ctx->host_free_list;
    ctx->host_free_list = h;
    ctx->host_free_num++;

    return;
}

/*
 * ���ع����ʱ��������õ�hostֵ�Ƿ���Ч��������host�Ķ���������һ��������ͨ���'*'
 */
static int cache_host_is_valid_name(string_t *name)
{
    int dot;
    char *p;
    string_t last_two_label[2];

    if (name->len < 3 || name->data[0] == '.' || name->data[name->len - 1] == '.') {
        return 0;
    }

    dot = 0;
    memset(last_two_label, 0, sizeof(last_two_label));
    for (p = name->data + name->len - 1; p >= name->data; p--) {
        if (*p == '.') {
            last_two_label[dot].data = p + 1;
            if (dot == 0) {
                last_two_label[dot].len = name->data + name->len - last_two_label[dot].data;
            } else {
                last_two_label[dot].len = last_two_label[dot - 1].data - 1 - last_two_label[dot].data;
            }
            dot++;
            if (dot > 1) {
                break;
            }
        }
    }
    if (dot == 0) {
        last_two_label[0].data = name->data;
        last_two_label[0].len = name->len;
    } else if (dot == 1) {
        last_two_label[1].data = name->data;
        last_two_label[1].len = last_two_label[0].data - 1 - last_two_label[1].data;
    }

    if (string_is_equal(&last_two_label[0], &host_wildcard)
            || string_is_equal(&last_two_label[1], &host_wildcard)) {
        return 0;
    }

    return 1;
}

/* XXX HOST����� XXX */
/* ����host�ṹ�壬��ɳ�ʼ�������hash���������ڵ� */
cache_host_t *cache_host_new(cache_host_ctx_t *ctx, string_t *name)
{
    cache_host_t *h;
    btrie_node_t *host_attach_node;

    if (!cache_host_is_valid_name(name)) {
        goto err_out;
    }

    h = cache_host_alloc(ctx);
    if (h == NULL) {
        goto err_out;
    }

    /* ��host������ӵ����ű��У������Ĳ����ܿ��ܲ���Ҫ������ӷ��ű��� */
    if (symtab_add(ctx->symtab, name, &h->host) != 0) {
        goto err_out1;
    }

    host_attach_node = cache_host_add(ctx, name);
    if (host_attach_node == NULL) {
        /* ��host�����������ʧ�ܣ���������Դ�������host�Ѵ��� */
        goto err_out1;
    }

    host_attach_node->data = h;

    return h;

err_out1:
    cache_host_free(ctx, h);
err_out:
    return NULL;
}

int cache_host_init(cache_host_ctx_t *ctx, size_t *alloc_size)
{
    cache_host_t *mem_host, *h;
    cache_host_hte_t *mem_hte, *hte;
    void **mem_ht;
    size_t size, total = 0;
    int i;

    if (ctx == NULL || alloc_size == NULL || ctx->host_capacity == 0 || ctx->hte_capacity == 0) {
        goto err_out;
    }

    size = ctx->host_capacity * sizeof(cache_host_t);
    mem_host = malloc(size);
    if (mem_host == NULL) {
        goto err_out;
    }
    memset(mem_host, 0, size);
    ctx->host_base = mem_host;
    ctx->host_free_num = ctx->host_capacity;
    ctx->host_free_list = &ctx->host_base[0];
    for (i = 1; i < ctx->host_free_num; i++) {
        h = &ctx->host_base[i];
        h->flags = (unsigned long)ctx->host_free_list;
        ctx->host_free_list = h;
    }
    total += size;

    size = ctx->hte_capacity * sizeof(cache_host_hte_t);
    mem_hte = malloc(size);
    if (mem_hte == NULL) {
        goto err_out1;
    }
    memset(mem_hte, 0, size);
    ctx->hte_base = mem_hte;
    ctx->hte_free_num = ctx->hte_capacity;
    ctx->hte_free_list = &ctx->hte_base[0];
    for (i = 1; i < ctx->hte_free_num; i++) {
        hte = &ctx->hte_base[i];
        hte->next = ctx->hte_free_list;
        ctx->hte_free_list = hte;
    }
    total += size;

    size = CACHE_HOST_HT_SIZE * sizeof(void *) * host_ht_max;
    mem_ht = malloc(size);
    if (mem_ht == NULL) {
        goto err_out2;
    }
    memset(mem_ht, 0, size);
    for (i = 0; i < host_ht_max; i++) {
        ctx->hash_table[i] = mem_ht + (CACHE_HOST_HT_SIZE * i);
    }
    total += size;

    *alloc_size = total;

    return 0;

err_out2:
    free(mem_hte);
err_out1:
    free(mem_host);
err_out:
    return -1;
}

void cache_host_uninit(cache_host_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->hash_table[0] != NULL) {
        free(ctx->hash_table[0]);
        memset(ctx->hash_table, 0, sizeof(ctx->hash_table));
    }

    if (ctx->hte_base != NULL) {
        free(ctx->hte_base);
        ctx->hte_base = NULL;
    }

    if (ctx->host_base != NULL) {
        free(ctx->host_base);
        ctx->host_base = NULL;
    }

    return;
}

void cache_host_walk(cache_host_ctx_t *ctx, cache_host_walk_func_t func)
{
    int i;
    cache_host_t *h;

    if (func == NULL || ctx == NULL || ctx->host_base == NULL) {
        return;
    }

    for (i = ctx->host_capacity - 1; i >= 0; i--) {
        h = &ctx->host_base[i];
        if (h->host.data != NULL) {
            func(h);
        }
    }

    if (ctx->default_host.host.data != NULL) {
        h = &ctx->default_host;
        func(h);
    }

    return;
}

int cache_host_hit(cache_host_ctx_t *ctx, string_t *host)
{
    cache_host_t *h;

    /* ����ƥ��Ĭ��host�¹������Դ��������hit����˻����豸��������� */
    h = cache_host_find(ctx, host);

    return (h != NULL);
}

#define DUMP_PRINT_BUFLEN 64
void cache_host_dump_hash(cache_host_ctx_t *ctx)
{
    int i, j, copy_size, used_slot, entry_count;
    cache_host_hte_t *hte;
    char print_buf[DUMP_PRINT_BUFLEN + 1];

    if (ctx == NULL) {
        return;
    }

    for (i = 0; i < host_ht_max; i++) {
        used_slot = 0;
        entry_count = 0;
        printf("*** Host Hash %d ***\n", i);
        if (ctx->hash_table[i] == NULL) {
            printf("   Empty\n-------------------\n");
            continue;
        }
        for (j = 0; j < CACHE_HOST_HT_SIZE; j++) {
            hte = ctx->hash_table[i][j];
            if (hte == NULL) {
                continue;
            }
            used_slot++;
            printf("   [%3d]:", j);
            for ( ; hte != NULL; hte = hte->next) {
                copy_size = DUMP_PRINT_BUFLEN;
                if (copy_size > hte->str.len) {
                    copy_size = hte->str.len;
                }
                memcpy(print_buf, hte->str.data, copy_size);
                print_buf[copy_size] = '\0';
                printf(" %s |", print_buf);
                entry_count++;
            }
            printf("\n");
        }
        printf("Host Hash %d: slot %d/%d, Total entry %d.\n\n",
                                i, used_slot, CACHE_HOST_HT_SIZE, entry_count);
    }

    return;
}

