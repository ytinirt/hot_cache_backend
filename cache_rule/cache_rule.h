#ifndef __CACHE_RULE_H__
#define __CACHE_RULE_H__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

/***************************************************************************************************
 * Macro definition for Configuring
 */
#define ARCH_LITTLE_ENDIAN                  1

#define CACHE_HOST_CFG_MAX_COUNT            256 /* 配置host容量 */
#define CACHE_HOST_NAME_MAX_LEN             128 /* host长度上限值 */
#define CACHE_HOST_AVR_RULE_COUNT           4   /* 每host的平均规则数量，非限制值，仅供资源预留 */
#define CACHE_HOST_LABEL_MAX_COUNT          8   /* a.b.com中每个由'.'分隔开的部分称作label */
#define CACHE_HOST_DOT_MAX_COUNT            (CACHE_HOST_LABEL_MAX_COUNT - 1) /* host中'.'最大数 */

#define CACHE_RULE_MAX_COUNT                (CACHE_HOST_CFG_MAX_COUNT * CACHE_HOST_AVR_RULE_COUNT)
#define CACHE_RULE_SYMTAB_LEN               (CACHE_RULE_MAX_COUNT * 32) /* 每rule预留32字节 */
#define CACHE_RULE_BTRIE_NODE_MAX_COUNT     (CACHE_RULE_MAX_COUNT * 4)  /* 缓存规则预留的btrie节点 */

#define CACHE_RULE_LINE_MAX_LEN             256 /* 一行RULE的最大长度 */

#define CACHE_RULE_SLASH_MAX_COUNT          12
#define CACHE_RULE_TAIL_SLASH_INDEX         CACHE_RULE_SLASH_MAX_COUNT
#define CACHE_RULE_SUFFIX_INDEX             (CACHE_RULE_TAIL_SLASH_INDEX + 1)
#define CACHE_RULE_MATCH_STR_COUNT          (CACHE_RULE_SUFFIX_INDEX + 1) /* 包括12个斜杠、尾部斜杠和后缀，共14项 */
#define CACHE_RULE_PARA_MAX_COUNT           3
#define CACHE_RULE_PARA_TOKEN               '?'

typedef struct cache_rule_stats_s {
    unsigned long mem_total;

    int host_capacity; /* 不包括默认host */
    int host_in_use;   /* 不包括默认host */
    int host_default_exist;

    int rule_capacity;
    int rule_in_use;

    int symtab_limit;
    int symtab_used;

    int btrie_node_capacity;
    int btrie_node_in_use;

    int host_hte_capacity;
    int host_hte_in_use;
} cache_rule_stats_t;

/***************************************************************************************************
 * Public structure and routine
 */
typedef struct string_s {
    size_t len;
    char  *data;
} string_t;
#define string_init(str)     { sizeof(str) - 1, (char *) str }
#define NULL_STR             {0, NULL}

/* 调用者必须检查参数 */
static inline int string_is_equal(string_t *str1, string_t *str2)
{
    int i;
    int ret = 0;

    if (str1->len == str2->len) {
        for (i = 0; i < str1->len; i++) {
            if (str1->data[i] == str2->data[i]) {
                continue;
            }
            goto out;
        }
        ret = 1;
    }

out:
    return ret;
}

/***************************************************************************************************
 * Symbol table
 */
typedef struct symtab_ctx_s {
    char        *mem_base;
    unsigned int capacity;
    char        *free_start;
} symtab_ctx_t;

/* 调用者保证参数的正确性 */
static inline int symtab_add(symtab_ctx_t *symtab, string_t *from, string_t *to)
{
    char tmp;
    char *p, *s = NULL;
    size_t len;

    tmp = from->data[from->len];
    from->data[from->len] = '\0';
    for (p = symtab->mem_base; p < symtab->free_start; ) {
        s = strstr(p, from->data);
        if (s != NULL) {
            break;
        }
        len = strlen(p);
        p = p + len + 1;
    }
    from->data[from->len] = tmp;

    if (s != NULL) {
        /* 已经存在，无需添加 */
        to->data = s;
        to->len = from->len;
        return 0;
    }

    if ((symtab->free_start + from->len)
            >= (symtab->mem_base + symtab->capacity)) {
        /* 符号缓存空间已满 */
        return -1;
    }

    to->data = symtab->free_start;
    to->len = from->len;

    memcpy(symtab->free_start, from->data, from->len);
    symtab->free_start[from->len] = '\0';
    symtab->free_start = symtab->free_start + from->len + 1;

    return 0;
}

/***************************************************************************************************
 * Btree-Trie
 */
#define BTRIE_NO_VALUE_MAGIC_LEN      0x12345678
#define BTRIE_WILDCARD_MAGIC_LEN      0X12345679
#define BTRIE_FLAG_WILDCARD           0x00000001UL
typedef struct btrie_node_s {
    unsigned long flags;

    /* 匹配项，例如0 ~ (CACHE_RULE_SLASH_MAX_COUNT-1)号斜杠，尾部斜杠或后缀 */
    unsigned long index;
    /* 匹配值 */
    string_t str;

    /* 当前节点不匹配时，进行同级的下一个匹配 */
    struct btrie_node_s *sibling;
    /* 当前节点匹配时，进行下一级匹配 */
    struct btrie_node_s *child;

    /* 匹配后对应的数据 */
    void *data;
} btrie_node_t;

typedef struct btrie_ctx_s {
    struct btrie_node_s *node_mem_base;
    unsigned int         node_capacity;
    unsigned int         node_used_count;
    struct symtab_ctx_s  *symtab;
} btrie_ctx_t;

btrie_node_t *btrie_insert(btrie_ctx_t *ctx,
                           btrie_node_t **ptr_root,
                           unsigned long count,
                           string_t str[],
                           unsigned long valids,
                           int end_index);
void *btrie_find(btrie_node_t *root,
                 unsigned long count, /* str[]的成员数量 */
                 string_t str[]);
int btrie_init(btrie_ctx_t *ctx, size_t *alloc_size);
void btrie_uninit(btrie_ctx_t *ctx);

/***************************************************************************************************
 * Accelerated Host Match, 特殊的域名使用hash方法加速匹配查找。
 */
/* 目前最常见的域名是*.com, *.cn, *.com.cn，仅针对这三种域名使用hash进行优化 */
typedef enum {
    host_ht_com = 0,
    host_ht_cn,
    host_ht_com_cn,
    host_ht_max,
} host_htable_index;
#define CACHE_HOST_HT_SIZE                  64  /* 配置hash表表项数，必须是2的幂次 */
#define CACHE_HOST_HT_MASK                  (CACHE_HOST_HT_SIZE - 1)
#define CACHE_HOST_HTE_MAX_COUNT            (CACHE_HOST_HT_SIZE * host_ht_max)

#define CACHE_HOST_DEFAULT                  0x00000001UL /* 默认host */
#define CACHE_HOST_SAME_AS                  0x00000002UL /* 本host的规则与某个已存在的host完全相同 */
typedef struct cache_host_s {
    unsigned long flags;
    string_t host;

    struct cache_host_s *same_as; /* 与host same_as的规则相同 */

    btrie_node_t *rule_root; /* 每个host的规则树 */
    unsigned long rule_num;
} cache_host_t;

/* Host Hash Table Entry */
typedef struct cache_host_hte_s {
    string_t str;
    struct cache_host_hte_s *next;
    btrie_node_t *host_root;
} cache_host_hte_t;

typedef struct cache_host_ctx_s {
    cache_host_t default_host;

    cache_host_t *host_base;
    cache_host_t *host_free_list;
    unsigned int host_capacity;
    unsigned int host_free_num;

    cache_host_hte_t *hte_base;
    cache_host_hte_t *hte_free_list;
    unsigned int hte_capacity;
    unsigned int hte_free_num;

    void **hash_table[host_ht_max]; /* 用于特殊host查找加速的hash表 */

    btrie_node_t *normal_host_root; /* 查找普通host的btrie树根 */

    symtab_ctx_t *symtab;
    btrie_ctx_t *btrie;
} cache_host_ctx_t;

typedef void (*cache_host_walk_func_t)(cache_host_t *host);
int cache_host_init(cache_host_ctx_t *ctx, size_t *alloc_size);
void cache_host_uninit(cache_host_ctx_t *ctx);
cache_host_t *cache_host_new(cache_host_ctx_t *ctx, string_t *name);
cache_host_t *cache_host_find(cache_host_ctx_t *ctx, string_t *host);
void cache_host_walk(cache_host_ctx_t *ctx, cache_host_walk_func_t func);
int cache_host_hit(cache_host_ctx_t *ctx, string_t *host);
void cache_host_dump_hash(cache_host_ctx_t *ctx);

/***************************************************************************************************
 * Cache rule stuff
 */
#define CACHE_ACTION_CACHE_SP               0x00000001UL /* SP将URL匹配记录下来，否则只能手动添加 */
#define CACHE_ACTION_UPPARSE                0x00000002UL /* 资源链接需要服务器进一步解析 */
#define CACHE_ACTION_UPSTREAM               0x00000004UL /* 资源由Nginx下载 */
#define CACHE_ACTION_SPWRITE                0x00000008UL /* 直接在快转数据面保存资源 */
#define CACHE_ACTION_REDIRECT_PARA          0x00000010UL
#define CACHE_ACTION_FORBIDDEN              0x00000020UL
#define CACHE_ACTION_CON_CLOSE              0x00000040UL
#define CACHE_ACTION_HOME_POLL              0x00000080UL
#define CACHE_ACTION_DBG_PRINT              0x80000000UL /* 打印匹配的url，不做任何操作，用于debug */

#define CACHE_KEY_S0                        0x00000001UL
#define CACHE_KEY_S1                        0x00000002UL
#define CACHE_KEY_S2                        0x00000004UL
#define CACHE_KEY_S3                        0x00000008UL
#define CACHE_KEY_S4                        0x00000010UL
#define CACHE_KEY_S5                        0x00000020UL
#define CACHE_KEY_S6                        0x00000040UL
#define CACHE_KEY_S7                        0x00000080UL
#define CACHE_KEY_S8                        0x00000100UL
#define CACHE_KEY_S9                        0x00000200UL
#define CACHE_KEY_S10                       0x00000400UL
#define CACHE_KEY_S11                       0x00000800UL
#define CACHE_KEY_ALL_SLASH                 0x00000FFFUL
#define CACHE_KEY_FILE                      0x80000000UL
#define CACHE_KEY_PARA                      0x40000000UL

typedef struct cache_rule_url_part_s {
    string_t host;
    /* XXX 注意: slash、tail_slash和suffix必须相连，且顺序不可修改*/
    string_t slash[CACHE_RULE_SLASH_MAX_COUNT]; /* 索引0 - 11 */
    string_t tail_slash;                        /* 索引12 */
    string_t suffix;                            /* 索引13 */
    string_t para;
} cache_rule_url_part_t;

typedef struct cache_rule_s {
    /* 操作此类请求URL */
    unsigned long action_flags;

    /*
     * 生成key值，唯一标识资源。
     * eg1:
     * http://192.168.5.69/ngcf/output/rsr20-14f-183742-main-322023/ngsa-main-rsr20-14f.map.sym
     *                    ^           ^                            ^
     *                    slash[0]    slash[2]                     slash[3] (tail_slash)
     * eg2:
     * http://10.128.10.81:8080/zcgl/zcgl/review/onLineViewAction!downWord.do?dto.ya9501=7&dto.yh5000=2003296
     *                         ^                ^                             ^            ^
     *                         slash[0]         slash[3] (tail_slash)         para[0]      para[1]
     */
    unsigned long key_flags;
    string_t key_para[CACHE_RULE_PARA_MAX_COUNT];

    /*
     * 本地保存的文件路径:
     * HTTP_ROOT/translated_host/key_name[local_suffix]
     *
     * XXX: 针对有para生成key的规则，由于可能没有显式的后缀名，可在规则中指定local_suffix。
     *      如果key中有host，则在生成文件路径时忽略key_name中的host，因为translated_host包括了host。
     *
     * eg1:
     * $HC_HTTP_ROOT/192_168_5_69/ngcf_rsr20-14f-183742-main-322023_ngsa-main-rsr20-14f.map.sym
     *
     * eg2:
     * $HC_HTTP_ROOT/10_128_10_81_8080/zcgl_onLineViewAction!downWord.do_dto.ya9501=7&dto.yh5000=2003296.doc
     *              ^                 ^                                                                ^
     *              translated_host   key_name                                                         local_suffix
     */
    string_t local_suffix;
} cache_rule_t;

typedef struct cache_rule_ctx_s {
    cache_rule_t *mem_base;
    cache_rule_t *free_list;
    unsigned int capacity;
    unsigned int free_num;

    symtab_ctx_t symtab;
    btrie_ctx_t btrie;
    cache_host_ctx_t hosts;

    size_t total_alloc_mem;
} cache_rule_ctx_t;

#define BUG(fmt, arg...) do { \
        fprintf(stderr, "[BUG] %s<%d>: " fmt "\n", __func__, __LINE__, ##arg); \
    } while (0)

#define NOTICE(fmt, arg...) do { \
        fprintf(stderr, "[NOTICE] %s<%d>: " fmt "\n", __func__, __LINE__, ##arg); \
    } while (0)

int cache_rule_str_is_equal(string_t *str1, string_t *str2);
int cache_rule_load(const char *rule_file, cache_rule_ctx_t **context);
void cache_rule_get_stats(cache_rule_ctx_t *ctx, cache_rule_stats_t *stats);
void cache_rule_dump_symtab(cache_rule_ctx_t *ctx);
void cache_rule_dump_host_hash(cache_rule_ctx_t *ctx);
cache_rule_t *cache_rule_get_rule(cache_rule_ctx_t *ctx, string_t *url);
int cache_rule_url2local_key(string_t *url, cache_rule_t *rule, string_t *key);
int cache_rule_url2local_file(string_t *url, cache_rule_t *rule, string_t *file);
void cache_rule_walk_host(cache_rule_ctx_t *ctx, cache_host_walk_func_t func);
int cache_rule_hit_host(cache_rule_ctx_t *ctx, string_t *host);

#endif /* __CACHE_RULE_H__ */

