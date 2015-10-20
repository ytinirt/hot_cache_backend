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

#define CACHE_HOST_CFG_MAX_COUNT            256 /* ����host���� */
#define CACHE_HOST_NAME_MAX_LEN             128 /* host��������ֵ */
#define CACHE_HOST_AVR_RULE_COUNT           4   /* ÿhost��ƽ������������������ֵ��������ԴԤ�� */
#define CACHE_HOST_LABEL_MAX_COUNT          8   /* a.b.com��ÿ����'.'�ָ����Ĳ��ֳ���label */
#define CACHE_HOST_DOT_MAX_COUNT            (CACHE_HOST_LABEL_MAX_COUNT - 1) /* host��'.'����� */

#define CACHE_RULE_MAX_COUNT                (CACHE_HOST_CFG_MAX_COUNT * CACHE_HOST_AVR_RULE_COUNT)
#define CACHE_RULE_SYMTAB_LEN               (CACHE_RULE_MAX_COUNT * 32) /* ÿruleԤ��32�ֽ� */
#define CACHE_RULE_BTRIE_NODE_MAX_COUNT     (CACHE_RULE_MAX_COUNT * 4)  /* �������Ԥ����btrie�ڵ� */

#define CACHE_RULE_LINE_MAX_LEN             256 /* һ��RULE����󳤶� */

#define CACHE_RULE_SLASH_MAX_COUNT          12
#define CACHE_RULE_TAIL_SLASH_INDEX         CACHE_RULE_SLASH_MAX_COUNT
#define CACHE_RULE_SUFFIX_INDEX             (CACHE_RULE_TAIL_SLASH_INDEX + 1)
#define CACHE_RULE_MATCH_STR_COUNT          (CACHE_RULE_SUFFIX_INDEX + 1) /* ����12��б�ܡ�β��б�ܺͺ�׺����14�� */
#define CACHE_RULE_PARA_MAX_COUNT           3
#define CACHE_RULE_PARA_TOKEN               '?'

typedef struct cache_rule_stats_s {
    unsigned long mem_total;

    int host_capacity; /* ������Ĭ��host */
    int host_in_use;   /* ������Ĭ��host */
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

/* �����߱�������� */
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

/* �����߱�֤��������ȷ�� */
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
        /* �Ѿ����ڣ�������� */
        to->data = s;
        to->len = from->len;
        return 0;
    }

    if ((symtab->free_start + from->len)
            >= (symtab->mem_base + symtab->capacity)) {
        /* ���Ż���ռ����� */
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

    /* ƥ�������0 ~ (CACHE_RULE_SLASH_MAX_COUNT-1)��б�ܣ�β��б�ܻ��׺ */
    unsigned long index;
    /* ƥ��ֵ */
    string_t str;

    /* ��ǰ�ڵ㲻ƥ��ʱ������ͬ������һ��ƥ�� */
    struct btrie_node_s *sibling;
    /* ��ǰ�ڵ�ƥ��ʱ��������һ��ƥ�� */
    struct btrie_node_s *child;

    /* ƥ����Ӧ������ */
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
                 unsigned long count, /* str[]�ĳ�Ա���� */
                 string_t str[]);
int btrie_init(btrie_ctx_t *ctx, size_t *alloc_size);
void btrie_uninit(btrie_ctx_t *ctx);

/***************************************************************************************************
 * Accelerated Host Match, ���������ʹ��hash��������ƥ����ҡ�
 */
/* Ŀǰ�����������*.com, *.cn, *.com.cn�����������������ʹ��hash�����Ż� */
typedef enum {
    host_ht_com = 0,
    host_ht_cn,
    host_ht_com_cn,
    host_ht_max,
} host_htable_index;
#define CACHE_HOST_HT_SIZE                  64  /* ����hash���������������2���ݴ� */
#define CACHE_HOST_HT_MASK                  (CACHE_HOST_HT_SIZE - 1)
#define CACHE_HOST_HTE_MAX_COUNT            (CACHE_HOST_HT_SIZE * host_ht_max)

#define CACHE_HOST_DEFAULT                  0x00000001UL /* Ĭ��host */
#define CACHE_HOST_SAME_AS                  0x00000002UL /* ��host�Ĺ�����ĳ���Ѵ��ڵ�host��ȫ��ͬ */
typedef struct cache_host_s {
    unsigned long flags;
    string_t host;

    struct cache_host_s *same_as; /* ��host same_as�Ĺ�����ͬ */

    btrie_node_t *rule_root; /* ÿ��host�Ĺ����� */
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

    void **hash_table[host_ht_max]; /* ��������host���Ҽ��ٵ�hash�� */

    btrie_node_t *normal_host_root; /* ������ͨhost��btrie���� */

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
#define CACHE_ACTION_CACHE_SP               0x00000001UL /* SP��URLƥ���¼����������ֻ���ֶ���� */
#define CACHE_ACTION_UPPARSE                0x00000002UL /* ��Դ������Ҫ��������һ������ */
#define CACHE_ACTION_UPSTREAM               0x00000004UL /* ��Դ��Nginx���� */
#define CACHE_ACTION_SPWRITE                0x00000008UL /* ֱ���ڿ�ת�����汣����Դ */
#define CACHE_ACTION_REDIRECT_PARA          0x00000010UL
#define CACHE_ACTION_FORBIDDEN              0x00000020UL
#define CACHE_ACTION_CON_CLOSE              0x00000040UL
#define CACHE_ACTION_HOME_POLL              0x00000080UL
#define CACHE_ACTION_DBG_PRINT              0x80000000UL /* ��ӡƥ���url�������κβ���������debug */

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
    /* XXX ע��: slash��tail_slash��suffix������������˳�򲻿��޸�*/
    string_t slash[CACHE_RULE_SLASH_MAX_COUNT]; /* ����0 - 11 */
    string_t tail_slash;                        /* ����12 */
    string_t suffix;                            /* ����13 */
    string_t para;
} cache_rule_url_part_t;

typedef struct cache_rule_s {
    /* ������������URL */
    unsigned long action_flags;

    /*
     * ����keyֵ��Ψһ��ʶ��Դ��
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
     * ���ر�����ļ�·��:
     * HTTP_ROOT/translated_host/key_name[local_suffix]
     *
     * XXX: �����para����key�Ĺ������ڿ���û����ʽ�ĺ�׺�������ڹ�����ָ��local_suffix��
     *      ���key����host�����������ļ�·��ʱ����key_name�е�host����Ϊtranslated_host������host��
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

