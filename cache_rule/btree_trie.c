
#include "cache_rule.h"

/* 内存必须都被初始化为0 */
static btrie_node_t *btrie_node_alloc(btrie_ctx_t *ctx, int alloc_cnt)
{
    btrie_node_t *array;
    size_t len;

    if (ctx->node_used_count + alloc_cnt > ctx->node_capacity) {
        return NULL;
    }

    array = ctx->node_mem_base + ctx->node_used_count;
    ctx->node_used_count += alloc_cnt;

    len = sizeof(btrie_node_t) * alloc_cnt;
    memset(array, 0, len);

    return array;
}

static void btrie_node_free(btrie_ctx_t *ctx, int free_cnt)
{
    ctx->node_used_count -= free_cnt;

    return;
}

/*
 * XXX: btrie插入操作有其特殊性
 *      对rule匹配规则而言，它是松散的，count表示了str[]的总项数，valids表示有效的str项，end_index
 *            则表示最后一个有效str项的索引值，end_index可能大于valids。
 *      对host匹配规则而言，它是连续的，count依然表示str[]的总项数，但由于是连续，end_index总是等于
 *            valids-1。
 *      valids用于指导分配btrie_node，end_index则用于最后的检查工作。
 */
btrie_node_t *btrie_insert(btrie_ctx_t *ctx,
                           btrie_node_t **ptr_root,
                           unsigned long count,
                           string_t str[],
                           unsigned long valids,
                           int end_index)
{
    int node_cnt = 0, node_used = 0;
    btrie_node_t *new_node_array, *node, *wildcard;
    int i, found = 0;
    btrie_node_t **proot, *root, *ret = NULL;
    btrie_node_t **pcurr, *curr; /* 注意: 用于算法内部临时查找，而非当前处理节点 */

    if (ctx == NULL || ptr_root == NULL || count == 0 || str == NULL || valids > count || valids == 0) {
        return NULL;
    }
    if (end_index < 0 || end_index >= count) {
        return NULL;
    }

    node_cnt = valids * 2; /* 预留通配符节点，节点分配数量翻倍 */
    /* 注意: new_node_array必须是连续分配的，且严格的从头开始连续使用，以便连续释放空闲的 */
    new_node_array = btrie_node_alloc(ctx, node_cnt);
    if (new_node_array == NULL) {
        NOTICE();
        return NULL;
    }

    proot = ptr_root; /* 存放root的位置，方便修改root的值 */
    root = *proot;
    for (i = 0; i < count; i++) {
        if (str[i].len == 0) {
            continue;
        }
        if (str[i].len == BTRIE_NO_VALUE_MAGIC_LEN) {
            /* 对str是no val型，恢复其正确值0。 */
            str[i].len = 0;
        }
again:
        if (node_used >= node_cnt) {
            /* BUG: 使用量已经超过分配的数量 */
            BUG();
            return NULL;
        }
        if (root == NULL) {
            node = &new_node_array[node_used];
            node->index = i;
            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                node->flags = BTRIE_FLAG_WILDCARD;
            } else {
                if ((str[i].len > 0)
                        && (symtab_add(ctx->symtab, &str[i], &node->str) != 0)) {
                    goto err_out;
                }
            }
            node_used++;
            *proot = node;

            ret = node;
            proot = &node->child;
            root = node->child;
        } else if (root->index == i) {
            for (pcurr = proot, curr = root;
                    (curr != NULL) && (curr->flags != BTRIE_FLAG_WILDCARD);
                    pcurr = &curr->sibling, curr = curr->sibling) {
                if (string_is_equal(&curr->str, &str[i])) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                found = 0;
                proot = &curr->child;
                root = curr->child;
                ret = curr;
                continue;
            }

            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                if (curr == NULL) {
                    /* 通配符节点不存在，首先创建通配符节点 */
                    node = &new_node_array[node_used];
                    node->index = i;
                    node->flags = BTRIE_FLAG_WILDCARD;
                    node_used++;
                    /* 然后将通配符节点加入树中 */
                    node->sibling = curr;
                    *pcurr = node;
                    curr = node;
                }

                proot = &curr->child;
                root = curr->child;
                ret = curr;
                continue;
            } else {
                node = &new_node_array[node_used];
                node->index = i;
                if ((str[i].len > 0)
                        && (symtab_add(ctx->symtab, &str[i], &node->str) != 0)) {
                    goto err_out;
                }
                node_used++;

                node->sibling = curr;
                *pcurr = node;
                proot = &node->child;
                root = node->child;
                ret = node;
                continue;
            }
        } else if (root->index > i) {
            /* root节点等级比待加入节点低 */
            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                /* XXX: 目前只有host涉及到通配符，其不可能进入本分支 */
                BUG();
                goto err_out;
            }
            node = &new_node_array[node_used];
            node->index = i;
            if ((str[i].len > 0)
                    && (symtab_add(ctx->symtab, &str[i], &node->str) != 0)) {
                goto err_out;
            }
            node_used++;

            wildcard = &new_node_array[node_used++];
            wildcard->flags = BTRIE_FLAG_WILDCARD;
            wildcard->index = i;

            node->sibling = wildcard;
            wildcard->child = root;
            *proot = node;

            ret = node;
            proot = &node->child;
            root = node->child;
        } else {
            /* root节点等级比待加入节点高 root->index < i */
            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                /* XXX: 目前只有host涉及到通配符，其不可能进入本分支 */
                BUG();
                goto err_out;
            }
            for (pcurr = proot, curr = root;
                    (curr != NULL) && (curr->flags != BTRIE_FLAG_WILDCARD);
                    pcurr = &curr->sibling, curr = curr->sibling) {
                (void)0;
            }
            if (curr == NULL) {
                wildcard = &new_node_array[node_used++];
                wildcard->flags = BTRIE_FLAG_WILDCARD;
                wildcard->index = root->index;

                *pcurr = wildcard;
                curr = wildcard;
            }
            proot = &curr->child;
            root = curr->child;
            goto again;
        }
    }

    /* 对ret的有效性做检查 */
    if ((ret != NULL) && (ret->index != end_index)) {
        /* BUG: 竟然有ret，但还未到末尾的节点 */
        BUG();
        goto err_out;
    }
    /* XXX: 如果添加相同的RULE或者HOST，则ret中data不为NULL，认定为出错 */
    if ((ret != NULL) && (ret->data != NULL)) {
        NOTICE();
        goto err_out;
    }

    /* 释放未使用的mnode */
    btrie_node_free(ctx, (node_cnt - node_used));

    return ret;

err_out:
    /* 释放掉还未加入查找树中的节点，已加入的就不删除了 */
    btrie_node_free(ctx, (node_cnt - node_used));

    return NULL;
}

/*
 * XXX: 就rule匹配而言，虽然传入的count是完整的slash、tail_slash和后缀part，有14项之多，
 *      但比较的次数取决于匹配规则的数量，而非count，规则越多则比较次数越多，每次选取str[]中
 *      对应项进行比较。
 *      *** 规则不止、匹配不息。***
 */
void *btrie_find(btrie_node_t *root,
                 unsigned long count, /* str[]的成员数量 */
                 string_t str[])
{
    void *ret = NULL;
    unsigned long index;
    btrie_node_t *curr;
    string_t *val;

    if (str == NULL) {
        return NULL;
    }

    for (curr = root; curr != NULL; ) {
        index = curr->index;
        /* XXX: 可以省略检查，提高效率 */
        if (index >= count) {
            BUG();
            break;
        }

        val = &str[index];

        if (curr->flags & BTRIE_FLAG_WILDCARD) {
            /* 通配符，不需要比较内容，直接匹配上 */
            if (curr->data != NULL && val->len > 0) {
                /*
                 * 只有host支持通配符，但通配符匹配非空字符串，例如:
                 *     有规则*.baidu.com，但无法匹配baidu.com
                 *     有*.*.baidu.com，无法匹配a.baidu.com
                 */
                ret = curr->data;
            }
            curr = curr->child;
            continue;
        }

        if (string_is_equal(&curr->str, val)) {
            /* 同当前节点匹配 */
            if (curr->data != NULL) {
                ret = curr->data;
            }
            curr = curr->child;
        } else {
            curr = curr->sibling;
        }
    }

    return ret;
}

int btrie_init(btrie_ctx_t *ctx, size_t *alloc_size)
{
    void *mem;
    size_t size;

    if (ctx == NULL || alloc_size == NULL || ctx->node_capacity == 0) {
        return -1;
    }

    size = ctx->node_capacity * sizeof(btrie_node_t);
    mem = malloc(size);
    if (mem == NULL) {
        return -1;
    }

    memset(mem, 0, size);
    ctx->node_mem_base = mem;
    ctx->node_used_count = 0;

    *alloc_size = size;

    return 0;
}

void btrie_uninit(btrie_ctx_t *ctx)
{
    if (ctx == NULL || ctx->node_mem_base == NULL) {
        return;
    }

    free(ctx->node_mem_base);
    ctx->node_mem_base = NULL;

    return;
}

