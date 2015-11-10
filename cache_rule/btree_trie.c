
#include "cache_rule.h"

/* �ڴ���붼����ʼ��Ϊ0 */
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
 * XXX: btrie�����������������
 *      ��ruleƥ�������ԣ�������ɢ�ģ�count��ʾ��str[]����������valids��ʾ��Ч��str�end_index
 *            ���ʾ���һ����Чstr�������ֵ��end_index���ܴ���valids��
 *      ��hostƥ�������ԣ����������ģ�count��Ȼ��ʾstr[]������������������������end_index���ǵ���
 *            valids-1��
 *      valids����ָ������btrie_node��end_index���������ļ�鹤����
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
    btrie_node_t **pcurr, *curr; /* ע��: �����㷨�ڲ���ʱ���ң����ǵ�ǰ����ڵ� */

    if (ctx == NULL || ptr_root == NULL || count == 0 || str == NULL || valids > count || valids == 0) {
        return NULL;
    }
    if (end_index < 0 || end_index >= count) {
        return NULL;
    }

    node_cnt = valids * 2; /* Ԥ��ͨ����ڵ㣬�ڵ������������ */
    /* ע��: new_node_array��������������ģ����ϸ�Ĵ�ͷ��ʼ����ʹ�ã��Ա������ͷſ��е� */
    new_node_array = btrie_node_alloc(ctx, node_cnt);
    if (new_node_array == NULL) {
        NOTICE();
        return NULL;
    }

    proot = ptr_root; /* ���root��λ�ã������޸�root��ֵ */
    root = *proot;
    for (i = 0; i < count; i++) {
        if (str[i].len == 0) {
            continue;
        }
        if (str[i].len == BTRIE_NO_VALUE_MAGIC_LEN) {
            /* ��str��no val�ͣ��ָ�����ȷֵ0�� */
            str[i].len = 0;
        }
again:
        if (node_used >= node_cnt) {
            /* BUG: ʹ�����Ѿ�������������� */
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
                    /* ͨ����ڵ㲻���ڣ����ȴ���ͨ����ڵ� */
                    node = &new_node_array[node_used];
                    node->index = i;
                    node->flags = BTRIE_FLAG_WILDCARD;
                    node_used++;
                    /* Ȼ��ͨ����ڵ�������� */
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
            /* root�ڵ�ȼ��ȴ�����ڵ�� */
            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                /* XXX: Ŀǰֻ��host�漰��ͨ������䲻���ܽ��뱾��֧ */
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
            /* root�ڵ�ȼ��ȴ�����ڵ�� root->index < i */
            if (str[i].len == BTRIE_WILDCARD_MAGIC_LEN) {
                /* XXX: Ŀǰֻ��host�漰��ͨ������䲻���ܽ��뱾��֧ */
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

    /* ��ret����Ч������� */
    if ((ret != NULL) && (ret->index != end_index)) {
        /* BUG: ��Ȼ��ret������δ��ĩβ�Ľڵ� */
        BUG();
        goto err_out;
    }
    /* XXX: ��������ͬ��RULE����HOST����ret��data��ΪNULL���϶�Ϊ���� */
    if ((ret != NULL) && (ret->data != NULL)) {
        NOTICE();
        goto err_out;
    }

    /* �ͷ�δʹ�õ�mnode */
    btrie_node_free(ctx, (node_cnt - node_used));

    return ret;

err_out:
    /* �ͷŵ���δ����������еĽڵ㣬�Ѽ���ľͲ�ɾ���� */
    btrie_node_free(ctx, (node_cnt - node_used));

    return NULL;
}

/*
 * XXX: ��ruleƥ����ԣ���Ȼ�����count��������slash��tail_slash�ͺ�׺part����14��֮�࣬
 *      ���ȽϵĴ���ȡ����ƥ����������������count������Խ����Ƚϴ���Խ�࣬ÿ��ѡȡstr[]��
 *      ��Ӧ����бȽϡ�
 *      *** ����ֹ��ƥ�䲻Ϣ��***
 */
void *btrie_find(btrie_node_t *root,
                 unsigned long count, /* str[]�ĳ�Ա���� */
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
        /* XXX: ����ʡ�Լ�飬���Ч�� */
        if (index >= count) {
            BUG();
            break;
        }

        val = &str[index];

        if (curr->flags & BTRIE_FLAG_WILDCARD) {
            /* ͨ���������Ҫ�Ƚ����ݣ�ֱ��ƥ���� */
            if (curr->data != NULL && val->len > 0) {
                /*
                 * ֻ��host֧��ͨ�������ͨ���ƥ��ǿ��ַ���������:
                 *     �й���*.baidu.com�����޷�ƥ��baidu.com
                 *     ��*.*.baidu.com���޷�ƥ��a.baidu.com
                 */
                ret = curr->data;
            }
            curr = curr->child;
            continue;
        }

        if (string_is_equal(&curr->str, val)) {
            /* ͬ��ǰ�ڵ�ƥ�� */
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

