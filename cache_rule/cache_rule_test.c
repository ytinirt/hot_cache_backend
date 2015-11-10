#include <stdio.h>

#include "cache_rule.h"

#define BUFFER_LEN 512


static void process(cache_rule_ctx_t *ctx, char *url_string)
{
    cache_rule_t *rule;
    string_t url, key, file;
    char buffer[BUFFER_LEN];
    char *p;

    p = strstr(url_string, "http://");
    if (p == NULL) {
        url.data = url_string;
    } else {
        url.data = p + 7;
    }
    url.len = strlen(url.data);

    printf("URL:  %s\n", url.data);

    if (url.len >= BUFFER_LEN) {
        printf("URL too long: %d.\n", BUFFER_LEN);
        goto out;
    }
    rule = cache_rule_get_rule(ctx, &url);
    if (rule == NULL) {
        printf("Not find rule.\n");
        goto out;
    }

    if (rule->action_flags & CACHE_ACTION_DBG_PRINT) {
        printf("DBG:  %s\n", url.data);
        goto out;
    }

    key.len = BUFFER_LEN;
    key.data = buffer;
    if (cache_rule_url2local_key(&url, rule, &key) != 0) {
        printf("Gen key failed.\n");
        goto out;
    }
    printf("KEY:  %s\n", key.data);

    file.len = BUFFER_LEN;
    file.data = buffer;
    if (cache_rule_url2local_file(&url, rule, &file) != 0) {
        printf("Gen file failed.\n");
        goto out;
    }
    printf("FILE: %s\n", file.data);

out:
    printf("\n");

    return;
}

void walk_func(cache_host_t *h)
{
    cache_host_t *same_as;

    if (h == NULL) {
        return;
    }

    if (h->flags & CACHE_HOST_SAME_AS) {
        same_as = h->same_as;
        printf("[SAME-AS] %-48s: same as %s (%lu)\n", h->host.data,
                        (same_as != NULL) ? same_as->host.data : "<NULL>",
                        same_as->rule_num);
    } else {
        printf("[%s%-48s: RULE %lu\n", (h->flags & CACHE_HOST_DEFAULT) ? "DEFAULT] " : "CONFIG]  ",
                        h->host.data, h->rule_num);
    }

}

int main(int argc, char *argv[])
{
    char buffer[BUFFER_LEN + 16];   /* °üÀ¨"http://" */
    int rules_num;
    cache_rule_stats_t stats;
    cache_rule_ctx_t *ctx;
    int percent;

    if (argc >= 2) {
        rules_num = cache_rule_load(argv[1], &ctx);
        if (rules_num < 0) {
            printf("Load rules failed: %s\n", argv[1]);
            return -1;
        } else {
            printf("Load %d rules\n", rules_num);
        }
    } else {
        return -1;
    }

    cache_rule_walk_host(ctx, walk_func);

    cache_rule_dump_symtab(ctx);
    cache_rule_dump_host_hash(ctx);

    cache_rule_get_stats(ctx, &stats);
    printf("Total mem:  %lu bytes\n", stats.mem_total);
    percent = (stats.host_in_use * 100) / stats.host_capacity;
    printf("Host:       [%2d%%] %d/%d, %s\n", percent, stats.host_in_use, stats.host_capacity,
                                              stats.host_default_exist ? "default host exists" : "");
    percent = (stats.rule_in_use * 100) / stats.rule_capacity;
    printf("Rule:       [%2d%%] %d/%d\n", percent, stats.rule_in_use, stats.rule_capacity);
    percent = (stats.btrie_node_in_use * 100) / stats.btrie_node_capacity;
    printf("Btrie node: [%2d%%] %d/%d\n", percent, stats.btrie_node_in_use, stats.btrie_node_capacity);
    percent = (stats.host_hte_in_use * 100) / stats.host_hte_capacity;
    printf("Host HTE:   [%2d%%] %d/%d\n", percent, stats.host_hte_in_use, stats.host_hte_capacity);
    percent = (stats.symtab_used * 100) / stats.symtab_limit;
    printf("Symbuf:     [%2d%%] %d/%d\n", percent, stats.symtab_used, stats.symtab_limit);

    while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        if (buffer[0] == '\n') {
            continue;
        }
        buffer[strlen(buffer) - 1] = '\0';
        process(ctx, buffer);
    }

    return 0;
}


