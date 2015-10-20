
default: test

test:
	gcc -o test cache_rule_test.c cache_rule.c btree_trie.c cache_host.c

lib:
	gcc -c cache_rule.c btree_trie.c cache_host.c
	ar -r libcacherule.a cache_rule.o btree_trie.o cache_host.o
	rm -f *.o

clean:
	rm -f test *.o *.a
