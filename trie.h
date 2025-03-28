#ifndef TRIE_H
#define TRIE_H

#include <unistd.h>
#include <stdint.h>
#include "lib.h"

struct route_trie;
typedef struct route_trie *route_trie;

/* Create an empty trie */
extern route_trie create_trie(void);

/* Insert an element in the trie */
void trie_insert(route_trie t, uint32_t prefix, uint32_t mask,
                 struct route_table_entry *route_entry);

/* Fetch the best matching route_table_entry */
extern struct route_table_entry *trie_match(route_trie t, uint32_t ip);

#endif
