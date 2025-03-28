#include "trie.h"

#include <unistd.h>
#include <stdint.h>
#include "lib.h"

struct route_trie
{
    route_trie nodes[2];
    struct route_table_entry *route_entry;
};

route_trie create_trie(void)
{
    route_trie t = malloc(sizeof(struct route_trie));
    t->nodes[0] = NULL;
    t->nodes[1] = NULL;
    t->route_entry = NULL;

    return t;
}

void trie_insert(route_trie t, uint32_t prefix, uint32_t mask,
                 struct route_table_entry *route_entry)
{
    /* Mask ended */
    if (!mask) {
        t->route_entry = route_entry;
        return;
    }

    /* Decide where to go next */
    int next = prefix & 1;
    if (t->nodes[next] == NULL)
    {
        t->nodes[next] = create_trie();
    }
    trie_insert(t->nodes[next], prefix >> 1, mask >> 1, route_entry);
}

struct route_table_entry *trie_match(route_trie t, uint32_t ip)
{
    /* Decide where to go next */
    int next = ip & 1;
    if (t->nodes[next] == NULL)
    {
        return t->route_entry;
    }

    /* Carry best. Further means a greater mask -> better */
    struct route_table_entry *rtable_entry =
            trie_match(t->nodes[next], ip >> 1);
    return rtable_entry != NULL ? rtable_entry : t->route_entry;
}
