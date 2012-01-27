#ifndef STORAGE_H
#define STORAGE_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

#define NODE_INFO_GLOB  0x01
#define NODE_INFO_NAME  0x02
#define NODE_INFO_ALL   0x03
#define NODE_INFO_CHECK 0x04

#define NAME_SIZE_MAX 255

typedef struct node_info_s {
    int             flag;
    struct timeval  last_seen;
    struct in6_addr local;
    struct in6_addr global;
    char            name[NAME_SIZE_MAX+1];
} node_info_t;

extern int node_info_add_elem(struct in6_addr* addr);
extern int node_info_add_global(struct in6_addr* local, struct in6_addr*global, int ttl, char *domain);
extern int node_info_add_name(struct in6_addr* local, char* name, char *domain, int ttl);
extern int remove_elem(node_info_t *node_info);
extern node_info_t *search_name(char* name);
extern node_info_t *search_global_address(struct in6_addr* addr);
extern node_info_t *search_local_address(struct in6_addr* addr);
extern node_info_t *search_incomplete(int ttl, char *domain);
extern void delete_all_clients(char *domain);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* STORAGE_H */
