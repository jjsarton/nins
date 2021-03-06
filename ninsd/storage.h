#ifndef STORAGE_H
#define STORAGE_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

#define NODE_INFO_GLOB  0x01
#define NODE_INFO_NAME  0x02
#define NODE_INFO_ALL   0x03
#define NODE_INFO_CHECK 0x04
#define NODE_HAS_IPV4   0x08
#define NODE_QUERY_MAP  0x10

#define NAME_SIZE_MAX 255
extern char server[NAME_SIZE_MAX];
 
typedef struct node_info_s {
    int             flag;
    time_t          last_seen;
    struct in6_addr local;
    char            name[NAME_SIZE_MAX+1];
    int             name_queries;
    struct in6_addr global;
    int             global_queries;
    struct in_addr  ipv4;
    int             ipv4_queries;
} node_info_t;

extern int node_info_add_elem(struct in6_addr* addr, int flag);
extern int node_info_add_global(struct in6_addr* local, struct in6_addr*global, int ttl, char *domain, char *updater);
extern int node_info_add_ipv4(struct in6_addr* local, struct in_addr*ipv4, int ttl, char *domain, char *updater);
extern int node_info_add_name(struct in6_addr* local, char* name, char *domain, int ttl, char *updater);
extern int remove_elem(node_info_t *node_info);
extern node_info_t *search_name(char* name);
extern node_info_t *search_global_address(struct in6_addr* addr);
extern node_info_t *search_local_address(struct in6_addr* addr);
extern node_info_t *search_incomplete(int ttl, char *domain, char *updater, int get_ipv4);
extern void delete_all_clients(char *domain, char *updater);
extern void set_query_mapped(struct in6_addr* addr);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* STORAGE_H */
