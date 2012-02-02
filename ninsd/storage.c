#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/errqueue.h>
#include <linux/filter.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "list.h"
#include "storage.h"

extern char *print_addr(struct in6_addr *addr);

static list_t *root = NULL;

static node_info_t *create_element(void);
static int cpm_local_addr(const list_t *a, const void *b);
static int cpm_global_addr(const list_t *a, const void *b);
static int cpm_name(const list_t *a, const void *b);
static void call_nsupdate(struct in6_addr *addr, char *name, int ttl, char *domain, char *updater);
static void update_ns(int ttl, char *domain, char *updater);

static node_info_t *create_element(void)
{
    node_info_t *new;
    if ( (new = malloc(sizeof(node_info_t))) )
    {
        memset(new, 0, sizeof(node_info_t));
    }
    return new;
}

static int cpm_local_addr(const list_t *a, const void *b)
{
    return memcmp((const void*)&(((node_info_t*)(a->data))->local),
                  (const void*) b,
                  sizeof(struct in6_addr));
}

static int cpm_global_addr(const list_t *a, const void *b)
{
    return memcmp((const void*)&(((node_info_t*)(a->data))->global),
                  (const void*) b,
                  sizeof(struct in6_addr));
}

static int cpm_name(const list_t *a, const void *b)
{
    return strcmp(((node_info_t*)(a->data))->name,
                  (char*)b);
}

node_info_t *search_local_address(struct in6_addr* addr)
{
    list_t *elem = list_search(root, addr, cpm_local_addr);
    if (elem)
    {
        return (node_info_t *)elem->data;
    }
    return (node_info_t *)NULL;
}

node_info_t *search_global_address(struct in6_addr* addr)
{
    list_t *elem = list_search(root, addr, cpm_global_addr);
    if (elem)
    {
        return (node_info_t *)elem->data;
    }
    return (node_info_t *)NULL;
}

node_info_t *search_name(char* name)
{
    list_t *elem = list_search(root, name, cpm_name);
    if (elem)
    {
        return (node_info_t *)elem->data;
    }
    return (node_info_t *)NULL;
}

int remove_elem(node_info_t *node_info)
{
    list_t *elem = root;
    while(elem)
    {
        if ( elem->data == (void*)node_info )
        {
            if (list_remove(&root, elem) )
            {
                free(node_info);
                break;
            }
        }
        elem = elem->next;
    }
    return 1;
}


int node_info_add_elem(struct in6_addr* addr )
{
    list_t *elem;
    node_info_t *ni;
    elem = list_search(root, addr, cpm_local_addr);
    if ( elem == NULL )
    {
        ni = create_element();
        if ( ni )
        {
            gettimeofday(&ni->last_seen, NULL);
            memcpy(&ni->local, addr,sizeof(struct in6_addr));
            list_insert(&root, ni);
        }
    }
    else
    {
        ni = (node_info_t*)elem->data;
        gettimeofday(&ni->last_seen, NULL);
    }
    return 1;
}

int node_info_add_global(struct in6_addr* local, struct in6_addr* global, int ttl, char *domain, char *updater)
{
    list_t *elem;
    node_info_t *ni;
    elem = list_search(root, local, cpm_local_addr);
    if ( elem == NULL )
    {
        node_info_add_elem(local);
        elem = list_search(root, local, cpm_local_addr);
    }
    if ( elem )
    {
        ni = (node_info_t*)elem->data;
        memcpy(&ni->global, global, sizeof(*global));
        gettimeofday(&ni->last_seen, NULL);
        ni->flag |= NODE_INFO_GLOB;
        if ( (ni->flag & NODE_INFO_ALL) == NODE_INFO_ALL)
        {
            call_nsupdate(&ni->global, ni->name, ttl, domain, updater);
            ni->flag = NODE_INFO_ALL;
        }
    }
    return 1;
}

int node_info_add_name(struct in6_addr* local, char* name, char *domain, int ttl, char *updater)
{
    int dlen = domain?strlen(domain)+1:0;
    list_t *elem;
    node_info_t *ni;
    elem = list_search(root, local, cpm_local_addr);
    if ( elem == NULL )
    {
        node_info_add_elem(local);
        elem = list_search(root, local, cpm_local_addr);
    }

    if ( elem )
    {
        ni = (node_info_t*)elem->data;
        strncpy(ni->name, name, NAME_SIZE_MAX-dlen);
        if ( domain )
        {
            strcat(ni->name,".");
            strcat(ni->name,domain);
        }
        ni->flag |= NODE_INFO_NAME;
        gettimeofday(&ni->last_seen,NULL);
        if ( (ni->flag & NODE_INFO_ALL) == NODE_INFO_ALL)
        {
            call_nsupdate(&ni->global, ni->name, ttl, domain, updater);
            ni->flag = NODE_INFO_ALL;
        }
    }
    return 1;
}

node_info_t *search_incomplete(int ttl, char *domain, char *updater)
{
    struct timeval  act_time;
    list_t *elem = root;
    node_info_t *ret = NULL;
    gettimeofday(&act_time, NULL);
    while(elem)
    {
        node_info_t *ni = (node_info_t *)elem->data;
        if ( ni->last_seen.tv_sec < act_time.tv_sec+1 )
        {
            if ( (ni->flag & NODE_INFO_GLOB) != NODE_INFO_GLOB )
            {
                if ( ni->last_seen.tv_sec+3 < act_time.tv_sec )
                {
                    list_remove(&root, elem);
                    free(ni);
                    break; // entry must be removed
                }
                ret = ni; // call get addr from main loop
                break;
            }
            if ( act_time.tv_sec > ni->last_seen.tv_sec + ttl && !(ni->flag&NODE_INFO_CHECK) )
            {
                ni->flag |= NODE_INFO_CHECK;
                gettimeofday(&ni->last_seen, NULL);
                ret = ni; // check for availibility
                break;
            }
        }
        elem = elem->next;
    }
    update_ns(0, domain, updater);
    return ret;
}

static void call_nsupdate(struct in6_addr *addr, char *name, int ttl, char *domain, char *updater)
{
    char str[256];
    inet_ntop(AF_INET6, addr, str, sizeof(str));
    FILE *p = popen(updater, "w");
    if ( p )
    {
        printf("server ::1\n");
        printf("zone %s.\n",domain);
        printf("update delete %s AAAA\n", name);
        if ( ttl > 0 )
            printf("update add %s %d AAAA %s\n", name, ttl, str);

        fprintf(p,"server ::1\n");
        fprintf(p,"update delete %s AAAA %s\n", name, str);
        if ( ttl > 0 )
            fprintf(p,"update add %s %d AAAA %s\n", name, ttl, str);
        fprintf(p,"send\n");
        pclose(p);
    }
}

void update_ns(int ttl, char *domain, char *updater)
{
    struct timeval  act_time;
    list_t *elem = root;
    gettimeofday(&act_time, NULL);
    while(elem)
    {
        node_info_t *ni = (node_info_t *)elem->data;
        if ( ni->last_seen.tv_sec + ttl < act_time.tv_sec )
        {
            if ((ni->flag & NODE_INFO_CHECK) == NODE_INFO_CHECK )
            {
                /* call nsupdate  for remove */
                call_nsupdate(&ni->global, ni->name,0, domain, updater);
                list_remove(&root, elem);
                free(ni);
                break;
            }
        }
        elem = elem->next;
    }
}

void delete_all_clients(char *domain, char *updater)
{
    node_info_t *ni;
    list_t *elem = root;
    while (elem)
    {
        ni = (node_info_t *)elem->data;
        call_nsupdate(&ni->global, ni->name,0, domain, updater);
        list_remove(&root, elem);
        free(ni);
        elem = root;
    }
}
