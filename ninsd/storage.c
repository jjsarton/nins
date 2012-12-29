#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>

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
static void call_nsupdate(node_info_t *ni, int ttl, char *domain, char *updater);
static void update_ns(int ttl, int del, char *domain, char *updater);

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

static int cpm_ipv4_addr(const list_t *a, const void *b)
{
    return memcmp((const void*)&(((node_info_t*)(a->data))->ipv4),
                  (const void*) b,
                  sizeof(struct in_addr));
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

node_info_t *search_ipv4_address(struct in_addr* addr)
{
    list_t *elem = list_search(root, addr, cpm_ipv4_addr);
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


int node_info_add_elem(struct in6_addr* addr, int flag )
{
    list_t *elem;
    node_info_t *ni;
    elem = list_search(root, addr, cpm_local_addr);
    if ( elem == NULL )
    {
        ni = create_element();
        if ( ni )
        {
            ni->last_seen = time(NULL);
            if ( flag == NODE_INFO_CHECK )
            {
                ni->flag |= NODE_INFO_CHECK;
            }
            memcpy(&ni->local, addr,sizeof(struct in6_addr));
            list_insert(&root, ni);
        }
    }
    else
    {
        ni = (node_info_t*)elem->data;
        ni->last_seen = time(NULL);
    }
    return 1;
}

int node_info_add_global(struct in6_addr* local, struct in6_addr* global, int ttl, char *domain, char *updater)
{
    list_t *elem;
    node_info_t *ni;
    elem = list_search(root, local, cpm_local_addr);
    if ( elem == NULL && global != NULL )
    {
        node_info_add_elem(local, 0);
        elem = list_search(root, local, cpm_local_addr);
    }
    if ( elem )
    {
        ni = (node_info_t*)elem->data;
        if ( global )
        {
            ni->global_queries = 0;
            memcpy(&ni->global, global, sizeof(*global));
            ni->last_seen = time(NULL);
            ni->flag |= NODE_INFO_GLOB;
            if ( (ni->flag & NODE_INFO_ALL) == NODE_INFO_ALL)
            {
                call_nsupdate(ni, ttl, domain, updater);
                ni->flag |= NODE_INFO_ALL;
            }
        }
        else
        {
            call_nsupdate(ni, 0, domain, updater);
        }
        ni->flag = ni->flag & ~ NODE_INFO_CHECK;
    }
    return 1;
}

int node_info_add_ipv4(struct in6_addr* local, struct in_addr* ipv4, int ttl, char *domain, char *updater)
{
    list_t *elem;
    node_info_t *ni;
    /* may be we get 127.0.0.1, don't allows this */
    if ( ((uint8_t*)ipv4)[0] == 127 )
    {
        return 1;
    }
    elem = list_search(root, local, cpm_local_addr);
    if ( elem )
    {
        ni = (node_info_t*)elem->data;
        ni->last_seen = time(NULL);
        if ( (ni->flag & NODE_INFO_ALL) == NODE_INFO_ALL )
        {
            ni->ipv4_queries = 0;
            ni->flag |= NODE_HAS_IPV4;
            ni->flag = ni->flag & ~(NODE_QUERY_MAP);
            if ( memcmp(&ni->ipv4, ipv4, sizeof(*ipv4)) )
            {
                memcpy(&ni->ipv4, ipv4, sizeof(*ipv4));
                call_nsupdate(ni, ttl, domain, updater);
            }
        }
    }
    return 1;
}

static void get_suffix(char *name, char *suffix, list_t *from)
{
    int len = strlen(name);
    char letters[26];
    char host_name[256];
    list_t *list = root;
    node_info_t *elem;
    int cmp;

    memset(letters, 0, sizeof(letters));
    if ( gethostname(host_name, sizeof(host_name)) == 0 )
    {
       cmp = strncmp(host_name, name, len);
       if ( cmp == 0 && (cmp && (host_name[len] == '.')) )
       {
//printf("Set suffix - :: 1\n");
          *suffix='-';
       }
    }

    /* look for assigned suffixes */
    while (list)
    {
        elem = (node_info_t*)list->data;
        if ( list != from )
        {
           if ( *elem->name )
           {
//printf("CMP %s %s %d\n",elem->name, name, len);
              cmp = strncmp(elem->name, name, len);
              if ( cmp == 0 && (cmp && (elem->name[len] == '.' || elem->name[len] == '-')) )
              {
                 *suffix='-';
 //printf("Set suffix - :: 2 %d %p %s \n",cmp,  elem, elem->name);
                if ( elem->name[len+1] && elem->name[len+2] && !elem->name[len+3] )
                 {
                    letters[tolower(elem->name[len+2])-'a'] = '1';
                 }
              }
           }
        }
        list = list->next;
    }

    /* take the first not used suffix */
    if ( *suffix )
    {
        for ( cmp = 0; cmp < sizeof(letters); cmp++ )
        {
            if (letters[cmp] == '\0' )
            {
                suffix[1] = cmp+ + 'a';
                break;
            }
        }
    }
}

int node_info_add_name(struct in6_addr* local, char* name, char *domain, int ttl, char *updater)
{
    int dlen = domain?strlen(domain)+1:0;
    list_t *elem;
    node_info_t *ni;

    elem = list_search(root, local, cpm_local_addr);

    if ( elem )
    {
        ni = (node_info_t*)elem->data;
        if ( !*ni->name )
        {
            ni->name_queries = 0;
            if ( domain )
            {
                char suffix[3];
                memset(suffix, 0, sizeof(suffix));
                get_suffix(name, suffix,elem);
                strncpy(ni->name, name, NAME_SIZE_MAX-dlen);
                if ( *suffix )
                   strcat(ni->name,suffix);
                strcat(ni->name,".");
                strcat(ni->name,domain);
            }
        }
        ni->flag |= NODE_INFO_NAME;
        ni->last_seen = time(NULL);
        if ( (ni->flag & NODE_INFO_ALL) == NODE_INFO_ALL)
        {
            call_nsupdate(ni, ttl, domain, updater);
            ni->flag = NODE_INFO_ALL;
        }
        ni->flag = ni->flag & ~NODE_INFO_CHECK;
    }
    return 1;
}

void set_query_mapped(struct in6_addr* addr)
{
    node_info_t *ni =search_local_address(addr);
    if ( ni )
    {
        ni->flag |= NODE_QUERY_MAP;
    }
}

node_info_t *search_incomplete(int ttl, char *domain, char *updater, int get_ipv4)
{
    time_t act_time;
    list_t *elem = root;
    node_info_t *ret = NULL;
    act_time = time(NULL);
    int del = 0;
    while(elem)
    {
        node_info_t *ni = (node_info_t *)elem->data;
        if ( !(ni->flag & NODE_INFO_NAME) && ni->global_queries < 3 )
        {
            return ni;
        }
        if ( ni->flag & NODE_QUERY_MAP )
        {
            return ni;
        }
        if ( ni->last_seen < act_time )
        {
            if ( ((ni->flag & NODE_INFO_GLOB) != NODE_INFO_GLOB) || (get_ipv4 && !(ni->flag & NODE_HAS_IPV4)) )
            {
                if ( ni->last_seen+5 < act_time )
                {
                    list_remove(&root, elem);
                    free(ni);
                    break; // entry must be removed no node_info ?
                }
                if ( ni->global_queries++ < 3)
                {
                    ret = ni; // call get addr from main loop
                    break;
                }
            }

            if ( act_time > ni->last_seen + ttl - 1  && !(ni->flag&NODE_INFO_CHECK) )
            {
                /* check if the node is alive */
                ni->flag |= NODE_INFO_CHECK;
                ni->last_seen = time(NULL);
                ni->name_queries = ni->global_queries = ni->ipv4_queries = 0;
                ret = ni; // check for availibility
                break;
            }
        }

        if ( ni->flag&NODE_INFO_CHECK && ni->last_seen + 3 > act_time )
        {
            /* if we have not got an answer for this node,
             * the node is no more available
             */
            ni->name_queries = ni->global_queries = ni->ipv4_queries = 0;
            ni->last_seen = 0;
            del = 1;
            break;
        }
        elem = elem->next;
    }
    update_ns(ttl, del, domain, updater);
    return ret;
}

static void call_nsupdate(node_info_t *info, int ttl, char *domain, char *updater)
{
    char str[256];
    if ( *info->name == '\0' )
    {
        return;
    }
 
    FILE *p = popen(updater, "w");
    if ( p )
    {
        syslog(LOG_INFO,"Update DNS Time %lu\n",time(NULL));
        syslog(LOG_INFO,"server ::1\n");
        syslog(LOG_INFO,"zone %s.\n",domain);
        syslog(LOG_INFO,"update delete %s AAAA\n", info->name);
        if ( info->flag&NODE_HAS_IPV4 )
        {
            syslog(LOG_INFO,"update delete %s A\n", info->name);
        }
        if ( ttl > 0 )
        {
            inet_ntop(AF_INET6, &info->global, str, sizeof(str));
            syslog(LOG_INFO,"update add %s %d AAAA %s\n", info->name, ttl, str);
            if ( info->flag&NODE_HAS_IPV4 )
            {
                inet_ntop(AF_INET, &info->ipv4, str, sizeof(str));
                syslog(LOG_INFO,"update add %s %d A %s\n", info->name, ttl, str);
            }
        }
        fprintf(p,"server ::1\n");
        fprintf(p,"update delete %s AAAA\n", info->name);
        if ( info->flag&NODE_HAS_IPV4 )
        {
            fprintf(p,"update delete %s A\n", info->name);
        }
        if ( ttl > 0 )
        {
            inet_ntop(AF_INET6, &info->global, str, sizeof(str));
            fprintf(p,"update add %s %d AAAA %s\n", info->name, ttl, str);
            if ( info->flag&NODE_HAS_IPV4 )
            {
                inet_ntop(AF_INET, &info->ipv4, str, sizeof(str));
                fprintf(p,"update add %s %d A %s\n", info->name, ttl, str);
            }
        }
        fprintf(p,"send\n");
        pclose(p);
    }
    else
    {
        syslog(LOG_ERR,"failed to open pipe; %s\n",strerror(errno));
    }
}

void update_ns(int ttl, int del, char *domain, char *updater)
{
    time_t act_time = time(NULL);
    list_t *elem = root;

    while(elem)
    {
        node_info_t *ni = (node_info_t *)elem->data;
        /* add a little grace time (2 sec.) in order to avoid
         * premature deletion.
         */
        if ( del && ni->last_seen + ttl < act_time )
        {
            if ((ni->flag & NODE_INFO_CHECK) == NODE_INFO_CHECK )
            {
                /* call nsupdate  for remove */
                call_nsupdate(ni, 0, domain, updater);
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
        call_nsupdate(ni, 0, domain, updater);
        list_remove(&root, elem);
        free(ni);
        elem = root;
    }
}
