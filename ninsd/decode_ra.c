#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "decode_ra.h"

#if ! defined ND_OPT_RNDSS_INFORMATION
#define ND_OPT_RNDSS_INFORMATION 25
#endif

#if ! defined ND_OPT_DNSSL_INFORMATION
#define ND_OPT_DNSSL_INFORMATION 31
#endif

typedef struct ra_xxx_info_head
{
    uint8_t type;
    uint8_t length;
    uint16_t reserved;
    uint32_t lifetime;
} ra_xxx_head_t;

static char ip_nsserver[INET6_ADDRSTRLEN];

int decode_router_advertisement(struct icmp6_hdr *icmph, int len, struct in6_addr* ns_server, int *ttl, char *domain)
{
    uint8_t *list;
    ra_xxx_head_t *opt_head;
    struct nd_opt_hdr *opt_hdr;
    unsigned char *data = (unsigned char *)icmph + sizeof(struct icmp6_hdr) + sizeof(struct icmp6_hdr);
    len -= (char*)data-(char*)icmph;
    
    while (len > 0 )
    {
        opt_hdr = (struct nd_opt_hdr *)data;
        switch(opt_hdr->nd_opt_type)
        {
            case ND_OPT_RNDSS_INFORMATION:

                opt_head = (ra_xxx_head_t *) data;
                *ttl = (int)ntohl(opt_head->lifetime);
                list = data + sizeof(ra_xxx_head_t);
                memcpy(ns_server, list, sizeof(struct in6_addr));
                inet_ntop(AF_INET6, ns_server, ip_nsserver, sizeof(ip_nsserver));
            break;

            case ND_OPT_DNSSL_INFORMATION:
                
                list = data + sizeof(ra_xxx_head_t);
                *domain = '\0';
                uint8_t l;
                char *t = domain;
                while( (l = *list) )
                {
                    list++;
                    strncpy(t, (char*)list, l);
                    list += l;
                    t += l;
                    if ( *list )
                    {
                        *t++ = '.';
                    }
                    *t = '\0';
                }
            break;
        }
        data += opt_hdr->nd_opt_len * 8;
        len  -= opt_hdr->nd_opt_len * 8;
    }
    return 1;
}

