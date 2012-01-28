#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/time.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <sys/uio.h>

#include <poll.h>

#include "storage.h"
#include "decode_ra.h"
#include "ninfo.h"
#include "version.h"

#define MAXPACKET 4096

/* check at last every 10 minute for life */
#define TTL_MAX 600

static int ttl_max = TTL_MAX;
static int sock = -1;

struct sockaddr_in6 whereto; /* who to ping */
uint8_t outpack[MAXPACKET];

static char domain[NAME_SIZE_MAX];
static int ttl = 0;
static struct in6_addr own_addr;

/* Node Information query */
int ni_query = -1;
int ni_flag = 0;
void *ni_subject = NULL;
int ni_subject_len = 8;

uint8_t ni_nonce[8];

static struct in6_addr in6_anyaddr;
static int cmsglen = 0;
static unsigned char cmsgbuf[4096];

static char *print_addr(struct in6_addr *addr);
static int send_probe(int len, int set_hop);

static __inline__ int ipv6_addr_any(struct in6_addr *addr)
{
    return (memcmp(addr, &in6_anyaddr, 16) == 0);
}

int icmp_socket(char *device)
{
    struct icmp6_filter filter;
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if ( sock > 0 )
    {
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);  // 129 get node liste (ping6 -c1  -I eth0 ff02::1)
        ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter); // 133 new node inserted
        ICMP6_FILTER_SETPASS(ICMPV6_NI_REPLY, &filter);   // 140 yes we need this for name an ip query
                                                          // we can set a broad cast  ff02::1 or directly query the local link address
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT,&filter);   // for search and ns server ( if we need this
        ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT,&filter); // fneighbor Advertisment for the case of DHCPv6

        if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(struct icmp6_filter))<0)
        {
            perror("setsockopt");
            sock=-1;
        }
        else
        {
            if ( device )
            {
                if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)+1)<0)
                {
                    sock=-1;
                    perror("setsockopt");
                }
            }
        }
    }
    else
    {
        perror("socket");
    }
    return sock;
}

int send_ra_solicit(unsigned char *buf, struct sockaddr_in6 *whereto)
{
    int err;
    inet_pton(AF_INET6, "ff02::02", &whereto->sin6_addr);
    /* build a message */
    struct nd_router_solicit *solicit;
    solicit = (struct nd_router_solicit*)buf;
    solicit->nd_rs_type = ND_ROUTER_SOLICIT;
    solicit->nd_rs_code = 0;
    solicit->nd_rs_cksum = 0;
    solicit->nd_rs_reserved = 0;
    unsigned char *p = (unsigned char*)buf + sizeof(struct nd_router_solicit);
    err = send_probe(p - buf,1);
    return err;
}

int echo_request(unsigned char *buf, struct sockaddr_in6 *whereto)
{
    int err;
    /* this will send a echo request which will only
     * be answered from our local link address
     */
    inet_pton(AF_INET6, "ff02::01", &whereto->sin6_addr);
    struct icmp6_hdr *icmph = (struct icmp6_hdr*)buf;
    icmph->icmp6_type = ICMP6_ECHO_REQUEST;
    icmph->icmp6_code = 0;
    icmph->icmp6_cksum = 0;
    icmph->icmp6_id = 0; /* not process with id = 0 -> we are means */
    err = send_probe(sizeof(struct icmp6_hdr),-1);
    return err;
}

static int send_probe(int len, int set_hop)
{
    if ( set_hop )
    {
        /* handle ra solicit and echo request so that
         * we will get an answer
         */
        int hoplimit = 64;
        socklen_t hlen = sizeof(hoplimit);
        hoplimit = set_hop == -1?0:255;
        setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, hlen);
    }


    int  cc;
    struct msghdr mhdr;
    struct iovec iov;

    iov.iov_len  = len;
    iov.iov_base = outpack;
    mhdr.msg_name = &whereto;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = cmsgbuf;
    mhdr.msg_controllen = cmsglen;

    cc = sendmsg(sock, &mhdr, 0);
    if ( cc < 0 )
    {
        perror("sendmsg");
    }
    return (cc == len ? 0 : cc);

}

int build_niquery(struct in6_addr *addr, uint8_t *_nih, int ni_query_code)
{
    struct ni_hdr *nih;
    int cc;

    nih = (struct ni_hdr *)_nih;
    nih->ni_cksum = 0;

    nih->ni_type = ICMPV6_NI_QUERY;
    cc = sizeof(*nih);

    memcpy(nih->ni_nonce, ni_nonce, sizeof(nih->ni_nonce));

    nih->ni_code = NI_SUBJ_IPV6;
    nih->ni_qtype = htons(ni_query_code);
    nih->ni_flags = ni_query_code==NI_QTYPE_IPV6ADDR?(NI_IPV6ADDR_F_GLOBAL):0;

    ni_subject = &whereto.sin6_addr;
    ni_subject_len = sizeof(whereto.sin6_addr);

    memcpy(nih + 1, ni_subject, ni_subject_len);
    cc += ni_subject_len;

    return cc;
}

void query_addr(struct in6_addr *addr)
{
    int i;
    for (i = 0; i < 8; i++)
        ni_nonce[i] = rand();
    memcpy(&whereto.sin6_addr, addr, sizeof(struct in6_addr));
    i = build_niquery(addr,outpack,NI_QTYPE_IPV6ADDR);
    send_probe(i,0);
}

void query_name(struct in6_addr *addr)
{
    int i;
    for (i = 0; i < 8; i++)
        ni_nonce[i] = rand();
    memcpy(&whereto.sin6_addr, addr, sizeof(struct in6_addr));
    i = build_niquery(addr,outpack,NI_QTYPE_NAME);
    send_probe(i,0);
}

char *print_addr(struct in6_addr *addr)
{
    static char str[128];
    inet_ntop(AF_INET6, addr, str, sizeof(str));
    return str;
}

int parse_reply(struct msghdr *msg, int cc, void *addr)
{
    struct sockaddr_in6 *from = addr;
    uint8_t *buf = msg->msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;

    for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
        if (c->cmsg_level != SOL_IPV6)
            continue;
        switch(c->cmsg_type) {
        case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
        case IPV6_2292HOPLIMIT:
#endif
            if (c->cmsg_len < CMSG_LEN(sizeof(int)))
                continue;
        }
    }

    /* Now the ICMP part */

    icmph = (struct icmp6_hdr *) buf;
    struct ni_hdr *nih = (struct ni_hdr*) buf;
    if (cc < 8) {
        return 1;
    }
    switch (icmph->icmp6_type)
    {
        case ICMP6_ECHO_REPLY:
            printf("got ICMP6_ECHO_REPLY from %s\n", print_addr(&from->sin6_addr));
            if ( icmph->icmp6_id == 0)
            {
                /* answer from our interface */
                memcpy(&own_addr, &from->sin6_addr, sizeof(own_addr));
            }
        break;
        case ICMPV6_NI_REPLY:
            printf("got ICMPV6_NI_REPLY from %s ", print_addr(&from->sin6_addr));
            if ( memcmp(&own_addr, &from->sin6_addr, sizeof(own_addr)) == 0 )
            {
                printf("\n");
                break;
            }
            int nl;
            int len;
            switch(ntohs(nih->ni_qtype))
            {
                case NI_QTYPE_NAME:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 2 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        data++;
                        data[nl] = '\0';
                        printf("name %s\n",data);
                        node_info_add_name(&from->sin6_addr,(char*)data, domain, ttl);
                    }
                break;
                case NI_QTYPE_IPV6ADDR:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 23 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        printf("Addr %s\n",print_addr((struct in6_addr*)data));
                        node_info_add_global(&from->sin6_addr,(struct in6_addr*)data, ttl, domain);
                    }
                    else
                    {
                        printf("\n");
                    }
                break;
                default:
                    printf("Other NI_QTYPE\n");
            }
        break;
        case ND_ROUTER_SOLICIT:
            printf("got ND_ROUTER_SOLICIT from %s\n", print_addr(&from->sin6_addr));
            node_info_add_elem(&from->sin6_addr);
        break;
        break;
        case ND_ROUTER_ADVERT:
            printf("got ND_ROUTER_ADVERT from %s\n", print_addr(&from->sin6_addr));
            struct in6_addr ns_server;
            memset(&ns_server, 0, sizeof(ns_server));
            decode_router_advertisement(icmph, cc, &ns_server, &ttl, domain);
            if ( ttl == 0 )
            {
                delete_all_clients(domain);
            }
            else if ( ttl > ttl_max )
            {
                ttl = ttl_max;
            }
        break;
        case ND_NEIGHBOR_ADVERT:
            printf("got ND_NEIGHBOR_ADVERT from %s\n", print_addr(&from->sin6_addr));
            if ( memcmp(&own_addr, &from->sin6_addr, sizeof(own_addr)) )
            {
                node_info_add_elem(&from->sin6_addr);
            }
            break;
        default:
            printf("Received type %d\n",icmph->icmp6_type);
        break;
    }
    return 0;
}

void complete_info(int ttl)
{
    node_info_t *ni = search_incomplete(ttl, domain);
    if ( ni )
    {
        if (!(ni->flag&NODE_INFO_NAME))
            query_name(&ni->local);
        if ( !(ni->flag&NODE_INFO_GLOB))
            query_addr(&ni->local);
        if ( (ni->flag&NODE_INFO_CHECK) == NODE_INFO_CHECK)
            query_addr(&ni->local);
    }
}

int mainloop(int sock, int packlen)
{
    struct pollfd pollfd;

    char addrbuf[128];
    char ans_data[4096];
    struct iovec iov;
    struct msghdr msg;
    int cc;
    int polling = MSG_DONTWAIT;
    int send_echo_request = 1;
    pollfd.fd = sock;
    pollfd.events = POLLIN;
    pollfd.revents = 0;

    /* get out link local address */
    echo_request(outpack,&whereto);
    /* make shure that radvd send a router advertisement */
    send_ra_solicit(outpack,&whereto);

    for(;;)
    {
        poll(&pollfd, 1, 1000);
        if ( (pollfd.revents & POLLIN) == POLLIN )
        {
            iov.iov_len = packlen;
            iov.iov_base = ans_data;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = addrbuf;
            msg.msg_namelen = sizeof(addrbuf);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ans_data;
            msg.msg_controllen = sizeof(ans_data);
            cc = recvmsg(sock, &msg, polling);
            if (cc < 0)
            {
                perror("recvmsg");
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
            }
            else
            {
                parse_reply(&msg, cc, addrbuf);
                if ( ttl == 0 )
                    send_echo_request = 1;
            }
        }
        else if (ttl)
        {
            // check for task to be done;
            complete_info(ttl);
            if ( send_echo_request )
            {
                int i;
                    for (i = 0; i < 8; i++)
                        ni_nonce[i] = rand();
                struct in6_addr addr;
                inet_pton(AF_INET6, "ff02::1", &addr);
                query_name(&addr);
                send_echo_request = 0;
            }
        }
    }
    return 0;
}

char *prgName = NULL;

static void usage(char *me)
{
    fprintf(stderr,"Usage %s -i interface [-v] [-f] [-t ttl_max]\n",me);
    abort();
}

int main(int argc, char **argv)
{
    int packlen =  8 + 4096 + 40 + 8; 
    char *device = NULL;
    int c;
    int foreground = 0;
    int t;

    prgName = argv[0];
    if ( prgName && (prgName=strrchr(prgName,'/')) )
        prgName++;

    while( (c = getopt(argc, argv, "i:vft:")) > 0)
    {
        switch(c)
        {
            case 'i':
                device = optarg;
            break;
            case 'v':
                printf("%s: wersion %s\n",prgName, version);
                exit(0);
            break;
            case 'f':
                foreground=1;
            break;
            case 't':
                t = atoi(optarg);
                if ( t > 0 )
                    ttl_max = t;
            break;
            default:
                usage(prgName);
            break;
        }
    }

    if ( device == NULL )
    {
        usage(prgName);
    }

    memset(&own_addr,0,sizeof(own_addr));

    if ( ! foreground )
    {
        if (daemon(0, 0) < 0)
        {
            perror("daemon");
            exit(1);
        }
    }

    sock = icmp_socket(device);

    if ( sock < 0 )
    {
        return 1;
    }

    /* preset target addr values */
    memset(&whereto,0, sizeof(struct sockaddr_in6));
    whereto.sin6_family = AF_INET6;
    whereto.sin6_port = htons(IPPROTO_ICMPV6);

    mainloop(sock, packlen);
    return 0;
}
