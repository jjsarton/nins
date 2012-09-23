/* send.c
 * build and send icmp-v6 messaged
 */
 
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
#include <stdint.h>
#include <syslog.h>

#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <sys/uio.h>

#include <poll.h>

#include "decode_ra.h"
#include "ninfo.h"
#include "send.h"


static int send_probe(int sock, uint8_t *buf, struct in6_addr *addr, int len, int set_hop)
{
    struct sockaddr_in6 whereto;
    memset(&whereto,0, sizeof(struct sockaddr_in6));
    whereto.sin6_family = AF_INET6;
    whereto.sin6_port = htons(IPPROTO_ICMPV6);
    memcpy(&whereto.sin6_addr, addr, sizeof(struct in6_addr));

    if ( set_hop )
    {
        /* handle ra solicit and echo request so that
         * we will get an answer
         */
        int hoplimit;
        socklen_t hlen = sizeof(hoplimit);
        hoplimit = set_hop;
        setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, hlen);
    }

    int  cc;
    struct msghdr mhdr;
    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    memset(&mhdr, 0, sizeof(mhdr));

    iov.iov_len  = len;
    iov.iov_base = buf;
    mhdr.msg_name = &whereto;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;

    cc = sendmsg(sock, &mhdr, 0);
    if ( cc < 0 )
    {
       static char str[128];
       inet_ntop(AF_INET6, addr, str, sizeof(str));
       syslog(LOG_ERR,"sendmsg to %s: %s",str,strerror(errno));
    }
    return (cc == len ? 0 : cc);

}

static int build_niquery(uint8_t *buf, struct in6_addr *addr,  int ni_query_code)
{
    struct ni_hdr *nih = (struct ni_hdr *)buf;
    void *ni_subject = NULL;
    int cc;
    int i;

    nih->ni_type = ICMPV6_NI_QUERY;
    nih->ni_code = NI_SUBJ_IPV6;
    nih->ni_cksum = 0;
    nih->ni_qtype = htons(ni_query_code);
    switch(ni_query_code)
    {
        case NI_QTYPE_IPV6ADDR:
            nih->ni_flags = NI_IPV6ADDR_F_GLOBAL;
        break;
        case NI_QTYPE_IPV4ADDR:
            nih->ni_flags = 0;
        break;
        default:
           nih->ni_flags = 0;
    }
    for (i = 0; i < 8; i++)
        nih->ni_nonce[i] = rand();
    cc = sizeof(*nih);

    /* header build now fill query data */
    ni_subject = (uint8_t*)buf+cc;
    memcpy(ni_subject, addr, sizeof(struct in6_addr));

    cc += sizeof(struct in6_addr);

    return cc;
}

int query_addr(int sock, uint8_t *buf, struct in6_addr *addr)
{
    int cc;
    cc = build_niquery(buf, addr, NI_QTYPE_IPV6ADDR);
    return send_probe(sock, buf, addr, cc, 0);
}

int query_ipv4(int sock, uint8_t *buf, struct in6_addr *addr)
{
    int cc;
    cc = build_niquery(buf, addr, NI_QTYPE_IPV4ADDR);
    return send_probe(sock, buf, addr, cc, 0);
}

int query_name(int sock, uint8_t *buf, struct in6_addr *addr)
{
    int cc;
    cc = build_niquery(buf, addr, NI_QTYPE_NAME);
    return send_probe(sock, buf, addr, cc, 0);
}

int send_ra_solicit(int sock, uint8_t *buf)
{
    int err;
    struct in6_addr addr;
    /* set receiver address */
    inet_pton(AF_INET6, "ff02::02", &addr);

    /* build the message */
    struct nd_router_solicit *solicit;
    solicit = (struct nd_router_solicit*)buf;
    solicit->nd_rs_type = ND_ROUTER_SOLICIT;
    solicit->nd_rs_code = 0;
    solicit->nd_rs_cksum = 0;
    solicit->nd_rs_reserved = 0;
    uint8_t *p = (uint8_t*)buf + sizeof(struct nd_router_solicit);
    err = send_probe(sock, buf, &addr, p - buf, 255);
    return err;
}

int send_echo_query(int sock, uint8_t *buf)
{
    static unsigned short seq =1;
    int err;
    struct in6_addr addr;
    /* set receiver address */
    inet_pton(AF_INET6, "ff02::01", &addr);
    struct icmp6_hdr *req;
    req = (struct icmp6_hdr*)buf;
    memset(req,0,sizeof(struct icmp6_hdr));
    req->icmp6_type = ICMP6_ECHO_REQUEST;
    req->icmp6_id = htons(getpid());
    req->icmp6_seq = htons(seq);
    if ( seq == 65535 )
        seq = 1;
    else
        seq++;
    uint8_t *p = (uint8_t*)buf + sizeof(struct icmp6_hdr);
    err = send_probe(sock, buf, &addr, p - buf, 255);
    return err;
}
