/* getprefix.c */
/* get IPv6 prefix for a given link from router advertisement */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <poll.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static int icmp_socket(char *name)
{
    struct icmp6_filter filter;
    int sock = -1;

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if ( sock > 0 )
    {

        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT,&filter);

        if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER,
                       &filter, sizeof(struct icmp6_filter)) < 0 )
        {
            perror("setsockopt: %s");
            close(sock);
            sock = -1;
        }
        else
        {
            if ( name )
            {
                if (setsockopt(sock, SOL_SOCKET,
                               SO_BINDTODEVICE, name,
                               strlen(name)+1) < 0 )
                {
                    perror("setsockopt:");
                    close(sock);
                    sock = -1;
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

static void usage(char *me)
{
    fprintf(stderr,"Syntax: %s -i <interface>\n",me);
}

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
       fprintf(stderr,"sendmsg to %s: %s\n",str,strerror(errno));
    }
    return (cc == len ? 0 : cc);

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

int parse_reply(struct msghdr *msg, int cc)
{
    uint8_t *buf = msg->msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;
    struct in6_addr any = IN6ADDR_ANY_INIT;

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
    if (cc < 8)
    {
        return 1;
    }

    struct nd_opt_hdr *opt_hdr = NULL;
    unsigned char *data = NULL;
    switch (icmph->icmp6_type)
    {
        case ND_ROUTER_ADVERT:
            /* walk though datas up to the prefix (ND_OPT_PREFIX_INFORMATION) */

            data = (unsigned char *)icmph + sizeof(struct icmp6_hdr) + sizeof(struct icmp6_hdr);
            cc -= (char*)data-(char*)icmph;
            while (cc > 0 )
            {
                opt_hdr = (struct nd_opt_hdr *)data;
                if (opt_hdr->nd_opt_type == ND_OPT_PREFIX_INFORMATION )
                {
                    struct nd_opt_prefix_info *pinfo = (struct nd_opt_prefix_info *)data;
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &pinfo->nd_opt_pi_prefix, str, sizeof(str));
                    printf("%s\n",str);
                    return 0;
                }
                data += opt_hdr->nd_opt_len * 8;
                cc  -= opt_hdr->nd_opt_len * 8;
            }
        break;
        default:
           return 1;
        break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char *prgName = NULL;
    int c;
    char *iface = NULL;
    if ( (prgName=strrchr(argv[0],'/')) )
        prgName++;
    else
        prgName = argv[0];

    while( (c = getopt(argc, argv, "i:h")) > 0)
    {
        switch(c)
        {
            case 'i':
                iface = optarg;
            break;
            case 'h':
                usage(prgName);
                return 1;
            break;
        }
    }
    if ( iface == NULL )
    {
        usage(prgName);
        return 1;
    }

    /* open socket */
    int fd = icmp_socket(iface);
    if ( fd == -1 ) return 1;
    /* send a router solicitation */
    unsigned char buf[2048];
    if ((c = send_ra_solicit(fd, buf))< 0 ) return 1;
    /* listen for router advertisement */
    struct pollfd pollfd;
    pollfd.fd = fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;
    int rp = poll(&pollfd, 1, 2000); /* wait max 2 sec. */
    if ( rp > 0 )
    {
        /* print prefix on stdout */
        char ans_data[4096];
        struct iovec iov;
        struct msghdr msg;
        int cc;
        iov.iov_len = sizeof(ans_data);
        iov.iov_base = ans_data;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ans_data;
        msg.msg_controllen = sizeof(ans_data);
        cc = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (cc < 0)
        {
            perror("recvmsg:");
            return 1;
        }
        else
        {
            parse_reply(&msg, cc);
        }
        
    }
    else
    {
        return 1;
    }
    return 0;
}
