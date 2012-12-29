#define _WIN32_WINNT 0x0501

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#ifdef __POCC__
#define _NETIOAPI_H
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// lcc don't know this
#ifndef SIO_ROUTING_INTERFACE_QUERY
#define SIO_ROUTING_INTERFACE_QUERY   _WSAIORW(IOC_WS2,20)
#endif
#ifndef IPPROTO_ICMPV6
#define  IPPROTO_ICMPV6  58
#endif
#ifndef IPPROTO_IPV6
#define  IPPROTO_IPV6 41
#endif

static int debug = 0;

struct icmp6_hdr
  {
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */
    union
    {
        uint32_t  icmp6_un_data32[1]; /* type-specific field */
        uint16_t  icmp6_un_data16[2]; /* type-specific field */
        uint8_t   icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
  };

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

#define ICMP6_DST_UNREACH             1
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_PARAM_PROB              4

#define ICMP6_INFOMSG_MASK  0x80    /* all informational messages */

#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129
#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REPORT         131
#define MLD_LISTENER_REDUCTION      132

#define ICMP6_DST_UNREACH_NOROUTE     0 /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN       1 /* communication with destination */
                                        /* administratively prohibited */
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2 /* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR        3 /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT      4 /* bad port */

#define ICMP6_TIME_EXCEED_TRANSIT     0 /* Hop Limit == 0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 /* Reassembly time out */

#define ICMP6_PARAMPROB_HEADER        0 /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER    1 /* unrecognized Next Header */
#define ICMP6_PARAMPROB_OPTION        2 /* unrecognized IPv6 option */

struct ni_hdr {
    struct icmp6_hdr ni_u;
    unsigned char ni_nonce[8];
};

#define ni_type  ni_u.icmp6_type
#define ni_code  ni_u.icmp6_code
#define ni_cksum ni_u.icmp6_cksum
#define ni_qtype ni_u.icmp6_data16[0]
#define ni_flags ni_u.icmp6_data16[1]

/* Types */
#ifndef ICMPV6_NI_QUERY
# define ICMPV6_NI_QUERY 139
# define ICMPV6_NI_REPLY 140
#endif

/* Query Codes */
#define NI_SUBJ_IPV6 0
#define NI_SUBJ_NAME 1
#define NI_SUBJ_IPV4 2

/* Reply Codes */
#define NI_SUCCESS 0
#define NI_REFUSED 1
#define NI_UNKNOWN 2

/* Qtypes */
#define NI_QTYPE_NOOP     0
#define NI_QTYPE_NAME     2
#define NI_QTYPE_IPV6ADDR 3
#define NI_QTYPE_IPV4ADDR 4

/* Flags */
#define NI_IPV6ADDR_F_TRUNCATE  ntohs(0x0001)
#define NI_IPV6ADDR_F_ALL       ntohs(0x0002)
#define NI_IPV6ADDR_F_COMPAT    ntohs(0x0004)
#define NI_IPV6ADDR_F_LINKLOCAL ntohs(0x0008)
#define NI_IPV6ADDR_F_SITELOCAL ntohs(0x0010)
#define NI_IPV6ADDR_F_GLOBAL    ntohs(0x0020)

#define NI_IPV4ADDR_F_TRUNCATE  NI_IPV6ADDR_F_TRUNCATE
#define NI_IPV4ADDR_F_ALL       NI_IPV6ADDR_F_ALL


#if defined _WIN32 && ! (defined __POCC__ && _WIN32_WINNT >= 0x600)
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
    if (af == AF_INET)
    {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(struct in_addr));
        getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    }
    else if (af == AF_INET6)
    {
        SOCKADDR_IN6 in;
        memset(&in, 0, sizeof(in));
        in.sin6_family = AF_INET6;
        memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
        getnameinfo((struct sockaddr *)&in, sizeof(SOCKADDR_IN6), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    }
    return NULL;
}
#endif

#if defined _WIN32 
int inet_pton(int af, const char *src, void *dst)
{
    struct addrinfo hints, *res, *ressave;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = af;

    if (getaddrinfo(src, NULL, &hints, &res) != 0)
    {
        return -1;
    }

    ressave = res;

    while (res)
    {
        memcpy(dst, res->ai_addr, res->ai_addrlen);
        res = res->ai_next;
    }

    freeaddrinfo(ressave);
    return 0;
}
#endif

int get_addresses( SOCKADDR_IN6 *ll, int family, unsigned char *buf, int size)
{
#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

    DWORD dwRetVal = 0;
    unsigned int i = 0;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    int ifFound = 0;
    int retVal = 0;

    do {

        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
        if (pAddresses == NULL) {
            printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
            exit(1);
        }

        dwRetVal =
            GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR)
    {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses)
        {
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if (pUnicast != NULL)
            {
                for (i = 0; pUnicast != NULL; i++)
                {
                    if ( pUnicast->Next == 0 )
                    {
                        SOCKADDR_IN6 *sockaddr = (SOCKADDR_IN6*)pUnicast->Address.lpSockaddr;
                        if ( memcmp(&sockaddr->sin6_addr, &ll->sin6_addr, sizeof(sockaddr->sin6_addr)) == 0 )
                        {
                           ifFound = 1;
                        }
                    }
                    pUnicast = pUnicast->Next;
                }
                if ( ifFound )
                {
                    pUnicast = pCurrAddresses->FirstUnicastAddress;
                    int j=i-1;
                    for (i = 0; i < j ; i++) {
                        if ( family == AF_INET6 && pUnicast->Address.lpSockaddr->sa_family==family )
                        {
                            SOCKADDR_IN6 *sa6 = (SOCKADDR_IN6*)pUnicast->Address.lpSockaddr;
			    if ( memcmp(&sa6->sin6_addr,"",1 ) )
			    {
                                memcpy(buf, &sa6->sin6_addr, 16);
                                retVal = 16;
                            }
                        }
                        else if ( family == AF_INET && pUnicast->Address.lpSockaddr->sa_family==family && retVal < 64 )
                        {
                            struct sockaddr_in *sa = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                            memcpy(buf, &sa->sin_addr, 4);
                            retVal = +4;
                        }
                        pUnicast = pUnicast->Next;
                    }
                    break;
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    if (pAddresses) {
        FREE(pAddresses);
    }

    return retVal;
}

void makeCheckSum(unsigned char *ad, SOCKADDR_IN6 *src, struct ni_hdr *ni_hdr, int len)
{
    unsigned char buf[2048];
    unsigned char *s = buf;

    memset(buf,0,sizeof(buf));
    memcpy(s, ad, 16); s+=16;
    memcpy(s, &src->sin6_addr, 16); s+=16;
    uint32_t l = htonl(len);
    memcpy(s, &l, 4); s+=4;
    s+=3;
    *s = 58; s++;
    memcpy(s,ni_hdr,len);
    s += len;
    uint16_t *us = (uint16_t*)buf;
    uint32_t c = 0;
    len = (s-buf+1) >>1;

    while ( len > 0 )
    {
        c += ntohs(*(const uint16_t *)us);
        us++;
        len--;
    }
    c += c>>16;
    c = ~c;

    ni_hdr->ni_cksum = htons(c);

    return;
}

int get_routing_address(int sock, SOCKADDR_IN6 *dest, SOCKADDR_IN6 *via, LPDWORD size )
{
    int result = 0;

    result =
       WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, (struct sockaddr *)dest, sizeof(*dest),
                (struct sockaddr *)via, sizeof(*via), size, NULL, NULL);

  return result;
}


static unsigned char rbuf[2048];
static char str[INET6_ADDRSTRLEN];
static char name[256];
static char sub[INET6_ADDRSTRLEN];

int __cdecl main(int argc, char **argv)
{
    if ( argc > 1 && strcmp(argv[1],"-d")==0 )
        debug=1;

    if ( debug )
    {
        printf("%s started\n",argv[0]);
        fflush(stdout);
    }
    WSADATA wsaData;
    if ( WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 )
    {
        printf("WSAStartup failed\n");
        fflush(stdout);
        return 1;
    }

    if ( debug )
    {
        printf("%s started WSAStartup OK\n",argv[0]);
        fflush(stdout);
    }

    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if ( sock > -1 )
    {
        if ( debug )
        {
            printf("Raw socket %d created\n",sock);
            fflush(stdout);
        }
        /* send to :: in order to avoid error WSAEINVAL on recvfrom() */
        SOCKADDR_IN6 dstTmp;
        memset(&dstTmp,0,sizeof(dstTmp));
        dstTmp.sin6_family=AF_INET6;
        sendto(sock, (char*)rbuf, 0, 0, (struct sockaddr*)&dstTmp, sizeof(dstTmp));
        if ( debug )
        {
            printf("Send via %d done\n",sock);
            fflush(stdout);
        }
#if 0 // don't work
       DWORD val = RCVALL_ON;
       WSAIoctl(sock, SIO_RCV_ALL, &val, sizeof(val), NULL, 0, 0, NULL, NULL);
#endif
#if 1
        /* allow us to receive multicast ICMPv6 frames which are not processed
         * by the kernel itself.
         */
        struct ipv6_mreq multicastRequest;  /* Multicast address join structure */
        unsigned char mc[16] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        multicastRequest.ipv6mr_interface=0;
        memcpy(&multicastRequest.ipv6mr_multiaddr,mc, sizeof(multicastRequest.ipv6mr_multiaddr));
        if ( setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*) &multicastRequest, sizeof(multicastRequest)) != 0 )
        {
            printf("Join ff02::1 failed error %d\n",WSAGetLastError());
            fflush(stdout);
        }
#endif
        for (;;)
        {
           SOCKADDR_IN6 src;
           memset(&src,0,sizeof(src));
           src.sin6_family = AF_INET6;
           int len = sizeof(src);
           int rec = recvfrom(sock, (char*)rbuf, sizeof(rbuf), 0, (struct sockaddr*)&src, &len);

           if ( rec > 0 )
           {
                struct ni_hdr *ni_hdr = (struct ni_hdr*)rbuf;
                inet_ntop(AF_INET6, &src.sin6_addr, str, sizeof(str));
                if ( debug )
                {
                    printf("received %d bytes from %s type %d\n",rec,str,ni_hdr->ni_type);
                    fflush(stdout);
                }

                /* if not from link local address, ignore message or mc address ignore*/
                if ( strcmp(str,"ff02::1") == 0 || strncmp(str,"fe80::",6) == 0 )
                {
                    if (ni_hdr->ni_type == ICMPV6_NI_QUERY && ni_hdr->ni_code == NI_SUBJ_IPV6 )
                    {
                       unsigned char *ad = (unsigned char *)ni_hdr+sizeof(struct ni_hdr);
                       unsigned char dest[16];
                       memcpy(dest, ad, 16);
                       inet_ntop(AF_INET6, ad, sub, sizeof(sub));
                       SOCKADDR_IN6 via;
                       if ( strcmp(sub,"ff02::1") == 0 )
                       {
                           DWORD size;
                           size = 0;
                           if (get_routing_address(sock, &src, &via,&size) == 0 )
                           {
                               printf("Recedived via: %s\n", (char*)sub);
                               memcpy(dest, &via.sin6_addr, 16);
                           }
                           else
                           {
                               printf("get_routing_address() fehler %d\n",WSAGetLastError());
                           }
                       }
                       else
                       {
                           memset(&via, 0, sizeof(via));
                           via.sin6_family = AF_INET6;
                           memcpy(&via.sin6_addr, dest, 16);
                       }

                       /* answer to sender */
                       ni_hdr->ni_type = ICMPV6_NI_REPLY;
                       int qtype = htons(ni_hdr->ni_qtype);
                       unsigned char *l = NULL;
                       unsigned char abuf[64];
                       int ret;
                       switch(qtype)
                       {
                           case NI_QTYPE_IPV6ADDR:
                               /* accept only NI_IPV6ADDR_F_GLOBAL */
                               if ( ni_hdr->ni_flags != NI_IPV6ADDR_F_GLOBAL )
                                   continue;
                               if ( debug )
                               {
                                   printf("got NI_QTYPE_IPV6ADDR from %s\n",sub);
                                   fflush(stdout);
                               }
                               ret = get_addresses(&via, AF_INET6, abuf, 64);
                               /* set ttl */
                               l = rbuf + sizeof(struct ni_hdr);
                               *l++ = 0;
                               *l++ = 0;
                               *l++ = 0;
                               *l++ = 0;
                               /* copy address */
                               memcpy(l, abuf,ret);
                               l+=ret;
                               ni_hdr->ni_flags = 0;
                               ni_hdr->ni_cksum = 0;
                               makeCheckSum(dest, &src, ni_hdr, l-rbuf);
                               sendto(sock, (char*)rbuf, l-rbuf,  0, (struct sockaddr*)&src, sizeof(src));
                           break;
                           case NI_QTYPE_IPV4ADDR:
                               if ( ni_hdr->ni_flags != 0 )
                                   continue;
                               if ( debug )
                               {
                                   printf("got NI_QTYPE_IPV4ADDR from %s\n",sub);
                                   fflush(stdout);
                               }
                               ret = get_addresses(&via, AF_INET, abuf, 64);
                               /* set ttl */
                               l = rbuf + sizeof(struct ni_hdr);
                               unsigned char *a = abuf;
                               while (ret > 0 )
                               {
                                   *l++ = 0;
                                   *l++ = 0;
                                   *l++ = 0;
                                   *l++ = 0;
                                   /* copy address */
                                   memcpy(l, a,ret);
                                   a += 4;
                                   l += 4;
                                   ret -= 4;
                               }
                               ni_hdr->ni_flags = 0;
                               ni_hdr->ni_cksum = 0;
                               makeCheckSum(dest, &src, ni_hdr, l-rbuf);
                               sendto(sock, (char*)rbuf, l-rbuf,  0, (struct sockaddr*)&src, sizeof(src));
                           break;
                           case NI_QTYPE_NAME:
                               if ( ni_hdr->ni_flags != 0 )
                                   continue;
                               if ( debug )
                               {
                                   printf("got NI_QTYPE_NAME from %s\n",sub);
                                   fflush(stdout);
                               }
                               gethostname(name,sizeof(name));
                               name[sizeof(name)-1] = '\0';
                               /* set ttl */
                               l = rbuf + sizeof(struct ni_hdr);
                               *l++ = 0;
                               *l++ = 0;
                               *l++ = 0;
                               *l++ = 0;
                               /* copy name */
                               *l = 0;
                               unsigned char *d = l+1;
                               unsigned char *s = (unsigned char*)name;
                               while( *s )
                               {
                                  if ( *s == '.' )
                                  {
                                      l = d;
                                      *l = 0;
                                      d++;
                                      s++;
                                  }
                                  else
                                  {
                                      unsigned char c;
                                      c = tolower(*s);
                                      *l += 1;
                                      *d++ = c;
                                      s++;
                                  }
                               }
                               l = d;
                               *l++= 0;
                               *l++= 0;
                               ni_hdr->ni_flags = 0;
                               ni_hdr->ni_cksum = 0;
                               makeCheckSum(dest, &src, ni_hdr, l-rbuf);
                               sendto(sock, (char*)rbuf, l-rbuf,  0, (struct sockaddr*)&src, sizeof(src));
                           break;
                           default: /* ignore */
                               if ( debug )
                               {
                                   printf("got %d from %s\n",qtype,sub);
                                   fflush(stdout);
                               }
                           break;
                       }
                    }
                }
           }
           else
           {
               printf("Error %d\n",WSAGetLastError());
               fflush(stdout);
               return 1;
           }
        }
    }
    return 1;
}
