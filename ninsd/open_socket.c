#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <sys/poll.h>

#include "open_socket.h"
#include "ninfo.h"

/***********************************************
 * wait_for_iface()
 *
 * get the interface address with the given name
 * link local address.
 *
 * if The device is not up or there a link local
 * adress is not available, wait a little bit
 * and try again.
 *
 * if the link local adress is present
 * return with the adress stored into addr
 *
 * 0 if the parameters are NULL or the interface
 * what not foud.  1 if all is OK
 *
 **********************************************/
 
static int wait_for_iface(char *name, struct in6_addr *addr)
{
   struct ifaddrs *ifa = NULL;
   struct ifaddrs *pt;
   int family=0;
   int link_local;
   int if_found = 0;
   if ( name == NULL || addr == NULL)
   {
       fprintf(stderr,"%s: null parameters not allowed\n",__FUNCTION__);
       return 0;
   }

   for(;;)
   {
       if ( getifaddrs(&ifa) )
       {
           perror("getifaddrs");
           return 0;
       }
       
       pt = ifa;
       while(pt)
       {
           if ( strcmp(name, pt->ifa_name) == 0 )
           {
                if_found = 1;
           }

           struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)pt->ifa_addr;
           family = sa6? sa6->sin6_family : -1;
           if ( family == AF_INET6 && strcmp(pt->ifa_name,name) == 0 )
           {
               link_local = IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr);
               if ( link_local )
               {
                   memcpy(addr, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
                   freeifaddrs(ifa);
                   return 1;
               }
           }
           pt = pt->ifa_next;
       }

       if ( ifa )
       {
          freeifaddrs(ifa);
       }

       if ( !if_found )
       {
           fprintf(stderr,"Interface %s not found\n",name);
           return 0;
       }
       poll(NULL,0,1000);
    }
}

/***********************************************
 * icmp_socket()
 *
 * Open a docket for listenin on icmp-v6 messages
 * on the interface given by name.
 *
 * The link local adress for the interface is
 * returned into addr.
 *
 * Return sock handler or -1 on error
 *
 **********************************************/

int icmp_socket(char *name, struct in6_addr *addr)
{
    struct icmp6_filter filter;
    int sock = -1;

    if ( !wait_for_iface(name, addr) )
    {
       return -1;
    }

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if ( sock > 0 )
    {
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
        ICMP6_FILTER_SETPASS(ICMPV6_NI_REPLY, &filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT,&filter);
        ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT,&filter);

        if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER,
                       &filter, sizeof(struct icmp6_filter)) < 0 )
        {
            perror("setsockopt");
            close(sock);
        }
        else
        {
            if ( name )
            {
                if (setsockopt(sock, SOL_SOCKET,
                               SO_BINDTODEVICE, name,
                               strlen(name)+1) < 0 )
                {
                    perror("setsockopt");
                    close(sock);
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

#if 0
int main(int argc, char **argv)
{
    char *device = "eth0";
    static struct in6_addr own_addr;
    char ad[INET6_ADDRSTRLEN];

    if ( argc > 1 )
        device = argv[1];

    if ( icmp_socket(device, &own_addr) < 0 )
    {
       return 1;
    }

    inet_ntop(AF_INET6, &own_addr, ad, sizeof(ad));
    printf("%-7s %s\n",device,ad );

    return 0;
}
#endif
