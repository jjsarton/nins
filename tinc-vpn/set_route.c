#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <sys/poll.h>


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
 
static int wait_for_iface(char *name, struct in6_addr *addr, int local)
{
   struct ifaddrs *ifa = NULL;
   struct ifaddrs *pt;
   int family=0;
   char ad[INET6_ADDRSTRLEN];
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
               if ( (local && link_local) || (!local && !link_local) )
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

static void mask_addr(struct in6_addr *addr, int bits)
{
    int sz = 128;
    unsigned char *b = (unsigned char*)addr;
    while (bits>0)
    {
       switch (sz - bits)
       {
           case 1: *b &= 0x80; break;
           case 2: *b &= 0xc0; break;
           case 3: *b &= 0xe0; break;
           case 4: *b &= 0xf0; break;
           case 5: *b &= 0xf8; break;
           case 6: *b &= 0xfc; break;
           case 7: *b &= 0xfe; break;
       }
       b++;
       bits -=8;
       sz   -= 8;
   }
   while (sz)
   {
       *b = 0;
       b++;
       sz -= 8;
   }
}

static void usage(char *me)
{
    printf("Usage: %s [-i interface] [-n net-mask-bits]  [-m subnet-mask-bits] [-s suffix] [-w metric] [-t]\n",
            me);
}

int main(int argc, char **argv)
{
    char *device = "eth0";
    static struct in6_addr own_addr;
    static struct in6_addr addr;
    char cmd[4096];;
    char ad[INET6_ADDRSTRLEN];
    char oad[INET6_ADDRSTRLEN];
    char *mask = "48";
    char *own_mask = "64";
    char *suffix = "1";
    char *metric = "1024";
    int res;
    int bits;
    char *me;
    int c;
    int verbose = 0;
    int test = 0;

    if ( (me=strrchr(argv[0], '/')) ) me++;
    else me =  argv[0];

    while((c=getopt(argc, argv,"i:n:m:s:tv")) > 0 )
    {
         switch(c)
         {
             case 'i': device = optarg; break;
             case 'n': mask = optarg; break;
             case 'm': own_mask = optarg; break;
             case 's': suffix = optarg; break;
             case 't': test = 1; verbose = 1; break;
             case 'w': metric = optarg; break;
            default: usage(me); return 0;
        }
    }

    if ( ( res = wait_for_iface(device, &own_addr,0)) != 1 )
    {
        return 1;
    }

    /* set forwarding to 1 for our tap device this will avoid
     * that the default route via the local link addresse is set again
     * and disturbe our rounting
     */

    snprintf(cmd, sizeof(cmd),"sysctl -w net.ipv6.conf.%s.forwarding=1",device);
    if ( verbose )
    {
        printf("%s\n",cmd);
    }
    if ( !test )
    {
        system(cmd);
    }

    memcpy(&addr, &own_addr, sizeof(addr));

    /* build ip command */
    bits=atoi(own_mask);
    mask_addr(&own_addr, bits);

    bits=atoi(mask);
    mask_addr(&addr, bits);

    inet_ntop(AF_INET6, &own_addr, oad, sizeof(oad));
    inet_ntop(AF_INET6, &addr, ad, sizeof(ad));
    snprintf(cmd,sizeof(cmd),"ip -6 ro ad %s/%s via %s%s dev %s metric %s",ad, mask, oad, suffix, device, metric);

    if ( verbose )
    {
        printf("%s\n",cmd);
    }
    if ( ! test )
    {
        system(cmd);
    }

    return 0;
}
