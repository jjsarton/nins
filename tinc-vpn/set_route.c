#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <getopt.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <sys/poll.h>
#include <linux/if_addr.h>

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
       poll(NULL,0,250);
    }
}

static void mask_addr(struct in6_addr *addr, int bits)
{
    int sz = 128;
    unsigned char *b = (unsigned char*)addr;
    while (bits>0)
    {
       switch ( bits)
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
    printf("Usage: %s [-i interface] [-n net-mask-bits]  [-m subnet-mask-bits] [-s suffix] [-w metric] [-f script_to_call]\n",
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
    char *script_name = NULL;
    int res;
    int bits;
    char *me;
    int c;

    if ( (me=strrchr(argv[0], '/')) ) me++;
    else me =  argv[0];

    while((c=getopt(argc, argv,"i:n:m:s:f:")) > 0 )
    {
         switch(c)
         {
             case 'i': device = optarg; break;
             case 'n': mask = optarg; break;
             case 'm': own_mask = optarg; break;
             case 's': suffix = optarg; break;
             case 'w': metric = optarg; break;
             case 'f': script_name = optarg; break;
            default: usage(me); return 0;
        }
    }


    if ( ( res = wait_for_iface(device, &own_addr,0)) != 1 )
    {
        return 1;
    }

    /* we knowm the global addresse assigned to our interface
     * and we can now prepare the values to pass to our script
     * via the environment,
     */

    /* calculate the network mask */
    bits=atoi(own_mask);
    mask_addr(&own_addr, bits);
    inet_ntop(AF_INET6, &own_addr, oad, sizeof(oad));

    /* calculate the subnet mask  for setting our gateway addresse */
    bits=atoi(mask);
    inet_ntop(AF_INET6, &own_addr, ad, sizeof(ad));
    mask_addr(&addr, bits);

    /* set the environment to pass to our script */
    setenv("PREFIX_NET",ad,1);
    setenv("MASK_NET",mask,1);
    setenv("PREFIX_SUBNET",oad,1);
    setenv("SUFFIX",suffix,1);
    setenv("METRIC",metric,1);

    if ( script_name == NULL )
    {
         /* set the script name */
         char *netname = getenv("NETNAME");
         snprintf(cmd,sizeof(cmd),"/etc/tinc/%s/tinc-slaac",netname?netname:"");
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "%s", script_name);
    }

    execl(cmd,cmd,NULL);
    perror("execl");

    /* execl() will, on success, not return, but we want't to avoid cc/gcc complain */
    return 0;
}
