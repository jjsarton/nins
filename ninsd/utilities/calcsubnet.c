/* calcsubnet.c */
/* calcsubnet.c print out a new prefix/64 based on
 * the main prefix for a subnet as for example prefix/62
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>

static void usage(char *me)
{
    fprintf(stderr,"Syntax: %s -p <base-prefix> [-o <offset> | -i <id>]\n",me);
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

int main(int argc, char **argv)
{
    char str[INET6_ADDRSTRLEN];
    struct sockaddr_in6 sa6;
    char *prgName = NULL;
    long  offset = 0;
    int  c;
    struct  in6_addr addr;
    struct  in6_addr suffix;
    char *prefix = NULL;
    char *id = NULL;
    int   mb = 64;
    char *s = NULL;

    if ( (prgName=strrchr(argv[0],'/')) )
        prgName++;
    else
        prgName = argv[0];

    while ((c=getopt(argc, argv,"i:hp:o:")) > 0 )
    {
        switch(c)
        {
            case 'i':
                id = optarg;
            break;
            case 'p':
                prefix = strdup(optarg);
            break;
            case 'o':
                offset = atoi(optarg);
            break;
            default:
                usage(prgName);
                return 1;
            break;
        }
    }

    if ( id )
    {
        if ( strstr(id,"::") == id )
        {
            strncpy(str,id, INET6_ADDRSTRLEN);
        }
        else
        {
            strcpy(str,"::");
            strncat(str,id, INET6_ADDRSTRLEN-2);
        }
        str[INET6_ADDRSTRLEN-1] = '\0';
        inet_pton(AF_INET6, str, &suffix);
    }


    if ( prefix && (s=strchr(prefix,'/')) )
    {
        mb = atoi(s+1);
        *s = '\0';
        if ( mb > 64 )
        {
            fprintf(stderr,"%s: subnet > 64 not supported\n",prgName);
            return 1;
        }
        else
        {
            inet_pton(AF_INET6, prefix,&addr);
            mask_addr(&addr, mb);
            inet_ntop(AF_INET6, &addr, str, sizeof(str));
            printf("%s/%d\n",str,mb);
            return 0;
        }
    }

    if ( prefix && strstr(prefix, "::") && !strchr(prefix,'/') )
    {
        struct  in6_addr addr;
        inet_pton(AF_INET6, prefix,&addr); 
        unsigned short *ad16 = (unsigned short *)&addr;
        ad16 += 3;
        unsigned short s = htons(*ad16);
        s += offset;
        *ad16 = htons(s);
        if ( id )
        {
            unsigned short *s16 = (unsigned short *)&suffix;
            s16 += 4;
            ad16++;
            int i;
            for ( i = 0; i < 4; i++ )
                *ad16++ = *s16++;
        }
        inet_ntop(AF_INET6, &addr, str, sizeof(str));
        printf("%s\n",str);
        return 0;
    }
    usage(prgName);
    return 1;
}
