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
#include <sys/stat.h>
#include <signal.h>

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
#include "open_socket.h"
#include "send.h"

#include "version.h"

#define MAXPACKET 4096

/* check at last every 10 minute for life */
#define TTL_MAX 600

#define PID_DIR "/var/run/"

#ifndef __linux__
#define daemon(a,b) m_daemon(a,b)
static int m_daemon(int nochdir, int noclose)
{
    pid_t pid ,sid; 
    pid = fork(); 
    if (pid < 0)
    {
        return -1; /* error */
    } 
    if (pid > 0) /* parent */
    {
        exit(0);
    } 
    /* child process */
 
    umask(0);
    sid = setsid();
    if (sid < 0) 
    {
         return -1;
    }
    
    if ( !noclose )
    {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    if ( !nochdir )
    {
        chdir("/");
        close(STDOUT_FILENO);
    }
    
    return 0;
}
#endif

static int ttl_max = TTL_MAX;
static int sock = -1;
static char *updater = "nsupdate";
static uint8_t outpack[MAXPACKET];

static char domain[NAME_SIZE_MAX];
static int ttl = 0;
static struct in6_addr own_addr;
static char *map_file = NULL; /* NAT46 Mapping */
static int get_ipv4 = 0;

char *pid_file = NULL;

static void sig_handler(int sig)
{
    int err;
    /* first remove all dymamic entries */
    delete_all_clients(domain, updater);
    err = unlink(pid_file);
    if (err < 0)
    {
         perror("unlink");
         exit(1);
    }
    exit(0);
}

static void set_signals(void)
{
    struct sigaction act;
    sigset_t smask;
    sigemptyset(&smask);
    sigaddset(&smask, SIGHUP);
    sigaddset(&smask, SIGINT);
    sigaddset(&smask, SIGQUIT);
    sigaddset(&smask, SIGTERM);

    memset(&act, 0, sizeof(act));
    act.sa_handler = sig_handler;
    act.sa_mask = smask;

    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
} 

static char *print_addr(struct in6_addr *addr)
{
    static char str[128];
    inet_ntop(AF_INET6, addr, str, sizeof(str));
    return str;
}

static char *print_addr4(struct in_addr *addr)
{
    static char str[128];
    inet_ntop(AF_INET, addr, str, sizeof(str));
    return str;
}

void get_dynamic_ipv4(node_info_t *ni, char *map_file)
{
    FILE *fp;
    char gladdr[128];
    char line[1024];
    inet_ntop(AF_INET6, &ni->global, gladdr, sizeof(gladdr));

    if ( (fp = fopen(map_file,"r")) )
    {
        while (fgets(line,sizeof(line),fp) )
        {
           if ( *line == '#' ) continue;
           char ip4[1024];
           char ip6[1024];
           char rest[1024];
           sscanf(line,"%s\t%s\t%s\n",ip4,ip6,rest);
           if ( strcmp(ip6, gladdr) == 0 )
           {
               struct in_addr ipv4;
               inet_pton(AF_INET, ip4, &ipv4);
               node_info_add_ipv4(&ni->local, &ipv4, ttl, domain, updater);
               break;
           }
        }
        fclose(fp);
    }
}

int parse_reply(struct msghdr *msg, int cc, void *addr)
{
    struct sockaddr_in6 *from = addr;
    uint8_t *buf = msg->msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;

    /* don't process if this is not frm a link local address */
    if ( !IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr) )
        return 0;

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
                        node_info_add_name(&from->sin6_addr,(char*)data, domain, ttl, updater);
                    }
                break;
                case NI_QTYPE_IPV6ADDR:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 23 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        printf("Addr %s\n",print_addr((struct in6_addr*)data));
                        node_info_add_global(&from->sin6_addr,(struct in6_addr*)data, ttl, domain, updater);
                    }
                    else
                    {
                        printf("\n");
                    }
                break;
                case NI_QTYPE_IPV4ADDR:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 7 && get_ipv4 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        printf("Addr %s\n",print_addr4((struct in_addr*)data));
                        node_info_add_ipv4(&from->sin6_addr,(struct in_addr*)data, ttl, domain, updater);
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
        case ND_ROUTER_ADVERT:
            printf("got ND_ROUTER_ADVERT from %s\n", print_addr(&from->sin6_addr));
            struct in6_addr ns_server;
            memset(&ns_server, 0, sizeof(ns_server));
            decode_router_advertisement(icmph, cc, &ns_server, &ttl, domain);
            if ( ttl == 0 )
            {
                delete_all_clients(domain, updater);
            }
            else if ( ttl > ttl_max )
            {
                ttl = ttl_max;
            }
        break;

        case ND_NEIGHBOR_ADVERT:
            /* ignore this */
#if 0
            printf("got ND_NEIGHBOR_ADVERT from %s\n", print_addr(&from->sin6_addr));
            if ( memcmp(&own_addr, &from->sin6_addr, sizeof(own_addr)) )
            {
                node_info_add_elem(&from->sin6_addr);
            }
#endif
            break;
        default:
            printf("Received type %d\n",icmph->icmp6_type);
        break;
    }
    return 0;
}

void complete_info(int sock, uint8_t *outpack,int ttl)
{
    int flag = get_ipv4 ? 1: map_file ? 1 : 0;

    node_info_t *ni = search_incomplete(ttl, domain, updater, flag);
    if ( ni )
    {
        if (!(ni->flag&NODE_INFO_NAME))
            query_name(sock, outpack, &ni->local);

        if ( !(ni->flag&NODE_INFO_GLOB))
        {
            query_addr(sock, outpack, &ni->local);
        }

        if ( map_file && ni->flag&NODE_INFO_GLOB )
        {
            get_dynamic_ipv4(ni, map_file);
        }
        else if ( get_ipv4  && ni->flag&NODE_INFO_GLOB )
             query_ipv4(sock, outpack, &ni->local);

        if ( (ni->flag&NODE_INFO_CHECK) == NODE_INFO_CHECK)
        {
            query_addr(sock, outpack, &ni->local);

            if ( map_file )
            {
                get_dynamic_ipv4(ni, map_file);
            }
            else if ( get_ipv4 )
                query_ipv4(sock, outpack, &ni->local);
        }
    }
}

int mainloop(int sock, uint8_t *outpack, int packlen)
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

    /* make shure that radvd send a router advertisement */
    send_ra_solicit(sock, outpack);

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
            complete_info(sock, outpack, ttl);
            if ( send_echo_request )
            {
                struct in6_addr addr;
                inet_pton(AF_INET6, "ff02::1", &addr);
                query_name(sock, outpack, &addr);
                send_echo_request = 0;
            }
        }
    }
    return 0;
}

char *prgName = NULL;

static void usage(char *me)
{
    fprintf(stderr,"Usage %s -i interface [-v] [-f] [-t ttl_max] [-s updater] [-4] [-m map_file]\n",me);
    abort();
}

int main(int argc, char **argv)
{
    int packlen = sizeof(outpack);
    char *device = NULL;
    int c;
    int foreground = 0;
    int t;
    pid_t pid;

    prgName = argv[0];
    if ( prgName && (prgName=strrchr(prgName,'/')) )
        prgName++;

    while( (c = getopt(argc, argv, "i:vft:s:m:4p:")) > 0)
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
            case '4':
                get_ipv4=1;
            break;
            case 't':
                t = atoi(optarg);
                if ( t > 0 )
                    ttl_max = t;
            break;
            case 's':
                updater = optarg;
            break;
            case 'm':
                map_file = optarg;
            break;
            case 'p':
                pid_file = optarg;
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

    if ( !pid_file )
    {
        pid_file = calloc(strlen(PID_DIR)+strlen(prgName)+1,1);
	if ( pid_file == NULL )
	{
	     perror("calloc");
	     exit(1);
	}
	strcpy(pid_file, PID_DIR);
	strcat(pid_file, prgName);
    }


    memset(&own_addr,0,sizeof(own_addr));
    
    sock = icmp_socket(device, &own_addr);

    if ( sock < 0 )
    {
        return 1;
    }

    /* check for pid file */
    if ( access(pid_file,R_OK) == 0 )
    {
         fprintf(stderr,"%s: error %s exist\n",prgName,pid_file);
	 exit(1);
    }

    if ( ! foreground )
    {
        if (daemon(0, 0) < 0)
        {
            perror("daemon");
            exit(1);
        }
    }

    /* set signal handler and create pid file */
    set_signals();
    pid = getpid();
    FILE *pidf = fopen(pid_file,"w");
    if ( pidf > 0 )
    {
        fprintf(pidf,"%d\n",pid);
	fclose(pidf);
    }
    else
    {
        perror("fopen");
	exit(1);
    }
    
    mainloop(sock, outpack, packlen);
    return 0;
}
