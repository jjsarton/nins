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
#include <syslog.h>
#include <pwd.h>
#include <grp.h>

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
#include "nsupd_from.h"

#include "version.h"

#define MAXPACKET 4096
// send icmpv6 requests all 15 seconds after a router solicitation on ''
// arrived. The max time is according to this setting 3 minutes
// the windows system must be up within this time
#define MAX_ECHO_REQUESTS 12

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
static char *user = NULL;
static char *group = NULL;

char *pid_file = NULL;

static void sig_handler(int sig)
{
    int err = 0;
    /* first remove all dymamic entries */
    delete_all_clients(domain, updater);
    if ( pid_file )
    {
        err = unlink(pid_file);
        free(pid_file);
    }

    if (err < 0)
    {
         syslog(LOG_ERR, "unlink: %s",strerror(errno));
         exit(1);
    }
    syslog(LOG_NOTICE, "received signal %d, terminate",sig);
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
    static char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, str, sizeof(str));
    return str;
}

static char *print_addr4(struct in_addr *addr)
{
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, str, sizeof(str));
    return str;
}

static void set_ownership(char *user, char *group)
{
    struct passwd *pwd;
    struct group *grp;
    if ( group )
    {
        if ( (grp = getgrnam(group)) )
            setgid(grp->gr_gid);
    }
    if ( user )
    {
        if ( (pwd = getpwnam(user)) )
            setuid(pwd->pw_uid);
    }
}

static void set_pid_ownership(char *user, char *group, char *pid_obj)
{
    struct passwd *pwd;
    struct group *grp;
    pid_t uid = 0;
    gid_t gid = 0;
    if ( group )
    {
        if ( (grp = getgrnam(group)) )
            gid = grp->gr_gid;
    }
    if ( user )
    {
        if ( (pwd = getpwnam(user)) )
            uid = pwd->pw_uid;
    }
    if ( pid_obj )
    {
        chown(pid_obj, uid, gid);
    }
}

void get_dynamic_ipv4(node_info_t *ni, char *map_file)
{
    FILE *fp;
    char gladdr[INET6_ADDRSTRLEN];
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

int parse_reply(struct msghdr *msg, int cc, void *addr, int *echo)
{
    struct sockaddr_in6 *from = addr;
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
    if (cc < 8) {
        return 1;
    }

    if ( memcmp(&from->sin6_addr, &any, sizeof(any)) == 0 &&
         icmph->icmp6_type == ND_ROUTER_SOLICIT)
    {
        syslog(LOG_INFO,"got ND_ROUTER_ADVERT from %s\n", print_addr(&from->sin6_addr));
        /* send mc icmp echo query */
        *echo = MAX_ECHO_REQUESTS;
        return 1;
    }

    /* don't process if this is not from a link local address */
    if ( !IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr) )
        return 0;

    switch (icmph->icmp6_type)
    {
        case ICMP6_ECHO_REPLY:
            syslog(LOG_INFO, "got ICMP6_ECHO_REPLY from %s", print_addr(&from->sin6_addr));
            if ( memcmp(&own_addr, &from->sin6_addr, sizeof(own_addr)) )
            {
                node_info_add_elem(&from->sin6_addr, NODE_INFO_CHECK);
            }
        break;
        case ICMPV6_NI_REPLY:
            if ( memcmp(&own_addr, &from->sin6_addr, sizeof(own_addr)) == 0 )
            {
                syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s", print_addr(&from->sin6_addr));
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
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: %s", print_addr(&from->sin6_addr),(char*)data);
                        node_info_add_name(&from->sin6_addr,(char*)data, domain, ttl, updater);
                    }
                    else
                    {
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: %s", print_addr(&from->sin6_addr),"NO NAME");
                    }
                break;
                case NI_QTYPE_IPV6ADDR:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 23 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        char add[INET6_ADDRSTRLEN];
                        strcpy(add, print_addr((struct in6_addr*)data));
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: Addr %s", print_addr(&from->sin6_addr),add);
                        node_info_add_global(&from->sin6_addr,(struct in6_addr*)data, ttl, domain, updater);
                    }
                    else
                    {
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: %s", print_addr(&from->sin6_addr),"NO IPV6");
                        /* unknown node ? */
                        node_info_add_elem(&from->sin6_addr, NODE_INFO_CHECK);
                    }
                break;
                case NI_QTYPE_IPV4ADDR:
                    len = cc - sizeof(struct ni_hdr) + 4;
                    if ( len > 7 && get_ipv4 )
                    {
                        uint8_t *data = (uint8_t *)nih + sizeof(struct ni_hdr) + 4; // ttl len = 4;
                        nl = data[0];
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: Addr %s", print_addr(&from->sin6_addr),print_addr4((struct in_addr*)data));
                        node_info_add_ipv4(&from->sin6_addr,(struct in_addr*)data, ttl, domain, updater);
                    }
                    else
                    {
                        syslog(LOG_INFO,"got ICMPV6_NI_REPLY from %s: %s", print_addr(&from->sin6_addr),"NO IPV4");
                        //set_query_mapped(&from->sin6_addr);
                    }
                break;
                default:
                    printf("Other NI_QTYPE\n");
            }
        break;
        case ND_ROUTER_SOLICIT:
            syslog(LOG_INFO, "got ND_ROUTER_SOLICIT from %s\n", print_addr(&from->sin6_addr));
            if ( memcmp(&from->sin6_addr,&own_addr, sizeof(own_addr)) )
            {
                node_info_add_elem(&from->sin6_addr, NODE_INFO_CHECK);
            }
        break;
        case ND_ROUTER_ADVERT:
            syslog(LOG_INFO,"got ND_ROUTER_ADVERT from %s\n", print_addr(&from->sin6_addr));
            if ( ! *domain || memcmp(&from->sin6_addr,&own_addr, sizeof(own_addr)) == 0)
            {
                struct in6_addr ns_server;
                memset(&ns_server, 0, sizeof(ns_server));
                decode_router_advertisement(icmph, cc, &ns_server, &ttl, domain);
            }
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
            syslog(LOG_INFO, "got ND_NEIGHBOR_ADVERT from %s\n", print_addr(&from->sin6_addr));
            if ( memcmp(&from->sin6_addr,&own_addr, sizeof(own_addr)) )
            {
                node_info_add_elem(&from->sin6_addr, NODE_INFO_CHECK);
            }
            break;
        case ND_NEIGHBOR_SOLICIT:
            syslog(LOG_INFO, "got ND_NEIGHBOR_SOLICIT from %s\n", print_addr(&from->sin6_addr));
            break;
        default:
            syslog(LOG_INFO, "Received type %d from %s\n",icmph->icmp6_type, print_addr(&from->sin6_addr));
        break;
    }
    return 0;
}

void get_ipv4_addr(int sock, node_info_t *ni, uint8_t *outpack,int ttl)
{
    /* true ipv4 address prevail */
    /* for the first time we may have the ipve adress from tayga
     * this will bereplaced by the true ipv4 adress of node as
     * soon as we have got it from the net.
     */
    if ( map_file && (ni->flag & NODE_QUERY_MAP))
    {
        get_dynamic_ipv4(ni, map_file);
    }
    else if ( get_ipv4 && ni->name_queries < 3 )
    {
        ni->name_queries++;
        query_ipv4(sock, outpack, &ni->local);
    }
}

void complete_info(int sock, uint8_t *outpack,int ttl)
{
    int flag = get_ipv4 ? 1: map_file ? 1 : 0;
    node_info_t *ni = search_incomplete(ttl, domain, updater, flag);
    if ( ni )
    {
        if (!(ni->flag&NODE_INFO_NAME) && ni->name_queries < 3)
        {
            ni->name_queries++;
            query_name(sock, outpack, &ni->local);
        }

        if ( !(ni->flag&NODE_INFO_GLOB)&& ni->global_queries < 3)
        {
            ni->global_queries++;
            query_addr(sock, outpack, &ni->local);
        }
        else if ( (ni->flag&NODE_INFO_CHECK) == NODE_INFO_CHECK && ni->global_queries < 3)
        {
            ni->global_queries++;
            query_addr(sock, outpack, &ni->local);
            get_ipv4_addr(sock, ni, outpack, ttl);
        }

        if ( (ni->flag&NODE_INFO_GLOB && !(ni->flag & NODE_HAS_IPV4)) || (ni->flag & NODE_QUERY_MAP) )
        {
            get_ipv4_addr(sock, ni, outpack, ttl);
        }

    }
}

int mainloop(int sock, uint8_t *outpack, int packlen, int listener)
{
    struct pollfd pollfd[2];
    char addrbuf[INET6_ADDRSTRLEN];
    char ans_data[4096];
    struct iovec iov;
    struct msghdr msg;
    int cc;
    int polling = MSG_DONTWAIT;
    int send_echo_request = 1;
    int req_echo=0;
    int pollret=0;
    time_t req_time = 0;

    pollfd[0].fd = sock;
    pollfd[0].events = POLLIN|POLLPRI|POLLRDHUP|POLLERR|POLLHUP|POLLNVAL;
    pollfd[0].revents = 0;
    
    if ( listener > 0 )
    {
        pollfd[1].fd = listener;
        pollfd[1].events = POLLIN|POLLPRI|POLLRDHUP|POLLERR|POLLHUP|POLLNVAL;
        pollfd[1].revents = 0;
    }

    /* make shure that radvd send a router advertisement */
    send_ra_solicit(sock, outpack);

    for(;;)
    {
        pollfd[0].revents = 0;
        pollfd[1].revents = 0;
        pollret = poll(pollfd, listener > 0 ? 2 : 1, 1000);

        if ( listener > 0 && (pollfd[1].revents & POLLIN) == POLLIN )
        {
            syslog(LOG_ERR,"Received Update query");
            update_from(listener,updater);
        }

        if ( (pollfd[0].revents & POLLIN) == POLLIN )
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
                syslog(LOG_ERR, "recvmsg: %s",strerror(errno));
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
            }
            else
            {
                parse_reply(&msg, cc, addrbuf, &req_echo);
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
                send_echo_request = 0;
                send_echo_query(sock,outpack);
            }
        }

        if ( pollret == 0 && req_echo > 0 )
        {
            if ( req_time == 0 )
            {
                req_time = time(NULL);
                continue;
            }

            if ( req_time + 15 <= time(NULL) )
            {
               req_echo--;
               send_echo_query(sock,outpack);
               req_time = time(NULL) + 15;
            }
        }

    }
    return 0;
}


char *prgName = NULL;

static void usage(char *me)
{
    fprintf(stderr,"Usage %s -i interface [-v] [-f] [-t ttl_max] [-d]\n",me);
    fprintf(stderr,"\t[-s updater] [-4] [-m map_file] [-g group] [-u user]\n");
    fprintf(stderr,"\t[-p ] [-w] [-D domain] [-T ttl] [-P port-number]\n");
}

int main(int argc, char **argv)
{
    int packlen = sizeof(outpack);
    char *device = NULL;
    int c;
    int foreground = 0;
    int t;
    pid_t pid;
    int debug = 0;
    int wait_for_if = 0;
    int port = 0;
    int listener = -1;

    if ( (prgName=strrchr(argv[0],'/')) )
        prgName++;
    else
        prgName = argv[0];
 
    while( (c = getopt(argc, argv, "i:vft:s:m:4p:du:g:wD:T:P:")) > 0)
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
                pid_file = strdup(optarg);
            break;
            break;
            case 'd':
                debug = 1;
            break;
            case 'u':
                user = optarg;
            break;
            case 'g':
                group = optarg;
            break;
            case 'w':
                wait_for_if=1;
            break;
            case 'D':
                strcpy(domain, optarg);
            break;
            case 'T':
                ttl = atoi(optarg);
            break;
            case 'P':
                port = atoi(optarg);
            break;
            default:
                usage(prgName);
                exit(1);
            break;
        }
    }

    if ( device == NULL )
    {
        usage(prgName);
    }

    umask(0);

    /* set logging */
    int opt = LOG_PID|LOG_CONS;
    if ( foreground||debug )
        opt |= LOG_PERROR;
    openlog(prgName, opt, LOG_DAEMON);
    if ( foreground||debug )
        setlogmask(LOG_UPTO(LOG_INFO));
    else
        setlogmask(LOG_UPTO(LOG_NOTICE));

    if ( !pid_file )
    {
        set_pid_ownership(user, group, PID_DIR);
        pid_file = calloc(strlen(PID_DIR)+strlen(prgName)+strlen(device)+7,1);
        if ( pid_file == NULL )
        {
             syslog(LOG_ERR,"calloc: %s",strerror(errno));
             exit(1);
        }
        sprintf(pid_file, "%s%s-%s.pid", PID_DIR, prgName, device);
    }

    /* check for pid file */
    FILE *pidf;
    if ( access(pid_file,R_OK) == 0 )
    {
        /* check if the process is running */
        pidf=fopen(pid_file,"r");
        if ( pidf )
        {
            if ( fscanf(pidf, "%d",&pid) == 1 )
            {
                 if ( kill(pid,0) == 0 )
                 {
                     syslog(LOG_ERR,"error %s exist\n",pid_file);
                     exit(1);
                 }
            }
            fclose(pidf);
        }
        else
        {
             syslog(LOG_ERR,"%s:%s  %s",prgName,pid_file, strerror(errno));
             exit(1);
        }
    }

    if ( ! foreground )
    {
        if (daemon(0, 0) < 0)
        {
             syslog(LOG_ERR, "daemon: %s",strerror(errno));
             exit(1);
        }
    }

    /* set signal handler and create pid file */
    set_signals();
    pid = getpid();

    if ( pid_file )
    {
       pidf = fopen(pid_file,"w");
       if ( pidf > 0 )
       {
           fprintf(pidf,"%d\n",pid);
           fclose(pidf);
           set_pid_ownership(user, group, pid_file);
       }
       else
       {
           syslog(LOG_ERR, "fopen: %s",strerror(errno));
           exit(1);
       }
    }
    
    syslog(LOG_NOTICE,"started");

    if ( port > 0 )
    {
       listener = open_listener(port);
    }

    /* if we have a virtual interface, we may wait fot it */
    do
    {
        memset(&own_addr,0,sizeof(own_addr));
        sock = icmp_socket(device, wait_for_if, &own_addr);

        if ( sock < 0 )
        {
            syslog(LOG_ERR,"error while opening socket");
            return 1;
        }

        set_ownership(user,group);
        syslog(LOG_NOTICE,"enter main loop");

        mainloop(sock, outpack, packlen, listener);
    }
    while ( wait_for_if );

    return 0;
}
