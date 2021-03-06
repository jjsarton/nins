/* radvc.c
 * listen for radvd router advertissement and
 * fill the file /etc/resolv.conf if the required
 * informations are not present.
 *
 * TBD:
 * read resolv.conf file into a list and check if search and nameserver
 * are set according to our infos.
 * if our search list don't contain our own domain put it at the beginnning
 * of oir list
 * put our name server as the first name server if there are more
 * name server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <getopt.h>
#include <ifaddrs.h>
#if defined __linux__
#define _GNU_SOURCE 1 /* for pktinfo */
#endif
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "version.h"
#include <net/if.h>

#if ! defined ND_OPT_RNDSS_INFORMATION
#define ND_OPT_RNDSS_INFORMATION 25
#endif

#if ! defined ND_OPT_DNSSL_INFORMATION
#define ND_OPT_DNSSL_INFORMATION 31
#endif

/* for VPN interface check */
#define NO_VPN  0
#define HAS_VPN 1
#define IS_VPN  2

/* a few globale variable for handling of the
 * resolv.conf file
 */
 
static char *resolv_conf = "/etc/resolv.conf";
static char *save_dir = "/tmp";
static char *save_file = "/tmp";
static char *save_file_vpn = "/tmp";
static char *vpn_file = "/tmp";

static char *pid_file = NULL;
static char *vpn_interface = NULL;
static int   vpn_idx=0;
static int   vpn_resolv_stored=0;

static char domain[4096];
static char ns_server[256];
static time_t resolv_time = 0;
static off_t  resolv_size = 0;

static int cp(const char *src, const char *dest);

static char *me = NULL;

typedef struct ra_xxx_info_head
{
    uint8_t type;
    uint8_t length;
    uint16_t reserved;
    uint32_t lifetime;
} ra_xxx_head_t;

static void restore_resolv_conf(char *saved_file, char *resolv_conf)
{
    cp(saved_file, resolv_conf);
    unlink(saved_file);
}

static void sig_handler(int sig)
{
    /* restore the resolv.conf file */
    if ( access(save_file, F_OK) == 0 )
    {
        restore_resolv_conf(save_file, resolv_conf);
        if (vpn_interface && access(save_file_vpn, F_OK) == 0)
        {
            unlink(save_file_vpn);
            unlink(vpn_file);
        }
    }
    else if (vpn_interface && access(save_file_vpn, F_OK) == 0 )
    {
        restore_resolv_conf(save_file_vpn, resolv_conf);
    }
    if ( pid_file )
    {
        pid_t my_pid = getpid();
        pid_t pid;
        FILE *fp;
        if ( (fp=fopen(pid_file,"r")) )
        {
            if ( fscanf(fp,"%d\n",&pid) == 1 )
            {
                if ( pid == my_pid )
                {
                    unlink(pid_file);
                }
            }
        }
    }

    exit(0);
}

static void usr_handler(int sig)
{
    if ( vpn_interface != NULL )
    {
        switch(sig)
        {
           case SIGUSR1: /* from subnet-up */
               cp(resolv_conf, vpn_file);
               if ( save_file_vpn )
               {
                  cp(save_file_vpn, resolv_conf);
               }
               else if ( access(save_file, F_OK) == 0 )
               {
                   cp(save_file, resolv_conf);
               }
           break;
           case SIGUSR2: /* from subnet-down */
               if ( access(vpn_file, F_OK) == 0 )
               {
                   cp(save_file_vpn, resolv_conf);
               }
           break;
        }
    }
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
    sigaddset(&smask, SIGUSR1);
    sigaddset(&smask, SIGUSR2);

    memset(&act, 0, sizeof(act));
    act.sa_handler = sig_handler;
    act.sa_mask = smask;

    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    act.sa_flags |= SA_RESTART;
    act.sa_handler = usr_handler;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    
}


static int cp(const char *src, const char *dest)
{
    struct stat st;
    int r;
    if ( stat(src, &st) == 0 )
    {
        char *buf = calloc(st.st_size,1);
        if ( buf )
        {
            FILE *fp = fopen(src, "r");
            if ( fp )
            {
                r = fread(buf, 1, st.st_size, fp);
                fclose(fp);
                if ( r > 0 && (fp = fopen(dest, "w")) )
                {
                    fwrite(buf, r, 1, fp);
                    fclose(fp);
                    return 1;
                }
                else
                {
                    perror("fopen dest");
                }
            }
            else
            {
                perror("fopen src");
            }
            free(buf);
        }
        else
        {
            perror("calloc");
        }
    }
    else
    {
        perror("stat");
    }
    return 0;
}

static int init_resolv_conf_data(void)
{
    struct  stat act_stat;
    if ( resolv_conf )
    {
        if ( stat(resolv_conf, &act_stat ) == 0 )
        {
            resolv_time = act_stat.st_mtime -1 ; /* first time actualize */
            resolv_size = act_stat.st_size;
            return 1;
        }
        else
        {
            perror("stat");
        }
    }
    return 0;
}

static int check_for_search(const char *line, const char *domain)
{
    int ret = 0;
    char *comment = strstr(line,"#");
    char *search = strstr(line,"search");
    char *dom = strstr(line,domain);
    if ( ! search )
    {
        search = strstr(line,"domain");
    }
    if ( dom && search )
    {
        if ( (comment && comment > search) || comment == NULL )
            if( (comment && comment > dom) || comment == NULL )
                if ( dom > search )
                    ret = 1;
    }
    return ret;
}

static int check_for_server(const char *line, const char *server)
{
    int ret = 0;
    char *comment = strstr(line,"#");
    char *ns = strstr(line,"nameserver");
    char *addr = strstr(line,server);

    if ( ns && addr )
    {
        if ( (comment && comment > ns) || comment == NULL )
            if( (comment && comment > addr) || comment == NULL )
                if ( addr > ns )
                    ret = 1;
    }
    return ret;
}

static int copy_name_server(char *in, char *out, int sz)
{
    int found = 0;
    if ( (strstr(in,"nameserver ")) == in )
    {
        if ( strlen(in) < sz-1 )
            strncpy(out, in, sz-1);
        else
            strcpy(out,in);
        out[sz-1]='\0';
        found = 1;
    }
    return found;
}

static int copy_search(char *in, char *out, int sz, char *domain)
{
    int found = 0;
    char *s;
    char *t;
    char *d;
    int dl = dl = strlen(domain);
    if ( ( (s=strstr(in,"search ")) == in)  && s == in )
    {
        if ( strlen(in) < sz-1-dl )
        {
            s = s + 6;
            t = out;
            d = strstr(s, domain);
            if (!d )
            {
                strcpy(t, s);
            }    
            else
            {
                if ( isspace(d[-1]) && (d[dl] == '\0' || isspace(d[dl])) )
                {
                     // copy part before domain */
                     s++;
                     strncpy(t, s, d-s);
                     // advance pointer
                     t += d-s;
                     s += d-s+dl+1;
                     strcpy(t, s);
                }
                else
                {
                     strcpy(t, s);
                }
            }
            
        }
        else
        {
            strcpy(out,in);
        }
        out[sz-1]='\0';
        found = 1;
    }
    return found;
}

static int mod_resolv_conf(const char *resolv_conf, char *save_file, char *domain, char *ns_server)
{
    struct  stat act_stat;
    char    nameserver[2][256];
    char    old_search[256];
    int idx = 0;

    memset(nameserver, 0, sizeof(nameserver));
    memset(old_search, 0, sizeof(old_search));
    if ( *domain && *resolv_conf )
    {
        if ( stat(resolv_conf, &act_stat) == 0 )
        {
            if ( act_stat.st_mtime > resolv_time || resolv_size != act_stat.st_size )
            {
                /* resolv.conf file what modified !
                 * look for the search and name server entry.
                 * if search is not set to domain add this
                 * if servername ns_server not set add this
                 */
                FILE *fp;
                if ( ( fp = fopen(resolv_conf,"r")) != NULL )
                {
                    char buf[2048];
                    int has_search = 0;
                    int has_server = 0;
                    while ( fgets(buf, sizeof(buf), fp) && (!has_search || !has_server))
                    {
                        char *c = strchr(buf,'\n');
                        if ( c ) *c = '\0';
                        if ( check_for_search(buf,domain) )
                        {
                            has_search = 1;
                        }
                        if ( check_for_server(buf, ns_server) )
                        {
                            has_server = 1;
                        }
                        if ( idx < 2 )
                        {
                            if (copy_name_server(buf, nameserver[idx], sizeof(nameserver[idx])))
                            {
                                idx++;
                            }
                        }
                        copy_search(buf, old_search, sizeof(old_search), domain);
                    }
                    fclose(fp);

                    if ( !has_server || !has_search )
                    {
                        /* save old file build a new */
                        if ( !cp(resolv_conf, save_file) )
                        {
                            printf("Copy %s to %s failed\n",resolv_conf, save_file);
                        }

                        fp = fopen(resolv_conf,"w");

                        if ( fp )
                        {
                            printf("%s: set search %s %s\n",me,domain, old_search);
                            fprintf(fp, "search %s %s\n",domain, old_search);
                            printf("%s: set nameserver %s\n",me,ns_server);
                            fprintf(fp, "nameserver %s\n",ns_server);
                            resolv_time = time(NULL);
                            int i = 0;
                            while (i < idx)
                            {
                                printf("%s: set %s\n",me,nameserver[i]);
                                fprintf(fp, "%s\n",nameserver[i]);
                                i++;
                            }
                            fclose(fp);
                        }
                    }
                }
            }
        }
    }
    return 1;
}

static int build_search_list(ra_xxx_head_t *hd)
{
    *domain = '\0';
    int length = hd->length << 3;
    uint8_t *s = (uint8_t*) hd  + sizeof(ra_xxx_head_t);
    int c;
    uint8_t l;
    char *t = domain;
    *t = '\0';

    for ( c = 0; c < length && *s ; )
    {
        /* first byte is number of chars */
        l = *s;
        s++;
        c++;
        strncpy((char*)t, (char*)s,l);
        s += l;
        c += l;
        t += l;

        if ( *s )
        { 
            *t++ = '.';
            c++;
        }
        else if ( s[1] )
        {
            *t++ = ' ';
            c++;
            s++;
        }
        *t = '\0';
    }
    return 1;
}

static int decode_router_advertisement(struct icmp6_hdr *icmph, int len, int vpn_state)
{
    uint8_t *list;
    struct nd_opt_hdr *opt_hdr;
    unsigned char *data = (unsigned char *)icmph + sizeof(struct icmp6_hdr) + sizeof(struct icmp6_hdr);
    len -= (char*)data-(char*)icmph;
    
    while (len > 0 )
    {
        opt_hdr = (struct nd_opt_hdr *)data;
        switch(opt_hdr->nd_opt_type)
        {
            case ND_OPT_RNDSS_INFORMATION:
                list = data + sizeof(ra_xxx_head_t);
                inet_ntop(AF_INET6, list, ns_server, sizeof(ns_server));
            break;
            case ND_OPT_DNSSL_INFORMATION:
                build_search_list((ra_xxx_head_t*)data);
            break;
        }
        data += opt_hdr->nd_opt_len * 8;
        len  -= opt_hdr->nd_opt_len * 8;
    }
    if ( *domain && *ns_server)
    {
        if ( vpn_state == NO_VPN )
        {
            if (vpn_resolv_stored == 0 )
            {
                mod_resolv_conf(resolv_conf, save_file, domain,  ns_server);
            }
            else if ( vpn_interface )
            {
                restore_resolv_conf(save_file_vpn,resolv_conf);
                vpn_resolv_stored = 0;
            }
        }
        else if ( vpn_state == IS_VPN )
        {
            mod_resolv_conf(resolv_conf, save_file_vpn, domain,  ns_server);
            vpn_resolv_stored = 1;
        }
    }

    return 1;
}

static int check_for_vpn(int idx)
{
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *pt;
    int if_found = 0;
    int res = NO_VPN;

    if ( vpn_interface == NULL )
    {
       return NO_VPN;
    }

    if ( vpn_idx == 0 && vpn_interface )
    {
        vpn_idx = if_nametoindex (vpn_interface);
    }

    /* check if the vpn interface is active */
    if ( getifaddrs(&ifa) )
    {
        perror("getifaddrs");
    }

    /* check state for VPN */
    pt = ifa;
    while(pt)
    {
        if ( strcmp(pt->ifa_name, vpn_interface) == 0 )
        {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)pt->ifa_addr;
            int family = sa6? sa6->sin6_family : -1;
            if ( family == AF_INET6 )
            {
                int link_local = IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr);
                int loopback = IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr);

                if ( !link_local && !loopback )
                {
                    if_found = 1;
                    break;
                }
            }
        }
        pt = pt->ifa_next;
    }
    if ( ifa )
    {
        freeifaddrs(ifa);
    }

    /* vpn interfave found and active */
    if ( if_found && idx == vpn_idx )
    {
        res = IS_VPN;
    }
    if ( if_found && idx != vpn_idx )
    {
        res = HAS_VPN;
    }

    if ( !if_found )
    {
        /* no vpn interface active */
        if ( vpn_resolv_stored )
        {
            /* actual resolv.conf wrong */
            /* restore to previous */
            if ( access(save_file,R_OK) == 0)
            {
                restore_resolv_conf(save_file, resolv_conf);
                vpn_resolv_stored = 0;
            }
            else if (vpn_interface && access(save_file_vpn,R_OK) == 0)
            {
                restore_resolv_conf(save_file_vpn, resolv_conf);
                vpn_resolv_stored = 0;
            }
        }
        vpn_idx = 0;
        res = NO_VPN;
    }

   return res;
}

static int parse_reply(struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
    unsigned char *buf = msg->msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;
    int idx = 0;
    struct in6_pktinfo *pkt;
    int vpn_state = NO_VPN;

    for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
    {
        if (c->cmsg_level != SOL_IPV6)
            continue;
        switch(c->cmsg_type)
        {
            case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
            case IPV6_2292HOPLIMIT:
#endif
            if (c->cmsg_len < CMSG_LEN(sizeof(int)))
                continue;
            break;
            case IPV6_PKTINFO:
                pkt = (struct in6_pktinfo *)CMSG_DATA(c);
                idx = pkt->ipi6_ifindex;
            break;
        }
    }

    /* Now the ICMP part */

    icmph = (struct icmp6_hdr *) buf;
    if (cc < 8) {
        return 1;
    }
    switch (icmph->icmp6_type)
    {
        case ND_ROUTER_ADVERT:
            if (idx )
            {
                vpn_state = check_for_vpn(idx);
            }
            if ( vpn_state == IS_VPN || (vpn_state == NO_VPN && !vpn_resolv_stored) )
            {
                decode_router_advertisement(icmph, cc, vpn_state);
            }
        break;
    }
    return 0;
}

static int mainloop(int sock, const char *resolv_conf, char *save_file)
{
    char addrbuf[128];
    char ans_data[4096];
    struct iovec iov;
    struct msghdr msg;
    int cc;
    int polling = 0;;
    struct pollfd pollfd;
    char control[sizeof(struct in6_pktinfo)<<1];

    pollfd.fd = sock;
    pollfd.events = POLLIN;
    pollfd.revents = 0;


    for(;;)
    {
        poll(&pollfd, 1, 1000);
        if ( (pollfd.revents & POLLIN) == POLLIN )
        {
            iov.iov_len = sizeof(ans_data);
            iov.iov_base = ans_data ;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = addrbuf;
            msg.msg_namelen = sizeof(addrbuf);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);;
            cc = recvmsg(sock, &msg, polling);
            if (cc > 8)
            {
                parse_reply(&msg, cc, addrbuf, NULL);
            }
        }
    }
    return 0;
}

static int open_socket(void)
{
    struct icmp6_filter filter;
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if ( sock > 0 )
    {
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT,&filter);
        if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(struct icmp6_filter))<0)
        {
            perror("setsockopt");
            close(sock);
            sock=-1;
        }
            int on = 1;
            if ( setsockopt(sock,IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0
#ifdef IPV6_2292PKTINFO
                 && setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on)) < 0 
#endif
               )
            {
                perror( "setsockopt");
            }
    }
    else
    {
        perror("socket");
    }
    return sock;
}

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

int main(int argc, char **argv)
{
    int foreground = 0;
    int c;
    int sock;
    pid_t pid;
    FILE *fp = NULL;

    me = strchr(argv[0],'/');
    if ( me == NULL ) me = argv[0];
    else me++;

    while((c = getopt(argc, argv, "fvd:r:p:i:")) > 0)
    {
        switch (c)
        {
            case 'f':
               foreground = 1;
            break;
            case 'r':
               resolv_conf = optarg;
            break;
            case 'd':
               save_dir = optarg;
            break;
            case 'p':
               pid_file = optarg;
            break;
            case 'i': /* vpn interface (special handle if set */
                vpn_interface = optarg;
            break;
            case 'v':
               printf("%s: version %s\n",me,version);
               return 0;
            break;
            default:
                printf("usage: %s [-f] [-r resolver-file] [-d savedir] [-p pid_file] [-i vpn-if]\n",me);
                exit(1);
        }
    }

    sock = open_socket();
    if ( sock == -1 )
        exit(1);
    if ( !init_resolv_conf_data() )
        exit(1);

    char *s = strrchr(resolv_conf, '/');
    if ( s )
    {
        c = strlen(save_dir)+1+ strlen(s);
        save_file = calloc(c+1,1);
        if ( save_file )
        {
            sprintf(save_file, "%s%s",save_dir, s);
        }
        else
        {
            perror("calloc");
            exit(1);
        }
        if ( vpn_interface )
        {
            c = strlen(save_dir)+1+ strlen(s)+4;
            save_file_vpn = calloc(c,1);
            if ( save_file_vpn )
            {
                sprintf(save_file_vpn, "%s%s.vpn",save_dir, s);
            }
            else
            {
                perror("calloc");
                exit(1);
            }
            vpn_file = calloc(c,1);
            if ( vpn_file )
            {
                sprintf(vpn_file, "%svpn-%s",save_dir, s);
            }
            else
            {
                perror("calloc");
                exit(1);
            }

        }
    }
    else
    {
        fprintf(stderr,"%s: absolute path required for the resolv.conf file\n",me);
        exit(1);
    }

    umask(07);

    if ( pid_file && access(pid_file,R_OK) == 0 )
    {
        /* check if the process is running */
        fp=fopen(pid_file,"r");
        if ( fp )
        {
            if ( fscanf(fp, "%d",&pid) == 1 )
            {
                 if ( kill(pid,0) == 0 )
                 {
                     fprintf(stderr, "%s: error %s exist\n",me, pid_file);
                     exit(1);
                 }
            }
            fclose(fp);
        }
        else
        {
             fprintf(stderr,"%s:%s  %s",me,pid_file, strerror(errno));
             exit(1);
        }
    }

    set_signals();

    if ( ! foreground )
    {
        if (daemon(1, 0) < 0)
        {
            perror("daemon");
            exit(1);
        }
    }

    if ( pid_file )
    {
        if ( (fp=fopen(pid_file,"w")) )
        {
             pid = getpid();
             fprintf(fp,"%d\n",pid);
             fclose(fp);
        }
    }

    mainloop(sock, resolv_conf, save_file);
    return 0;
}
