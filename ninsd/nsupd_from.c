/* nsupd_from.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/types.h>

int open_listener(int port)
{
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if ( sock == -1 )
    {
        syslog(LOG_NOTICE,"failed to open socket: %s", strerror(errno));
    }
    struct sockaddr_in6 sa;
    memset((void*)&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if ( bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0 )
    {
        syslog(LOG_NOTICE,"failed to bind socket: %s", strerror(errno));
    }
    
#ifdef SO_REUSEPORT
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *)&optval, sizeof(optval)) < 0)
    {
        syslog(LOG_NOTICE,"setsockopt: %s", strerror(errno))
        exit(1);
    }
#endif

    if (listen(sock, 1) < 0 )
    {
        syslog(LOG_NOTICE,"failed to listen: %s", strerror(errno));
    }

    return sock;
}


int update_from(int listener, char *updater)
{
    int ac;
    char buf[2048];
    struct sockaddr_in6 sa;
    socklen_t sz = sizeof(sa);

    if ((ac = accept(listener, (struct sockaddr*)&sa, &sz))<1)
    {
        syslog(LOG_NOTICE,"failed to accept: %s", strerror(errno));
    }
    else
    {
        /* process messages */
        struct pollfd pa;
        FILE *prg;
        prg = popen(updater,"w");
        if ( prg == NULL )
        {
           close(ac);
        }
        else
        {
            pa.fd = ac;
            pa.events = POLLIN|POLLHUP;

            for(;;)
            {
                int r = 0;
                poll(&pa, 1, 10);
                if ( (pa.revents & POLLIN) == POLLIN )
                {
                    r = recv(ac, buf, sizeof(buf), 0 );
		    if ( r > 0 )
                        fwrite(buf, r, 1, prg);
                }
                if ( (pa.revents & POLLHUP) == POLLHUP || r == 0 )
                {
                    close(ac);
                    fclose(prg);
                    break;
                }
            }
        }
    }
    
    return 0;
}

