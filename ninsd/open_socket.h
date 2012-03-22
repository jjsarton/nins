#ifndef OPEN_SOCKET_H
#define OPEN_SOCKET_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

extern int icmp_socket(char *name, int wait_for_if, struct in6_addr *addr);


#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* OPEN_SOCKET_H */
