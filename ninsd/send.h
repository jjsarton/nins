#ifndef SEND_H
#define SEND_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

extern int query_addr(int sock, uint8_t *buf, struct in6_addr *addr);
extern int query_name(int sock, uint8_t *buf, struct in6_addr *addr);
extern int send_ra_solicit(int sock, uint8_t *buf);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* SEND_H */
