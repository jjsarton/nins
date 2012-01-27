#ifndef DECODE_RA_H
#define DECODE_RA_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

extern int decode_router_advertisement(struct icmp6_hdr *icmph, int len, struct in6_addr* ns_server, int *ttl, char*domain);
extern void send_ra_solicit(unsigned char *buf, struct sockaddr_in6 *whereto);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* LIST_H */
