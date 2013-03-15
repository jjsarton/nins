#ifndef DECODE_RA_H
#define DECODE_RA_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

extern int decode_router_advertisement(struct icmp6_hdr *icmph, int len, struct in6_addr* ns_server, int *ttl, char*domain);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* DECODE_RA_H */
