/* defines and types for the ninfo elements */
struct ni_hdr {
	struct icmp6_hdr ni_u;
	uint8_t          ni_nonce[8];
};

#define ni_type  ni_u.icmp6_type
#define ni_code  ni_u.icmp6_code
#define ni_cksum ni_u.icmp6_cksum
#define ni_qtype ni_u.icmp6_data16[0]
#define ni_flags ni_u.icmp6_data16[1]

/* Types */
#ifndef ICMPV6_NI_QUERY
# define ICMPV6_NI_QUERY 139
# define ICMPV6_NI_REPLY 140
#endif

/* Query Codes */
#define NI_SUBJ_IPV6 0
#define NI_SUBJ_NAME 1
#define NI_SUBJ_IPV4 2

/* Reply Codes */
#define NI_SUCCESS 0
#define NI_REFUSED 1
#define NI_UNKNOWN 2

/* Qtypes */
#define NI_QTYPE_NOOP     0
#define NI_QTYPE_NAME     2
#define NI_QTYPE_IPV6ADDR 3
#define NI_QTYPE_IPV4ADDR 4

/* Flags */
#define NI_IPV6ADDR_F_TRUNCATE  ntohs(0x0001)
#define NI_IPV6ADDR_F_ALL       ntohs(0x0002)
#define NI_IPV6ADDR_F_COMPAT    ntohs(0x0004)
#define NI_IPV6ADDR_F_LINKLOCAL ntohs(0x0008)
#define NI_IPV6ADDR_F_SITELOCAL ntohs(0x0010)
#define NI_IPV6ADDR_F_GLOBAL    ntohs(0x0020)

#define NI_IPV4ADDR_F_TRUNCATE  NI_IPV6ADDR_F_TRUNCATE
#define NI_IPV4ADDR_F_ALL       NI_IPV6ADDR_F_ALL

