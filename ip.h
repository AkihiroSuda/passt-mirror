/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef IP_H
#define IP_H

#include <netinet/ip.h>
#include <netinet/ip6.h>

#define IN4_IS_ADDR_UNSPECIFIED(a) \
	(((struct in_addr *)(a))->s_addr == htonl_constant(INADDR_ANY))
#define IN4_IS_ADDR_BROADCAST(a) \
	(((struct in_addr *)(a))->s_addr == htonl_constant(INADDR_BROADCAST))
#define IN4_IS_ADDR_LOOPBACK(a) \
	(ntohl(((struct in_addr *)(a))->s_addr) >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET)
#define IN4_IS_ADDR_MULTICAST(a) \
	(IN_MULTICAST(ntohl(((struct in_addr *)(a))->s_addr)))
#define IN4_ARE_ADDR_EQUAL(a, b) \
	(((struct in_addr *)(a))->s_addr == ((struct in_addr *)b)->s_addr)
#define IN4ADDR_LOOPBACK_INIT \
	{ .s_addr	= htonl_constant(INADDR_LOOPBACK) }
#define IN4ADDR_ANY_INIT \
	{ .s_addr	= htonl_constant(INADDR_ANY) }

#define L2_BUF_IP4_INIT(proto)						\
	{								\
		.version	= 4,					\
		.ihl		= 5,					\
		.tos		= 0,					\
		.tot_len	= 0,					\
		.id		= 0,					\
		.frag_off	= 0,					\
		.ttl		= 0xff,					\
		.protocol	= (proto),				\
		.saddr		= 0,					\
		.daddr		= 0,					\
	}
#define L2_BUF_IP4_PSUM(proto)	((uint32_t)htons_constant(0x4500) +	\
				 (uint32_t)htons_constant(0xff00 | (proto)))

#define L2_BUF_IP6_INIT(proto)						\
	{								\
		.priority	= 0,					\
		.version	= 6,					\
		.flow_lbl	= { 0 },				\
		.payload_len	= 0,					\
		.nexthdr	= (proto),				\
		.hop_limit	= 255,					\
		.saddr		= IN6ADDR_ANY_INIT,			\
		.daddr		= IN6ADDR_ANY_INIT,			\
	}

struct ipv6hdr {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t			version:4,
				priority:4;
#else
	uint8_t			priority:4,
				version:4;
#endif
#pragma GCC diagnostic pop
	uint8_t			flow_lbl[3];

	uint16_t		payload_len;
	uint8_t			nexthdr;
	uint8_t			hop_limit;

	struct in6_addr		saddr;
	struct in6_addr		daddr;
};

struct ipv6_opt_hdr {
	uint8_t			nexthdr;
	uint8_t			hdrlen;
	/*
	 * TLV encoded option data follows.
	 */
} __attribute__((packed));	/* required for some archs */

char *ipv6_l4hdr(const struct pool *p, int idx, size_t offset, uint8_t *proto,
		 size_t *dlen);
#endif /* IP_H */
