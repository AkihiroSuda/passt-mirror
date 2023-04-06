// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * ndp.c - NDP support for PASST
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include <linux/icmpv6.h>

#include "checksum.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "log.h"

#define RS	133
#define RA	134
#define NS	135
#define NA	136

/**
 * ndp() - Check for NDP solicitations, reply as needed
 * @c:		Execution context
 * @ih:		ICMPv6 header
 * @saddr	Source IPv6 address
 *
 * Return: 0 if not handled here, 1 if handled, -1 on failure
 */
int ndp(struct ctx *c, const struct icmp6hdr *ih, const struct in6_addr *saddr)
{
	const struct in6_addr *rsaddr; /* src addr for reply */
	char buf[BUFSIZ] = { 0 };
	struct ipv6hdr *ip6hr;
	struct icmp6hdr *ihr;
	struct ethhdr *ehr;
	unsigned char *p;
	size_t len;

	if (ih->icmp6_type < RS || ih->icmp6_type > NA)
		return 0;

	if (c->no_ndp)
		return 1;

	ehr = (struct ethhdr *)buf;
	ip6hr = (struct ipv6hdr *)(ehr + 1);
	ihr = (struct icmp6hdr *)(ip6hr + 1);

	if (ih->icmp6_type == NS) {
		if (IN6_IS_ADDR_UNSPECIFIED(saddr))
			return 1;

		info("NDP: received NS, sending NA");
		ihr->icmp6_type = NA;
		ihr->icmp6_code = 0;
		ihr->icmp6_router = 1;
		ihr->icmp6_solicited = 1;
		ihr->icmp6_override = 1;

		p = (unsigned char *)(ihr + 1);
		memcpy(p, ih + 1, sizeof(struct in6_addr)); /* target address */
		p += 16;
		*p++ = 2;				    /* target ll */
		*p++ = 1;				    /* length */
		memcpy(p, c->mac, ETH_ALEN);
		p += 6;
	} else if (ih->icmp6_type == RS) {
		size_t dns_s_len = 0;
		int i, n;

		if (c->no_ra)
			return 1;

		info("NDP: received RS, sending RA");
		ihr->icmp6_type = RA;
		ihr->icmp6_code = 0;
		ihr->icmp6_hop_limit = 255;
		ihr->icmp6_rt_lifetime = htons(9000);
		ihr->icmp6_addrconf_managed = 1;

		p = (unsigned char *)(ihr + 1);
		p += 8;				/* reachable, retrans time */
		*p++ = 3;			/* prefix */
		*p++ = 4;			/* length */
		*p++ = 64;			/* prefix length */
		*p++ = 0xc0;			/* prefix flags: L, A */
		*(uint32_t *)p = htonl(3600);	/* lifetime */
		p += 4;
		*(uint32_t *)p = htonl(3600);	/* preferred lifetime */
		p += 8;
		memcpy(p, &c->ip6.addr, 8);	/* prefix */
		p += 16;

		if (c->mtu != -1) {
			*p++ = 5;			/* type */
			*p++ = 1;			/* length */
			p += 2;				/* reserved */
			*(uint32_t *)p = htonl(c->mtu);	/* MTU */
			p += 4;
		}

		if (c->no_dhcp_dns)
			goto dns_done;

		for (n = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[n]); n++);
		if (n) {
			*p++ = 25;				/* RDNSS */
			*p++ = 1 + 2 * n;			/* length */
			p += 2;					/* reserved */
			*(uint32_t *)p = htonl(60);		/* lifetime */
			p += 4;

			for (i = 0; i < n; i++) {
				memcpy(p, &c->ip6.dns[i], 16);	/* address */
				p += 16;
			}

			for (n = 0; *c->dns_search[n].n; n++)
				dns_s_len += strlen(c->dns_search[n].n) + 2;
		}

		if (!c->no_dhcp_dns_search && dns_s_len) {
			*p++ = 31;				/* DNSSL */
			*p++ = (dns_s_len + 8 - 1) / 8 + 1;	/* length */
			p += 2;					/* reserved */
			*(uint32_t *)p = htonl(60);		/* lifetime */
			p += 4;

			for (i = 0; i < n; i++) {
				char *dot;

				*(p++) = '.';

				strncpy((char *)p, c->dns_search[i].n,
					sizeof(buf) -
					((intptr_t)p - (intptr_t)buf));
				for (dot = (char *)p - 1; *dot; dot++) {
					if (*dot == '.')
						*dot = strcspn(dot + 1, ".");
				}
				p += strlen(c->dns_search[i].n);
				*(p++) = 0;
			}

			memset(p, 0, 8 - dns_s_len % 8);	/* padding */
			p += 8 - dns_s_len % 8;
		}

dns_done:
		*p++ = 1;			/* source ll */
		*p++ = 1;			/* length */
		memcpy(p, c->mac, ETH_ALEN);
		p += 6;
	} else {
		return 1;
	}

	len = (uintptr_t)p - (uintptr_t)ihr - sizeof(*ihr);

	if (IN6_IS_ADDR_LINKLOCAL(saddr))
		c->ip6.addr_ll_seen = *saddr;
	else
		c->ip6.addr_seen = *saddr;

	if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
		rsaddr = &c->ip6.gw;
	else
		rsaddr = &c->ip6.addr_ll;

	tap_icmp6_send(c, rsaddr, saddr, ihr, len + sizeof(*ihr));

	return 1;
}
