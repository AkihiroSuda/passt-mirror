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
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "log.h"

#define RS	133
#define RA	134
#define NS	135
#define NA	136

enum ndp_option_types {
	OPT_SRC_L2_ADDR		= 1,
	OPT_TARGET_L2_ADDR	= 2,
	OPT_PREFIX_INFO		= 3,
	OPT_MTU			= 5,
	OPT_RDNSS_TYPE		= 25,
	OPT_DNSSL_TYPE		= 31,
};

/**
 * struct opt_header - Option header
 * @type:	Option type
 * @len:	Option length, in units of 8 bytes
*/
struct opt_header {
	uint8_t type;
	uint8_t len;
} __attribute__((packed));

/**
 * struct opt_l2_addr - Link-layer address
 * @header:	Option header
 * @mac:	MAC address
 */
struct opt_l2_addr {
	struct opt_header header;
	unsigned char mac[ETH_ALEN];
} __attribute__((packed));

/**
 * struct ndp_na - NDP Neighbor Advertisement (NA) message
 * @ih:			ICMPv6 header
 * @target_addr:	Target IPv6 address
 * @target_l2_addr:	Target link-layer address
 */
struct ndp_na {
	struct icmp6hdr ih;
	struct in6_addr target_addr;
	struct opt_l2_addr target_l2_addr;
} __attribute__((packed));

/**
 * struct opt_prefix_info - Prefix Information option
 * @header:		Option header
 * @prefix_len:		The number of leading bits in the Prefix that are valid
 * @prefix_flags:	Flags associated with the prefix
 * @valid_lifetime:	Valid lifetime (ms)
 * @pref_lifetime:	Preferred lifetime (ms)
 * @reserved:		Unused
 */
struct opt_prefix_info {
	struct opt_header header;
	uint8_t prefix_len;
	uint8_t prefix_flags;
	uint32_t valid_lifetime;
	uint32_t pref_lifetime;
	uint32_t reserved;
} __attribute__((packed));

/**
 * struct opt_mtu - Maximum transmission unit (MTU) option
 * @header:		Option header
 * @reserved:		Unused
 * @value:		MTU value, network order
 */
struct opt_mtu {
	struct opt_header header;
	uint16_t reserved;
	uint32_t value;
} __attribute__((packed));

/**
 * struct rdnss - Recursive DNS Server (RDNSS) option
 * @header:	Option header
 * @reserved:	Unused
 * @lifetime:	Validity time (s)
 * @dns:	List of DNS server addresses
 */
struct opt_rdnss {
	struct opt_header header;
	uint16_t reserved;
	uint32_t lifetime;
	struct in6_addr dns[MAXNS + 1];
} __attribute__((packed));

/**
 * struct dnssl - DNS Search List (DNSSL) option
 * @header:		Option header
 * @reserved:		Unused
 * @lifetime:		Validity time (s)
 * @domains:		List of NULL-seperated search domains
 */
struct opt_dnssl {
	struct opt_header header;
	uint16_t reserved;
	uint32_t lifetime;
	unsigned char domains[MAXDNSRCH * NS_MAXDNAME];
} __attribute__((packed));

/**
 * struct ndp_ra - NDP Router Advertisement (RA) message
 * @ih:			ICMPv6 header
 * @reachable:		Reachability time, after confirmation (ms)
 * @retrans:		Time between retransmitted NS messages (ms)
 * @prefix_info:	Prefix Information option
 * @prefix:		IPv6 prefix
 * @mtu:		MTU option
 * @source_ll:		Target link-layer address
 * @var:		Variable fields
 */
struct ndp_ra {
	struct icmp6hdr ih;
	uint32_t reachable;
	uint32_t retrans;
	struct opt_prefix_info prefix_info;
	struct in6_addr prefix;
	struct opt_l2_addr source_ll;

	unsigned char var[sizeof(struct opt_mtu) + sizeof(struct opt_rdnss) +
			  sizeof(struct opt_dnssl)];
} __attribute__((packed, aligned(__alignof__(struct in6_addr))));

/**
 * struct ndp_ns - NDP Neighbor Solicitation (NS) message
 * @ih:			ICMPv6 header
 * @target_addr:	Target IPv6 address
 */
struct ndp_ns {
	struct icmp6hdr ih;
	struct in6_addr target_addr;
} __attribute__((packed, aligned(__alignof__(struct in6_addr))));

/**
 * ndp_send() - Send an NDP message
 * @c:		Execution context
 * @dst:	IPv6 address to send the message to
 * @buf:	ICMPv6 header + message payload
 * @l4len:	Length of message, including ICMPv6 header
 */
static void ndp_send(const struct ctx *c, const struct in6_addr *dst,
		     const void *buf, size_t l4len)
{
	const struct in6_addr *src = &c->ip6.our_tap_ll;

	tap_icmp6_send(c, src, dst, buf, l4len);
}

/**
 * ndp_na() - Send an NDP Neighbour Advertisement (NA) message
 * @c:		Execution context
 * @dst:	IPv6 address to send the NA to
 * @addr:	IPv6 address to advertise
 */
static void ndp_na(const struct ctx *c, const struct in6_addr *dst,
	    const struct in6_addr *addr)
{
	struct ndp_na na = {
		.ih = {
			.icmp6_type		= NA,
			.icmp6_code		= 0,
			.icmp6_router		= 1,
			.icmp6_solicited	= 1,
			.icmp6_override		= 1,
		},
		.target_addr = *addr,
		.target_l2_addr = {
			.header	= {
				.type		= OPT_TARGET_L2_ADDR,
				.len		= 1,
			},
		}
	};

	memcpy(na.target_l2_addr.mac, c->our_tap_mac, ETH_ALEN);

	ndp_send(c, dst, &na, sizeof(na));
}

/**
 * ndp_ra() - Send an NDP Router Advertisement (RA) message
 * @c:		Execution context
 * @dst:	IPv6 address to send the RA to
 */
static void ndp_ra(const struct ctx *c, const struct in6_addr *dst)
{
	struct ndp_ra ra = {
		.ih = {
			.icmp6_type		= RA,
			.icmp6_code		= 0,
			.icmp6_hop_limit	= 255,
			/* RFC 8319 */
			.icmp6_rt_lifetime	= htons_constant(65535),
			.icmp6_addrconf_managed	= 1,
		},
		.prefix_info = {
			.header = {
				.type		= OPT_PREFIX_INFO,
				.len		= 4,
			},
			.prefix_len		= 64,
			.prefix_flags		= 0xc0,	/* prefix flags: L, A */
			.valid_lifetime		= ~0U,
			.pref_lifetime		= ~0U,
		},
		.prefix = c->ip6.addr,
		.source_ll = {
			.header = {
				.type		= OPT_SRC_L2_ADDR,
				.len		= 1,
			},
		},
	};
	unsigned char *ptr = NULL;

	ptr = &ra.var[0];

	if (c->mtu != -1) {
		struct opt_mtu *mtu = (struct opt_mtu *)ptr;
		*mtu = (struct opt_mtu) {
			.header = {
				.type		= OPT_MTU,
				.len		= 1,
			},
			.value			= htonl(c->mtu),
		};
		ptr += sizeof(struct opt_mtu);
	}

	if (!c->no_dhcp_dns) {
		size_t dns_s_len = 0;
		int i, n;

		for (n = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[n]); n++);
		if (n) {
			struct opt_rdnss *rdnss = (struct opt_rdnss *)ptr;
			*rdnss = (struct opt_rdnss) {
				.header = {
					.type		= OPT_RDNSS_TYPE,
					.len		= 1 + 2 * n,
				},
				.lifetime		= ~0U,
			};
			for (i = 0; i < n; i++) {
				rdnss->dns[i] = c->ip6.dns[i];
			}
			ptr += offsetof(struct opt_rdnss, dns) +
			       i * sizeof(rdnss->dns[0]);

			for (n = 0; *c->dns_search[n].n; n++)
				dns_s_len += strlen(c->dns_search[n].n) + 2;
		}

		if (!c->no_dhcp_dns_search && dns_s_len) {
			struct opt_dnssl *dnssl = (struct opt_dnssl *)ptr;
			*dnssl = (struct opt_dnssl) {
				.header = {
					.type = OPT_DNSSL_TYPE,
					.len  = DIV_ROUND_UP(dns_s_len, 8) + 1,
				},
				.lifetime     = ~0U,
			};
			ptr = dnssl->domains;

			for (i = 0; i < n; i++) {
				size_t len;
				char *dot;

				*(ptr++) = '.';

				len = sizeof(dnssl->domains) -
				      (ptr - dnssl->domains);

				strncpy((char *)ptr, c->dns_search[i].n, len);
				for (dot = (char *)ptr - 1; *dot; dot++) {
					if (*dot == '.')
						*dot = strcspn(dot + 1, ".");
				}
				ptr += strlen(c->dns_search[i].n);
				*(ptr++) = 0;
			}

			memset(ptr, 0, 8 - dns_s_len % 8);	/* padding */
			ptr += 8 - dns_s_len % 8;
		}
	}

	memcpy(&ra.source_ll.mac, c->our_tap_mac, ETH_ALEN);

	ndp_send(c, dst, &ra, ptr - (unsigned char *)&ra);
}

/**
 * ndp() - Check for NDP solicitations, reply as needed
 * @c:		Execution context
 * @ih:		ICMPv6 header
 * @saddr:	Source IPv6 address
 * @p:		Packet pool
 *
 * Return: 0 if not handled here, 1 if handled, -1 on failure
 */
int ndp(const struct ctx *c, const struct icmp6hdr *ih,
	const struct in6_addr *saddr, const struct pool *p)
{
	if (ih->icmp6_type < RS || ih->icmp6_type > NA)
		return 0;

	if (c->no_ndp)
		return 1;

	if (ih->icmp6_type == NS) {
		const struct ndp_ns *ns;

		ns = packet_get(p, 0, 0, sizeof(struct ndp_ns), NULL);
		if (!ns)
			return -1;

		if (IN6_IS_ADDR_UNSPECIFIED(saddr))
			return 1;

		info("NDP: received NS, sending NA");

		ndp_na(c, saddr, &ns->target_addr);
	} else if (ih->icmp6_type == RS) {
		if (c->no_ra)
			return 1;

		info("NDP: received RS, sending RA");
		ndp_ra(c, saddr);
	}

	return 1;
}
