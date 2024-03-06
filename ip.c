// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * ip.c - IP related functions
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stddef.h>
#include "util.h"
#include "ip.h"

#define IPV6_NH_OPT(nh)							\
	((nh) == 0   || (nh) == 43  || (nh) == 44  || (nh) == 50  ||	\
	 (nh) == 51  || (nh) == 60  || (nh) == 135 || (nh) == 139 ||	\
	 (nh) == 140 || (nh) == 253 || (nh) == 254)

/**
 * ipv6_l4hdr() - Find pointer to L4 header in IPv6 packet and extract protocol
 * @p:		Packet pool, packet number @idx has IPv6 header at @offset
 * @idx:	Index of packet in pool
 * @offset:	Pre-calculated IPv6 header offset
 * @proto:	Filled with L4 protocol number
 * @dlen:	Data length (payload excluding header extensions), set on return
 *
 * Return: pointer to L4 header, NULL if not found
 */
char *ipv6_l4hdr(const struct pool *p, int idx, size_t offset, uint8_t *proto,
		 size_t *dlen)
{
	const struct ipv6_opt_hdr *o;
	const struct ipv6hdr *ip6h;
	char *base;
	int hdrlen;
	uint8_t nh;

	base = packet_get(p, idx, 0, 0, NULL);
	ip6h = packet_get(p, idx, offset, sizeof(*ip6h), dlen);
	if (!ip6h)
		return NULL;

	offset += sizeof(*ip6h);

	nh = ip6h->nexthdr;
	if (!IPV6_NH_OPT(nh))
		goto found;

	while ((o = packet_get_try(p, idx, offset, sizeof(*o), dlen))) {
		nh = o->nexthdr;
		hdrlen = (o->hdrlen + 1) * 8;

		if (IPV6_NH_OPT(nh))
			offset += hdrlen;
		else
			goto found;
	}

	return NULL;

found:
	if (nh == 59)
		return NULL;

	*proto = nh;
	return base + offset;
}
