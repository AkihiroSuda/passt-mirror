/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_INTERNAL_H
#define UDP_INTERNAL_H

#include "tap.h" /* needed by udp_meta_t */

#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */

/**
 * struct udp_payload_t - UDP header and data for inbound messages
 * @uh:		UDP header
 * @data:	UDP data
 */
struct udp_payload_t {
	struct udphdr uh;
	char data[USHRT_MAX - sizeof(struct udphdr)];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)));
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))));
#endif

size_t udp_update_hdr4(struct iphdr *ip4h, struct udp_payload_t *bp,
		       const struct flowside *toside, size_t dlen,
		       bool no_udp_csum);
size_t udp_update_hdr6(struct ipv6hdr *ip6h, struct udp_payload_t *bp,
                       const struct flowside *toside, size_t dlen,
		       bool no_udp_csum);
int udp_sock_errs(const struct ctx *c, int s, uint32_t events);
#endif /* UDP_INTERNAL_H */
