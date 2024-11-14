/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NDP_H
#define NDP_H

struct icmp6hdr;

int ndp(const struct ctx *c, const struct icmp6hdr *ih,
	const struct in6_addr *saddr, const struct pool *p);
void ndp_timer(const struct ctx *c, const struct timespec *now);

#endif /* NDP_H */
