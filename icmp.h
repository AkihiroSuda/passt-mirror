/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef ICMP_H
#define ICMP_H

#define ICMP_TIMER_INTERVAL		1000 /* ms */

struct ctx;

void icmp_sock_handler(const struct ctx *c, union epoll_ref ref);
void icmpv6_sock_handler(const struct ctx *c, union epoll_ref ref);
int icmp_tap_handler(const struct ctx *c, uint8_t pif, int af,
		     const void *saddr, const void *daddr,
		     const struct pool *p, const struct timespec *now);
void icmp_timer(const struct ctx *c, const struct timespec *ts);
void icmp_init(void);

/**
 * union icmp_epoll_ref - epoll reference portion for ICMP tracking
 * @v6:			Set for IPv6 sockets or connections
 * @u32:		Opaque u32 value of reference
 * @id:			Associated echo identifier, needed if bind() fails
 */
union icmp_epoll_ref {
	uint16_t id;
	uint32_t u32;
};

/**
 * struct icmp_ctx - Execution context for ICMP routines
 * @timer_run:		Timestamp of most recent timer run
 */
struct icmp_ctx {
	struct timespec timer_run;
};

#endif /* ICMP_H */
