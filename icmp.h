/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef ICMP_H
#define ICMP_H

#define ICMP_TIMER_INTERVAL		1000 /* ms */

struct ctx;

void icmp_sock_handler(const struct ctx *c, union epoll_ref ref,
		       uint32_t events, const struct timespec *now);
int icmp_tap_handler(const struct ctx *c, int af, const void *addr,
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
	struct {
		uint32_t	v6:1,
				id:16;
	} icmp;
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
