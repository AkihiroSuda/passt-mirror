/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now);
int udp_tap_handler(struct ctx *c, int af, const void *addr,
		    const struct pool *p, const struct timespec *now);
int udp_sock_init(const struct ctx *c, int ns, sa_family_t af,
		  const void *addr, const char *ifname, in_port_t port);
int udp_init(struct ctx *c);
void udp_timer(struct ctx *c, const struct timespec *ts);
void udp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s,
		       const struct in_addr *ip_da);

/**
 * union udp_epoll_ref - epoll reference portion for TCP connections
 * @bound:		Set if this file descriptor is a bound socket
 * @splice:		Set if descriptor packets to be "spliced"
 * @orig:		Set if a spliced socket which can originate "connections"
 * @ns:			Set if this is a socket in the pasta network namespace
 * @v6:			Set for IPv6 sockets or connections
 * @port:		Source port for connected sockets, bound port otherwise
 * @u32:		Opaque u32 value of reference
 */
union udp_epoll_ref {
	struct {
		bool		splice:1,
				orig:1,
				ns:1,
				v6:1;
		uint32_t	port:16;
	} udp;
	uint32_t u32;
};


/**
 * udp_port_fwd - UDP specific port forwarding configuration
 * @f:		Generic forwarding configuration
 * @rdelta:	Reversed delta map to translate source ports on return packets
 */
struct udp_port_fwd {
	struct port_fwd f;
	in_port_t rdelta[NUM_PORTS];
};

/**
 * struct udp_ctx - Execution context for UDP
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	struct udp_port_fwd fwd_in;
	struct udp_port_fwd fwd_out;
	struct timespec timer_run;
};

#endif /* UDP_H */
