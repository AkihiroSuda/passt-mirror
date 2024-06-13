/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_portmap_clear(void);
void udp_buf_sock_handler(const struct ctx *c, union epoll_ref ref, uint32_t events,
		      const struct timespec *now);
int udp_tap_handler(struct ctx *c, uint8_t pif, sa_family_t af,
		    const void *saddr, const void *daddr,
		    const struct pool *p, int idx, const struct timespec *now);
int udp_sock_init(const struct ctx *c, int ns, sa_family_t af,
		  const void *addr, const char *ifname, in_port_t port);
int udp_init(struct ctx *c);
void udp_timer(struct ctx *c, const struct timespec *now);
void udp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s);

/**
 * union udp_epoll_ref - epoll reference portion for TCP connections
 * @port:		Source port for connected sockets, bound port otherwise
 * @pif:		pif for this socket
 * @bound:		Set if this file descriptor is a bound socket
 * @splice:		Set if descriptor packets to be "spliced"
 * @orig:		Set if a spliced socket which can originate "connections"
 * @v6:			Set for IPv6 sockets or connections
 * @u32:		Opaque u32 value of reference
 */
union udp_epoll_ref {
	struct {
		in_port_t	port;
		uint8_t		pif;
		bool		splice:1,
				orig:1,
				v6:1;
	};
	uint32_t u32;
};


/**
 * udp_fwd_ports - UDP specific port forwarding configuration
 * @f:		Generic forwarding configuration
 * @rdelta:	Reversed delta map to translate source ports on return packets
 */
struct udp_fwd_ports {
	struct fwd_ports f;
	in_port_t rdelta[NUM_PORTS];
};

/**
 * struct udp_ctx - Execution context for UDP
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	struct udp_fwd_ports fwd_in;
	struct udp_fwd_ports fwd_out;
	struct timespec timer_run;
};

#endif /* UDP_H */
