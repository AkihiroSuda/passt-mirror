/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * UDP flow tracking data structures
 */
#ifndef UDP_FLOW_H
#define UDP_FLOW_H

/**
 * struct udp - Descriptor for a flow of UDP packets
 * @f:		Generic flow information
 * @closed:	Flow is already closed
 * @ts:		Activity timestamp
 * @s:		Socket fd (or -1) for each side of the flow
 */
struct udp_flow {
	/* Must be first element */
	struct flow_common f;

	bool closed :1;
	time_t ts;
	int s[SIDES];
};

struct udp_flow *udp_at_sidx(flow_sidx_t sidx);
flow_sidx_t udp_flow_from_sock(const struct ctx *c, union epoll_ref ref,
			       const union sockaddr_inany *s_in,
			       const struct timespec *now);
flow_sidx_t udp_flow_from_tap(const struct ctx *c,
			      uint8_t pif, sa_family_t af,
			      const void *saddr, const void *daddr,
			      in_port_t srcport, in_port_t dstport,
			      const struct timespec *now);
void udp_flow_close(const struct ctx *c, struct udp_flow *uflow);
bool udp_flow_defer(const struct udp_flow *uflow);
bool udp_flow_timer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now);

#endif /* UDP_FLOW_H */
