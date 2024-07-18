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
 * @ts:		Activity timestamp
 * @s:		Socket fd (or -1) for each side of the flow
 */
struct udp_flow {
	/* Must be first element */
	struct flow_common f;

	time_t ts;
	int s[SIDES];
};

bool udp_flow_timer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now);

#endif /* UDP_FLOW_H */
