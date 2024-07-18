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
 */
struct udp_flow {
	/* Must be first element */
	struct flow_common f;

	time_t ts;
};

bool udp_flow_timer(const struct ctx *c, const struct udp_flow *uflow,
		    const struct timespec *now);

#endif /* UDP_FLOW_H */
