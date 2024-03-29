/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef PORT_FWD_H
#define PORT_FWD_H

/* Number of ports for both TCP and UDP */
#define	NUM_PORTS	(1U << 16)

enum port_fwd_mode {
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/**
 * port_fwd - Describes port forwarding for one protocol and direction
 * @mode:	Overall forwarding mode (all, none, auto, specific ports)
 * @scan4:	/proc/net fd to scan for IPv4 ports when in AUTO mode
 * @scan6:	/proc/net fd to scan for IPv6 ports when in AUTO mode
 * @map:	Bitmap describing which ports are forwarded
 * @delta:	Offset between the original destination and mapped port number
 */
struct port_fwd {
	enum port_fwd_mode mode;
	int scan4;
	int scan6;
	uint8_t map[PORT_BITMAP_SIZE];
	in_port_t delta[NUM_PORTS];
};

void port_fwd_scan_tcp(struct port_fwd *fwd, const struct port_fwd *rev);
void port_fwd_scan_udp(struct port_fwd *fwd, const struct port_fwd *rev,
		       const struct port_fwd *tcp_fwd,
		       const struct port_fwd *tcp_rev);
void port_fwd_init(struct ctx *c);

#endif /* PORT_FWD_H */
