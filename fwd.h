/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef FWD_H
#define FWD_H

struct flowside;

/* Number of ports for both TCP and UDP */
#define	NUM_PORTS	(1U << 16)

void fwd_probe_ephemeral(void);
bool fwd_port_is_ephemeral(in_port_t port);

enum fwd_ports_mode {
	FWD_UNSET = 0,
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/**
 * fwd_ports - Describes port forwarding for one protocol and direction
 * @mode:	Overall forwarding mode (all, none, auto, specific ports)
 * @scan4:	/proc/net fd to scan for IPv4 ports when in AUTO mode
 * @scan6:	/proc/net fd to scan for IPv6 ports when in AUTO mode
 * @map:	Bitmap describing which ports are forwarded
 * @delta:	Offset between the original destination and mapped port number
 */
struct fwd_ports {
	enum fwd_ports_mode mode;
	int scan4;
	int scan6;
	uint8_t map[PORT_BITMAP_SIZE];
	in_port_t delta[NUM_PORTS];
};

void fwd_scan_ports_tcp(struct fwd_ports *fwd, const struct fwd_ports *rev);
void fwd_scan_ports_udp(struct fwd_ports *fwd, const struct fwd_ports *rev,
			const struct fwd_ports *tcp_fwd,
			const struct fwd_ports *tcp_rev);
void fwd_scan_ports_init(struct ctx *c);

uint8_t fwd_nat_from_tap(const struct ctx *c, uint8_t proto,
			 const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_splice(const struct ctx *c, uint8_t proto,
			    const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_host(const struct ctx *c, uint8_t proto,
			  const struct flowside *ini, struct flowside *tgt);

#endif /* FWD_H */
