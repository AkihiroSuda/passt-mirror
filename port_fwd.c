// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * port_fwd.c - Port forwarding helpers
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>

#include "util.h"
#include "port_fwd.h"
#include "passt.h"
#include "lineread.h"

/* See enum in kernel's include/net/tcp_states.h */
#define UDP_LISTEN	0x07
#define TCP_LISTEN	0x0a

/**
 * procfs_scan_listen() - Set bits for listening TCP or UDP sockets from procfs
 * @fd:		fd for relevant /proc/net file
 * @lstate:	Code for listening state to scan for
 * @map:	Bitmap where numbers of ports in listening state will be set
 * @exclude:	Bitmap of ports to exclude from setting (and clear)
 *
 * #syscalls:pasta lseek
 * #syscalls:pasta ppc64le:_llseek ppc64:_llseek armv6l:_llseek armv7l:_llseek
 */
static void procfs_scan_listen(int fd, unsigned int lstate,
			       uint8_t *map, const uint8_t *exclude)
{
	struct lineread lr;
	unsigned long port;
	unsigned int state;
	char *line;

	if (lseek(fd, 0, SEEK_SET)) {
		warn("lseek() failed on /proc/net file: %s", strerror(errno));
		return;
	}

	lineread_init(&lr, fd);
	lineread_get(&lr, &line); /* throw away header */
	while (lineread_get(&lr, &line) > 0) {
		/* NOLINTNEXTLINE(cert-err34-c): != 2 if conversion fails */
		if (sscanf(line, "%*u: %*x:%lx %*x:%*x %x", &port, &state) != 2)
			continue;

		if (state != lstate)
			continue;

		if (bitmap_isset(exclude, port))
			bitmap_clear(map, port);
		else
			bitmap_set(map, port);
	}
}

/**
 * get_bound_ports_tcp() - Get maps of TCP ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 */
void get_bound_ports_tcp(struct ctx *c, int ns)
{
	uint8_t *map, *excl;

	if (ns) {
		map = c->tcp.fwd_in.map;
		excl = c->tcp.fwd_out.map;
	} else {
		map = c->tcp.fwd_out.map;
		excl = c->tcp.fwd_in.map;
	}

	memset(map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(c->proc_net_tcp[V4][ns], TCP_LISTEN, map, excl);
	procfs_scan_listen(c->proc_net_tcp[V6][ns], TCP_LISTEN, map, excl);
}

/**
 * get_bound_ports_udp() - Get maps of UDP ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 */
void get_bound_ports_udp(struct ctx *c, int ns)
{
	uint8_t *map, *excl;

	if (ns) {
		map = c->udp.fwd_in.f.map;
		excl = c->udp.fwd_out.f.map;
	} else {
		map = c->udp.fwd_out.f.map;
		excl = c->udp.fwd_in.f.map;
	}

	memset(map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(c->proc_net_udp[V4][ns], UDP_LISTEN, map, excl);
	procfs_scan_listen(c->proc_net_udp[V6][ns], UDP_LISTEN, map, excl);

	/* Also forward UDP ports with the same numbers as bound TCP ports.
	 * This is useful for a handful of protocols (e.g. iperf3) where a TCP
	 * control port is used to set up transfers on a corresponding UDP
	 * port.
	 */
	procfs_scan_listen(c->proc_net_tcp[V4][ns], TCP_LISTEN, map, excl);
	procfs_scan_listen(c->proc_net_tcp[V6][ns], TCP_LISTEN, map, excl);
}

/**
 * port_fwd_init() - Initial setup for port forwarding
 * @c:		Execution context
 */
void port_fwd_init(struct ctx *c)
{
	const int flags = O_RDONLY | O_CLOEXEC;

	c->proc_net_tcp[V4][0] = c->proc_net_tcp[V4][1] = -1;
	c->proc_net_tcp[V6][0] = c->proc_net_tcp[V6][1] = -1;
	c->proc_net_udp[V4][0] = c->proc_net_udp[V4][1] = -1;
	c->proc_net_udp[V6][0] = c->proc_net_udp[V6][1] = -1;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		c->proc_net_tcp[V4][1] = open_in_ns(c, "/proc/net/tcp", flags);
		c->proc_net_tcp[V6][1] = open_in_ns(c, "/proc/net/tcp6", flags);
		get_bound_ports_tcp(c, 1);
	}
	if (c->udp.fwd_in.f.mode == FWD_AUTO) {
		c->proc_net_udp[V4][1] = open_in_ns(c, "/proc/net/udp", flags);
		c->proc_net_udp[V6][1] = open_in_ns(c, "/proc/net/udp6", flags);
		get_bound_ports_udp(c, 1);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO) {
		c->proc_net_tcp[V4][0] = open("/proc/net/tcp", flags);
		c->proc_net_tcp[V6][0] = open("/proc/net/tcp6", flags);
		get_bound_ports_tcp(c, 0);
	}
	if (c->udp.fwd_out.f.mode == FWD_AUTO) {
		c->proc_net_udp[V4][0] = open("/proc/net/udp", flags);
		c->proc_net_udp[V6][0] = open("/proc/net/udp6", flags);
		get_bound_ports_udp(c, 0);
	}
}
