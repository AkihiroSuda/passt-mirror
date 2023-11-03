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
 * @fd:		Pointer to fd for relevant /proc/net file
 * @path:	Path to /proc/net file to open (if fd is -1)
 * @lstate:	Code for listening state to scan for
 * @map:	Bitmap where numbers of ports in listening state will be set
 * @exclude:	Bitmap of ports to exclude from setting (and clear)
 *
 * #syscalls:pasta lseek
 * #syscalls:pasta ppc64le:_llseek ppc64:_llseek armv6l:_llseek armv7l:_llseek
 */
static void procfs_scan_listen(int *fd, const char *path, unsigned int lstate,
			       uint8_t *map, const uint8_t *exclude)
{
	struct lineread lr;
	unsigned long port;
	unsigned int state;
	char *line;

	if (*fd != -1) {
		if (lseek(*fd, 0, SEEK_SET)) {
			warn("lseek() failed on %s: %s", path, strerror(errno));
			return;
		}
	} else if ((*fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
		return;
	}

	lineread_init(&lr, *fd);
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
 * get_bound_ports() - Get maps of ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
void get_bound_ports(struct ctx *c, int ns, uint8_t proto)
{
	uint8_t *udp_map, *udp_excl, *tcp_map, *tcp_excl;

	if (ns) {
		udp_map = c->udp.fwd_in.f.map;
		udp_excl = c->udp.fwd_out.f.map;
		tcp_map = c->tcp.fwd_in.map;
		tcp_excl = c->tcp.fwd_out.map;
	} else {
		udp_map = c->udp.fwd_out.f.map;
		udp_excl = c->udp.fwd_in.f.map;
		tcp_map = c->tcp.fwd_out.map;
		tcp_excl = c->tcp.fwd_in.map;
	}

	if (proto == IPPROTO_UDP) {
		memset(udp_map, 0, PORT_BITMAP_SIZE);
		procfs_scan_listen(&c->proc_net_udp[V4][ns], "/proc/net/udp",
				   UDP_LISTEN, udp_map, udp_excl);
		procfs_scan_listen(&c->proc_net_udp[V6][ns], "/proc/net/udp6",
				   UDP_LISTEN, udp_map, udp_excl);

		procfs_scan_listen(&c->proc_net_tcp[V4][ns], "/proc/net/tcp",
				   TCP_LISTEN, udp_map, udp_excl);
		procfs_scan_listen(&c->proc_net_tcp[V6][ns], "/proc/net/tcp6",
				   TCP_LISTEN, udp_map, udp_excl);
	} else if (proto == IPPROTO_TCP) {
		memset(tcp_map, 0, PORT_BITMAP_SIZE);
		procfs_scan_listen(&c->proc_net_tcp[V4][ns], "/proc/net/tcp",
				   TCP_LISTEN, tcp_map, tcp_excl);
		procfs_scan_listen(&c->proc_net_tcp[V6][ns], "/proc/net/tcp6",
				   TCP_LISTEN, tcp_map, tcp_excl);
	}
}

/**
 * struct get_bound_ports_ns_arg - Arguments for get_bound_ports_ns()
 * @c:		Execution context
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
struct get_bound_ports_ns_arg {
	struct ctx *c;
	uint8_t proto;
};

/**
 * get_bound_ports_ns() - Get maps of ports in namespace with bound sockets
 * @arg:	See struct get_bound_ports_ns_arg
 *
 * Return: 0
 */
static int get_bound_ports_ns(void *arg)
{
	struct get_bound_ports_ns_arg *a = (struct get_bound_ports_ns_arg *)arg;
	struct ctx *c = a->c;

	if (!c->pasta_netns_fd)
		return 0;

	ns_enter(c);
	get_bound_ports(c, 1, a->proto);

	return 0;
}

/**
 * port_fwd_init() - Initial setup for port forwarding
 * @c:		Execution context
 */
void port_fwd_init(struct ctx *c)
{
	struct get_bound_ports_ns_arg ns_ports_arg = { .c = c };

	c->proc_net_tcp[V4][0] = c->proc_net_tcp[V4][1] = -1;
	c->proc_net_tcp[V6][0] = c->proc_net_tcp[V6][1] = -1;
	c->proc_net_udp[V4][0] = c->proc_net_udp[V4][1] = -1;
	c->proc_net_udp[V6][0] = c->proc_net_udp[V6][1] = -1;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		ns_ports_arg.proto = IPPROTO_TCP;
		NS_CALL(get_bound_ports_ns, &ns_ports_arg);
	}
	if (c->udp.fwd_in.f.mode == FWD_AUTO) {
		ns_ports_arg.proto = IPPROTO_UDP;
		NS_CALL(get_bound_ports_ns, &ns_ports_arg);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO)
		get_bound_ports(c, 0, IPPROTO_TCP);
	if (c->udp.fwd_out.f.mode == FWD_AUTO)
		get_bound_ports(c, 0, IPPROTO_UDP);
}
