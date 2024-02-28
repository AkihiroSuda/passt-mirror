// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * fwd.c - Port forwarding helpers
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>

#include "util.h"
#include "fwd.h"
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

	if (fd < 0)
		return;

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
 * fwd_scan_ports_tcp() - Scan /proc to update TCP forwarding map
 * @fwd:	Forwarding information to update
 * @rev:	Forwarding information for the reverse direction
 */
void fwd_scan_ports_tcp(struct fwd_ports *fwd, const struct fwd_ports *rev)
{
	memset(fwd->map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(fwd->scan4, TCP_LISTEN, fwd->map, rev->map);
	procfs_scan_listen(fwd->scan6, TCP_LISTEN, fwd->map, rev->map);
}

/**
 * fwd_scan_ports_udp() - Scan /proc to update UDP forwarding map
 * @fwd:	Forwarding information to update
 * @rev:	Forwarding information for the reverse direction
 * @tcp_fwd:	Corresponding TCP forwarding information
 * @tcp_rev:	TCP forwarding information for the reverse direction
 */
void fwd_scan_ports_udp(struct fwd_ports *fwd, const struct fwd_ports *rev,
			const struct fwd_ports *tcp_fwd,
			const struct fwd_ports *tcp_rev)
{
	uint8_t exclude[PORT_BITMAP_SIZE];

	bitmap_or(exclude, PORT_BITMAP_SIZE, rev->map, tcp_rev->map);

	memset(fwd->map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(fwd->scan4, UDP_LISTEN, fwd->map, exclude);
	procfs_scan_listen(fwd->scan6, UDP_LISTEN, fwd->map, exclude);

	/* Also forward UDP ports with the same numbers as bound TCP ports.
	 * This is useful for a handful of protocols (e.g. iperf3) where a TCP
	 * control port is used to set up transfers on a corresponding UDP
	 * port.
	 *
	 * This means we need to skip numbers of TCP ports bound on the other
	 * side, too. Otherwise, we would detect corresponding UDP ports as
	 * bound and try to forward them from the opposite side, but it's
	 * already us handling them.
	 */
	procfs_scan_listen(tcp_fwd->scan4, TCP_LISTEN, fwd->map, exclude);
	procfs_scan_listen(tcp_fwd->scan6, TCP_LISTEN, fwd->map, exclude);
}

/**
 * fwd_scan_ports_init() - Initial setup for automatic port forwarding
 * @c:		Execution context
 */
void fwd_scan_ports_init(struct ctx *c)
{
	const int flags = O_RDONLY | O_CLOEXEC;

	c->tcp.fwd_in.scan4 = c->tcp.fwd_in.scan6 = -1;
	c->tcp.fwd_out.scan4 = c->tcp.fwd_out.scan6 = -1;
	c->udp.fwd_in.f.scan4 = c->udp.fwd_in.f.scan6 = -1;
	c->udp.fwd_out.f.scan4 = c->udp.fwd_out.f.scan6 = -1;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		c->tcp.fwd_in.scan4 = open_in_ns(c, "/proc/net/tcp", flags);
		c->tcp.fwd_in.scan6 = open_in_ns(c, "/proc/net/tcp6", flags);
		fwd_scan_ports_tcp(&c->tcp.fwd_in, &c->tcp.fwd_out);
	}
	if (c->udp.fwd_in.f.mode == FWD_AUTO) {
		c->udp.fwd_in.f.scan4 = open_in_ns(c, "/proc/net/udp", flags);
		c->udp.fwd_in.f.scan6 = open_in_ns(c, "/proc/net/udp6", flags);
		fwd_scan_ports_udp(&c->udp.fwd_in.f, &c->udp.fwd_out.f,
				   &c->tcp.fwd_in, &c->tcp.fwd_out);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO) {
		c->tcp.fwd_out.scan4 = open("/proc/net/tcp", flags);
		c->tcp.fwd_out.scan6 = open("/proc/net/tcp6", flags);
		fwd_scan_ports_tcp(&c->tcp.fwd_out, &c->tcp.fwd_in);
	}
	if (c->udp.fwd_out.f.mode == FWD_AUTO) {
		c->udp.fwd_out.f.scan4 = open("/proc/net/udp", flags);
		c->udp.fwd_out.f.scan6 = open("/proc/net/udp6", flags);
		fwd_scan_ports_udp(&c->udp.fwd_out.f, &c->udp.fwd_in.f,
				   &c->tcp.fwd_out, &c->tcp.fwd_in);
	}
}
