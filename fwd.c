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
#include "ip.h"
#include "fwd.h"
#include "passt.h"
#include "lineread.h"
#include "flow_table.h"

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
 * #syscalls:pasta ppc64le:_llseek ppc64:_llseek arm:_llseek
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
		warn_perror("lseek() failed on /proc/net file");
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
	c->udp.fwd_in.scan4 = c->udp.fwd_in.scan6 = -1;
	c->udp.fwd_out.scan4 = c->udp.fwd_out.scan6 = -1;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		c->tcp.fwd_in.scan4 = open_in_ns(c, "/proc/net/tcp", flags);
		c->tcp.fwd_in.scan6 = open_in_ns(c, "/proc/net/tcp6", flags);
		fwd_scan_ports_tcp(&c->tcp.fwd_in, &c->tcp.fwd_out);
	}
	if (c->udp.fwd_in.mode == FWD_AUTO) {
		c->udp.fwd_in.scan4 = open_in_ns(c, "/proc/net/udp", flags);
		c->udp.fwd_in.scan6 = open_in_ns(c, "/proc/net/udp6", flags);
		fwd_scan_ports_udp(&c->udp.fwd_in, &c->udp.fwd_out,
				   &c->tcp.fwd_in, &c->tcp.fwd_out);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO) {
		c->tcp.fwd_out.scan4 = open("/proc/net/tcp", flags);
		c->tcp.fwd_out.scan6 = open("/proc/net/tcp6", flags);
		fwd_scan_ports_tcp(&c->tcp.fwd_out, &c->tcp.fwd_in);
	}
	if (c->udp.fwd_out.mode == FWD_AUTO) {
		c->udp.fwd_out.scan4 = open("/proc/net/udp", flags);
		c->udp.fwd_out.scan6 = open("/proc/net/udp6", flags);
		fwd_scan_ports_udp(&c->udp.fwd_out, &c->udp.fwd_in,
				   &c->tcp.fwd_out, &c->tcp.fwd_in);
	}
}

/**
 * is_dns_flow() - Determine if flow appears to be a DNS request
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 *
 * Return: true if the flow appears to be directed at a dns server, that is a
 *         TCP or UDP flow to port 53 (domain) or port 853 (domain-s)
 */
static bool is_dns_flow(uint8_t proto, const struct flowside *ini)
{
	return ((proto == IPPROTO_UDP) || (proto == IPPROTO_TCP)) &&
		((ini->oport == 53) || (ini->oport == 853));
}

/**
 * fwd_nat_from_tap() - Determine to forward a flow from the tap interface
 * @c:		Execution context
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_tap(const struct ctx *c, uint8_t proto,
			 const struct flowside *ini, struct flowside *tgt)
{
	if (is_dns_flow(proto, ini) &&
	    inany_equals4(&ini->oaddr, &c->ip4.dns_match))
		tgt->eaddr = inany_from_v4(c->ip4.dns_host);
	else if (is_dns_flow(proto, ini) &&
		   inany_equals6(&ini->oaddr, &c->ip6.dns_match))
		tgt->eaddr.a6 = c->ip6.dns_host;
	else if (!c->no_map_gw && inany_equals4(&ini->oaddr, &c->ip4.gw))
		tgt->eaddr = inany_loopback4;
	else if (!c->no_map_gw && inany_equals6(&ini->oaddr, &c->ip6.gw))
		tgt->eaddr = inany_loopback6;
	else
		tgt->eaddr = ini->oaddr;

	tgt->eport = ini->oport;

	/* The relevant addr_out controls the host side source address.  This
	 * may be unspecified, which allows the kernel to pick an address.
	 */
	if (inany_v4(&tgt->eaddr))
		tgt->oaddr = inany_from_v4(c->ip4.addr_out);
	else
		tgt->oaddr.a6 = c->ip6.addr_out;

	/* Let the kernel pick a host side source port */
	tgt->oport = 0;
	if (proto == IPPROTO_UDP) {
		/* But for UDP we preserve the source port */
		tgt->oport = ini->eport;
	}

	return PIF_HOST;
}

/**
 * fwd_nat_from_splice() - Determine to forward a flow from the splice interface
 * @c:		Execution context
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_splice(const struct ctx *c, uint8_t proto,
			    const struct flowside *ini, struct flowside *tgt)
{
	if (!inany_is_loopback(&ini->eaddr) ||
	    (!inany_is_loopback(&ini->oaddr) && !inany_is_unspecified(&ini->oaddr))) {
		char estr[INANY_ADDRSTRLEN], fstr[INANY_ADDRSTRLEN];

		debug("Non loopback address on %s: [%s]:%hu -> [%s]:%hu",
		      pif_name(PIF_SPLICE),
		      inany_ntop(&ini->eaddr, estr, sizeof(estr)), ini->eport,
		      inany_ntop(&ini->oaddr, fstr, sizeof(fstr)), ini->oport);
		return PIF_NONE;
	}

	if (inany_v4(&ini->eaddr))
		tgt->eaddr = inany_loopback4;
	else
		tgt->eaddr = inany_loopback6;

	/* Preserve the specific loopback adddress used, but let the kernel pick
	 * a source port on the target side
	 */
	tgt->oaddr = ini->eaddr;
	tgt->oport = 0;

	tgt->eport = ini->oport;
	if (proto == IPPROTO_TCP)
		tgt->eport += c->tcp.fwd_out.delta[tgt->eport];
	else if (proto == IPPROTO_UDP)
		tgt->eport += c->udp.fwd_out.delta[tgt->eport];

	/* Let the kernel pick a host side source port */
	tgt->oport = 0;
	if (proto == IPPROTO_UDP)
		/* But for UDP preserve the source port */
		tgt->oport = ini->eport;

	return PIF_HOST;
}

/**
 * fwd_nat_from_host() - Determine to forward a flow from the host interface
 * @c:		Execution context
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_host(const struct ctx *c, uint8_t proto,
			  const struct flowside *ini, struct flowside *tgt)
{
	/* Common for spliced and non-spliced cases */
	tgt->eport = ini->oport;
	if (proto == IPPROTO_TCP)
		tgt->eport += c->tcp.fwd_in.delta[tgt->eport];
	else if (proto == IPPROTO_UDP)
		tgt->eport += c->udp.fwd_in.delta[tgt->eport];

	if (c->mode == MODE_PASTA && inany_is_loopback(&ini->eaddr) &&
	    (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
		/* spliceable */

		/* Preserve the specific loopback adddress used, but let the
		 * kernel pick a source port on the target side
		 */
		tgt->oaddr = ini->eaddr;
		tgt->oport = 0;
		if (proto == IPPROTO_UDP)
			/* But for UDP preserve the source port */
			tgt->oport = ini->eport;

		if (inany_v4(&ini->eaddr))
			tgt->eaddr = inany_loopback4;
		else
			tgt->eaddr = inany_loopback6;

		return PIF_SPLICE;
	}

	tgt->oaddr = ini->eaddr;
	tgt->oport = ini->eport;

	if (inany_is_loopback4(&tgt->oaddr) ||
	    inany_is_unspecified4(&tgt->oaddr) ||
	    inany_equals4(&tgt->oaddr, &c->ip4.addr_seen)) {
		tgt->oaddr = inany_from_v4(c->ip4.gw);
	} else if (inany_is_loopback6(&tgt->oaddr) ||
		   inany_equals6(&tgt->oaddr, &c->ip6.addr_seen) ||
		   inany_equals6(&tgt->oaddr, &c->ip6.addr)) {
		if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
			tgt->oaddr.a6 = c->ip6.gw;
		else
			tgt->oaddr.a6 = c->ip6.our_tap_ll;
	}

	if (inany_v4(&tgt->oaddr)) {
		tgt->eaddr = inany_from_v4(c->ip4.addr_seen);
	} else {
		if (inany_is_linklocal6(&tgt->oaddr))
			tgt->eaddr.a6 = c->ip6.addr_ll_seen;
		else
			tgt->eaddr.a6 = c->ip6.addr_seen;
	}

	return PIF_TAP;
}
