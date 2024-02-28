// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * icmp.c - ICMP/ICMPv6 echo proxy
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include <linux/icmpv6.h>

#include "packet.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "siphash.h"
#include "inany.h"
#include "icmp.h"

#define ICMP_ECHO_TIMEOUT	60 /* s, timeout for ICMP socket activity */
#define ICMP_NUM_IDS		(1U << 16)

/**
 * struct icmp_id_sock - Tracking information for single ICMP echo identifier
 * @sock:	Bound socket for identifier
 * @seq:	Last sequence number sent to tap, host order, -1: not sent yet
 * @ts:		Last associated activity from tap, seconds
 */
struct icmp_id_sock {
	int sock;
	int seq;
	time_t ts;
};

/* Indexed by ICMP echo identifier */
static struct icmp_id_sock icmp_id_map[IP_VERSIONS][ICMP_NUM_IDS];

/**
 * icmp_sock_handler() - Handle new data from ICMP or ICMPv6 socket
 * @c:		Execution context
 * @af:		Address family (AF_INET or AF_INET6)
 * @ref:	epoll reference
 */
void icmp_sock_handler(const struct ctx *c, sa_family_t af, union epoll_ref ref)
{
	struct icmp_id_sock *const id_sock = af == AF_INET
		? &icmp_id_map[V4][ref.icmp.id] : &icmp_id_map[V6][ref.icmp.id];
	const char *const pname = af == AF_INET ? "ICMP" : "ICMPv6";
	union sockaddr_inany sr;
	socklen_t sl = sizeof(sr);
	char buf[USHRT_MAX];
	uint16_t seq;
	ssize_t n;

	if (c->no_icmp)
		return;

	n = recvfrom(ref.fd, buf, sizeof(buf), 0, &sr.sa, &sl);
	if (n < 0) {
		warn("%s: recvfrom() error on ping socket: %s",
		     pname, strerror(errno));
		return;
	}
	if (sr.sa_family != af)
		goto unexpected;

	if (af == AF_INET) {
		struct icmphdr *ih4 = (struct icmphdr *)buf;

		if ((size_t)n < sizeof(*ih4) || ih4->type != ICMP_ECHOREPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih4->un.echo.id = htons(ref.icmp.id);
		seq = ntohs(ih4->un.echo.sequence);
	} else if (af == AF_INET6) {
		struct icmp6hdr *ih6 = (struct icmp6hdr *)buf;

		if ((size_t)n < sizeof(*ih6) ||
		    ih6->icmp6_type != ICMPV6_ECHO_REPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih6->icmp6_identifier = htons(ref.icmp.id);
		seq = ntohs(ih6->icmp6_sequence);
	} else {
		ASSERT(0);
	}

	/* In PASTA mode, we'll get any reply we send, discard them. */
	if (c->mode == MODE_PASTA) {
		if (id_sock->seq == seq)
			return;

		id_sock->seq = seq;
	}

	debug("%s: echo reply to tap, ID: %"PRIu16", seq: %"PRIu16, pname,
	      ref.icmp.id, seq);
	if (af == AF_INET)
		tap_icmp4_send(c, sr.sa4.sin_addr, tap_ip4_daddr(c), buf, n);
	else if (af == AF_INET6)
		tap_icmp6_send(c, &sr.sa6.sin6_addr,
			       tap_ip6_daddr(c, &sr.sa6.sin6_addr), buf, n);
	return;

unexpected:
	warn("%s: Unexpected packet on ping socket", pname);
}

/**
 * icmp_ping_close() - Close and clean up a ping socket
 * @c:		Execution context
 * @id_sock:	Socket number and other info
 */
static void icmp_ping_close(const struct ctx *c, struct icmp_id_sock *id_sock)
{
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, id_sock->sock, NULL);
	close(id_sock->sock);
	id_sock->sock = -1;
	id_sock->seq = -1;
}

/**
 * icmp_ping_new() - Prepare a new ping socket for a new id
 * @c:		Execution context
 * @id_sock:	Socket fd and other information
 * @af:		Address family, AF_INET or AF_INET6
 * @id:		ICMP id for the new socket
 *
 * Return: Newly opened ping socket fd, or -1 on failure
 */
static int icmp_ping_new(const struct ctx *c, struct icmp_id_sock *id_sock,
			 sa_family_t af, uint16_t id)
{
	uint8_t proto = af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
	const char *const pname = af == AF_INET ? "ICMP" : "ICMPv6";
	union icmp_epoll_ref iref = { .id = id };
	const void *bind_addr;
	const char *bind_if;
	int s;

	if (af == AF_INET) {
		bind_addr = &c->ip4.addr_out;
		bind_if = c->ip4.ifname_out;
	} else {
		bind_addr = &c->ip6.addr_out;
		bind_if = c->ip6.ifname_out;
	}

	s = sock_l4(c, af, proto, bind_addr, bind_if, 0, iref.u32);

	if (s < 0) {
		warn("Cannot open \"ping\" socket. You might need to:");
		warn("  sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
		warn("...echo requests/replies will fail.");
		goto cancel;
	}

	if (s > FD_REF_MAX)
		goto cancel;

	id_sock->sock = s;

	debug("%s: new socket %i for echo ID %"PRIu16, pname, s, id);

	return s;

cancel:
	if (s >= 0)
		close(s);
	return -1;
}

/**
 * icmp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @p:		Packet pool, single packet with ICMP/ICMPv6 header
 * @now:	Current timestamp
 *
 * Return: count of consumed packets (always 1, even if malformed)
 */
int icmp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		     const void *saddr, const void *daddr,
		     const struct pool *p, const struct timespec *now)
{
	const char *const pname = af == AF_INET ? "ICMP" : "ICMPv6";
	union sockaddr_inany sa = { .sa_family = af };
	const socklen_t sl = af == AF_INET ? sizeof(sa.sa4) : sizeof(sa.sa6);
	struct icmp_id_sock *id_sock;
	uint16_t id, seq;
	size_t plen;
	void *pkt;
	int s;

	(void)saddr;
	(void)pif;

	if (af == AF_INET) {
		const struct icmphdr *ih;

		if (!(pkt = packet_get(p, 0, 0, sizeof(*ih), &plen)))
			return 1;

		ih =  (struct icmphdr *)pkt;
		plen += sizeof(*ih);

		if (ih->type != ICMP_ECHO)
			return 1;

		id = ntohs(ih->un.echo.id);
		id_sock = &icmp_id_map[V4][id];
		seq = ntohs(ih->un.echo.sequence);
		sa.sa4.sin_addr = *(struct in_addr *)daddr;
	} else if (af == AF_INET6) {
		const struct icmp6hdr *ih;

		if (!(pkt = packet_get(p, 0, 0, sizeof(*ih), &plen)))
			return 1;

		ih = (struct icmp6hdr *)pkt;
		plen += sizeof(*ih);

		if (ih->icmp6_type != ICMPV6_ECHO_REQUEST)
			return 1;

		id = ntohs(ih->icmp6_identifier);
		id_sock = &icmp_id_map[V6][id];
		seq = ntohs(ih->icmp6_sequence);
		sa.sa6.sin6_addr = *(struct in6_addr *)daddr;
		sa.sa6.sin6_scope_id = c->ifi6;
	} else {
		ASSERT(0);
	}

	if ((s = id_sock->sock) < 0)
		if ((s = icmp_ping_new(c, id_sock, af, id)) < 0)
			return 1;

	id_sock->ts = now->tv_sec;

	if (sendto(s, pkt, plen, MSG_NOSIGNAL, &sa.sa, sl) < 0) {
		debug("%s: failed to relay request to socket: %s",
		      pname, strerror(errno));
	} else {
		debug("%s: echo request to socket, ID: %"PRIu16", seq: %"PRIu16,
		      pname, id, seq);
	}

	return 1;
}

/**
 * icmp_timer_one() - Handler for timed events related to a given identifier
 * @c:		Execution context
 * @id_sock:	Socket fd and activity timestamp
 * @now:	Current timestamp
 */
static void icmp_timer_one(const struct ctx *c, struct icmp_id_sock *id_sock,
			   const struct timespec *now)
{
	if (id_sock->sock < 0 || now->tv_sec - id_sock->ts <= ICMP_ECHO_TIMEOUT)
		return;

	icmp_ping_close(c, id_sock);
}

/**
 * icmp_timer() - Scan activity bitmap for identifiers with timed events
 * @c:		Execution context
 * @now:	Current timestamp
 */
void icmp_timer(const struct ctx *c, const struct timespec *now)
{
	unsigned int i;

	for (i = 0; i < ICMP_NUM_IDS; i++) {
		icmp_timer_one(c, &icmp_id_map[V4][i], now);
		icmp_timer_one(c, &icmp_id_map[V6][i], now);
	}
}

/**
 * icmp_init() - Initialise sequences in ID map to -1 (no sequence sent yet)
 */
void icmp_init(void)
{
	unsigned i;

	for (i = 0; i < ICMP_NUM_IDS; i++) {
		icmp_id_map[V4][i].seq = icmp_id_map[V6][i].seq = -1;
		icmp_id_map[V4][i].sock = icmp_id_map[V6][i].sock = -1;
	}
}
