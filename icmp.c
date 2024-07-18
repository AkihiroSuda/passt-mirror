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
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "siphash.h"
#include "inany.h"
#include "icmp.h"
#include "flow_table.h"

#define ICMP_ECHO_TIMEOUT	60 /* s, timeout for ICMP socket activity */
#define ICMP_NUM_IDS		(1U << 16)

/* Indexed by ICMP echo identifier */
static struct icmp_ping_flow *icmp_id_map[IP_VERSIONS][ICMP_NUM_IDS];

/**
 * ping_at_sidx() - Get ping specific flow at given sidx
 * @sidx:	Flow and side to retrieve
 *
 * Return: ping specific flow at @sidx, or NULL of @sidx is invalid.  Asserts if
 *         the flow at @sidx is not FLOW_PING4 or FLOW_PING6
 */
static struct icmp_ping_flow *ping_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_PING4 || flow->f.type == FLOW_PING6);
	return &flow->ping;
}

/**
 * icmp_sock_handler() - Handle new data from ICMP or ICMPv6 socket
 * @c:		Execution context
 * @ref:	epoll reference
 */
void icmp_sock_handler(const struct ctx *c, union epoll_ref ref)
{
	struct icmp_ping_flow *pingf = ping_at_sidx(ref.flowside);
	const struct flowside *ini = &pingf->f.side[INISIDE];
	union sockaddr_inany sr;
	socklen_t sl = sizeof(sr);
	char buf[USHRT_MAX];
	uint16_t seq;
	ssize_t n;

	if (c->no_icmp)
		return;

	ASSERT(pingf);

	n = recvfrom(ref.fd, buf, sizeof(buf), 0, &sr.sa, &sl);
	if (n < 0) {
		flow_err(pingf, "recvfrom() error: %s", strerror(errno));
		return;
	}

	if (pingf->f.type == FLOW_PING4) {
		struct icmphdr *ih4 = (struct icmphdr *)buf;

		if (sr.sa_family != AF_INET || (size_t)n < sizeof(*ih4) ||
		    ih4->type != ICMP_ECHOREPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih4->un.echo.id = htons(ini->eport);
		seq = ntohs(ih4->un.echo.sequence);
	} else if (pingf->f.type == FLOW_PING6) {
		struct icmp6hdr *ih6 = (struct icmp6hdr *)buf;

		if (sr.sa_family != AF_INET6 || (size_t)n < sizeof(*ih6) ||
		    ih6->icmp6_type != ICMPV6_ECHO_REPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih6->icmp6_identifier = htons(ini->eport);
		seq = ntohs(ih6->icmp6_sequence);
	} else {
		ASSERT(0);
	}

	/* In PASTA mode, we'll get any reply we send, discard them. */
	if (c->mode == MODE_PASTA) {
		if (pingf->seq == seq)
			return;

		pingf->seq = seq;
	}

	flow_dbg(pingf, "echo reply to tap, ID: %"PRIu16", seq: %"PRIu16,
		 ini->eport, seq);

	if (pingf->f.type == FLOW_PING4)
		tap_icmp4_send(c, sr.sa4.sin_addr, tap_ip4_daddr(c), buf, n);
	else if (pingf->f.type == FLOW_PING6)
		tap_icmp6_send(c, &sr.sa6.sin6_addr,
			       tap_ip6_daddr(c, &sr.sa6.sin6_addr), buf, n);
	return;

unexpected:
	flow_err(pingf, "Unexpected packet on ping socket");
}

/**
 * icmp_ping_close() - Close and clean up a ping flow
 * @c:		Execution context
 * @pingf:	ping flow entry to close
 */
static void icmp_ping_close(const struct ctx *c,
			    const struct icmp_ping_flow *pingf)
{
	uint16_t id = pingf->f.side[INISIDE].eport;

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, pingf->sock, NULL);
	close(pingf->sock);

	if (pingf->f.type == FLOW_PING4)
		icmp_id_map[V4][id] = NULL;
	else
		icmp_id_map[V6][id] = NULL;
}

/**
 * icmp_ping_new() - Prepare a new ping socket for a new id
 * @c:		Execution context
 * @id_sock:	Pointer to ping flow entry slot in icmp_id_map[] to update
 * @af:		Address family, AF_INET or AF_INET6
 * @id:		ICMP id for the new socket
 * @saddr:	Source address
 * @daddr:	Destination address
 *
 * Return: Newly opened ping flow, or NULL on failure
 */
static struct icmp_ping_flow *icmp_ping_new(const struct ctx *c,
					    struct icmp_ping_flow **id_sock,
					    sa_family_t af, uint16_t id,
					    const void *saddr, const void *daddr)
{
	uint8_t flowtype = af == AF_INET ? FLOW_PING4 : FLOW_PING6;
	union epoll_ref ref = { .type = EPOLL_TYPE_PING };
	union flow *flow = flow_alloc();
	struct icmp_ping_flow *pingf;
	const void *bind_addr;
	const char *bind_if;

	if (!flow)
		return NULL;

	flow_initiate_af(flow, PIF_TAP, af, saddr, id, daddr, id);
	/* FIXME: Record outbound source address when known */
	flow_target_af(flow, PIF_HOST,	af, NULL, 0, daddr, 0);
	pingf = FLOW_SET_TYPE(flow, flowtype, ping);

	pingf->seq = -1;

	if (af == AF_INET) {
		bind_addr = &c->ip4.addr_out;
		bind_if = c->ip4.ifname_out;
	} else {
		bind_addr = &c->ip6.addr_out;
		bind_if = c->ip6.ifname_out;
	}

	ref.flowside = FLOW_SIDX(flow, TGTSIDE);
	pingf->sock = sock_l4(c, af, EPOLL_TYPE_PING, bind_addr, bind_if,
			      0, ref.data);

	if (pingf->sock < 0) {
		warn("Cannot open \"ping\" socket. You might need to:");
		warn("  sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
		warn("...echo requests/replies will fail.");
		goto cancel;
	}

	if (pingf->sock > FD_REF_MAX)
		goto cancel;

	flow_dbg(pingf, "new socket %i for echo ID %"PRIu16, pingf->sock, id);

	*id_sock = pingf;

	FLOW_ACTIVATE(pingf);

	return pingf;

cancel:
	flow_alloc_cancel(flow);
	return NULL;
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
	union sockaddr_inany sa = { .sa_family = af };
	const socklen_t sl = af == AF_INET ? sizeof(sa.sa4) : sizeof(sa.sa6);
	struct icmp_ping_flow *pingf, **id_sock;
	size_t dlen, l4len;
	uint16_t id, seq;
	void *pkt;

	(void)saddr;
	ASSERT(pif == PIF_TAP);

	if (af == AF_INET) {
		const struct icmphdr *ih;

		if (!(pkt = packet_get(p, 0, 0, sizeof(*ih), &dlen)))
			return 1;

		ih =  (struct icmphdr *)pkt;
		l4len = dlen + sizeof(*ih);

		if (ih->type != ICMP_ECHO)
			return 1;

		id = ntohs(ih->un.echo.id);
		id_sock = &icmp_id_map[V4][id];
		seq = ntohs(ih->un.echo.sequence);
		sa.sa4.sin_addr = *(struct in_addr *)daddr;
	} else if (af == AF_INET6) {
		const struct icmp6hdr *ih;

		if (!(pkt = packet_get(p, 0, 0, sizeof(*ih), &dlen)))
			return 1;

		ih = (struct icmp6hdr *)pkt;
		l4len = dlen + sizeof(*ih);

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

	if (!(pingf = *id_sock))
		if (!(pingf = icmp_ping_new(c, id_sock, af, id, saddr, daddr)))
			return 1;

	pingf->ts = now->tv_sec;

	if (sendto(pingf->sock, pkt, l4len, MSG_NOSIGNAL, &sa.sa, sl) < 0) {
		flow_dbg(pingf, "failed to relay request to socket: %s",
			 strerror(errno));
	} else {
		flow_dbg(pingf,
			 "echo request to socket, ID: %"PRIu16", seq: %"PRIu16,
			 id, seq);
	}

	return 1;
}

/**
 * icmp_ping_timer() - Handler for timed events related to a given flow
 * @c:		Execution context
 * @pingf:	Ping flow to check for timeout
 * @now:	Current timestamp
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool icmp_ping_timer(const struct ctx *c, const struct icmp_ping_flow *pingf,
		     const struct timespec *now)
{
	if (now->tv_sec - pingf->ts <= ICMP_ECHO_TIMEOUT)
		return false;

	icmp_ping_close(c, pingf);
	return true;
}
