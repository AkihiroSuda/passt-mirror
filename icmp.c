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

/* Bitmaps, activity monitoring needed for identifier */
static uint8_t icmp_act[IP_VERSIONS][DIV_ROUND_UP(ICMP_NUM_IDS, 8)];

/**
 * icmp_sock_handler() - Handle new data from IPv4 ICMP socket
 * @c:		Execution context
 * @ref:	epoll reference
 */
void icmp_sock_handler(const struct ctx *c, union epoll_ref ref)
{
	char buf[USHRT_MAX];
	struct icmphdr *ih = (struct icmphdr *)buf;
	struct sockaddr_in sr;
	socklen_t sl = sizeof(sr);
	uint16_t seq, id;
	ssize_t n;

	if (c->no_icmp)
		return;

	n = recvfrom(ref.fd, buf, sizeof(buf), 0, (struct sockaddr *)&sr, &sl);
	if (n < 0)
		return;

	seq = ntohs(ih->un.echo.sequence);

	/* Adjust the packet to have the ID the guest was using, rather than the
	 * host chosen value */
	id = ref.icmp.id;
	ih->un.echo.id = htons(id);

	if (c->mode == MODE_PASTA) {
		if (icmp_id_map[V4][id].seq == seq)
			return;

		icmp_id_map[V4][id].seq = seq;
	}

	debug("ICMP: echo reply to tap, ID: %i, seq: %i", id, seq);

	tap_icmp4_send(c, sr.sin_addr, tap_ip4_daddr(c), buf, n);
}

/**
 * icmpv6_sock_handler() - Handle new data from ICMPv6 socket
 * @c:		Execution context
 * @ref:	epoll reference
 */
void icmpv6_sock_handler(const struct ctx *c, union epoll_ref ref)
{
	char buf[USHRT_MAX];
	struct icmp6hdr *ih = (struct icmp6hdr *)buf;
	struct sockaddr_in6 sr;
	socklen_t sl = sizeof(sr);
	uint16_t seq, id;
	ssize_t n;

	if (c->no_icmp)
		return;

	n = recvfrom(ref.fd, buf, sizeof(buf), 0, (struct sockaddr *)&sr, &sl);
	if (n < 0)
		return;

	seq = ntohs(ih->icmp6_sequence);

	/* Adjust the packet to have the ID the guest was using, rather than the
	 * host chosen value */
	id = ref.icmp.id;
	ih->icmp6_identifier = htons(id);

	/* In PASTA mode, we'll get any reply we send, discard them. */
	if (c->mode == MODE_PASTA) {
		if (icmp_id_map[V6][id].seq == seq)
			return;

		icmp_id_map[V6][id].seq = seq;
	}

	debug("ICMPv6: echo reply to tap, ID: %i, seq: %i", id, seq);

	tap_icmp6_send(c, &sr.sin6_addr,
		       tap_ip6_daddr(c, &sr.sin6_addr), buf, n);
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
int icmp_tap_handler(const struct ctx *c, uint8_t pif, int af,
		     const void *saddr, const void *daddr,
		     const struct pool *p, const struct timespec *now)
{
	size_t plen;

	(void)saddr;
	(void)pif;

	if (af == AF_INET) {
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
		};
		union icmp_epoll_ref iref;
		const struct icmphdr *ih;
		int id, s;

		ih = packet_get(p, 0, 0, sizeof(*ih), &plen);
		if (!ih)
			return 1;

		if (ih->type != ICMP_ECHO)
			return 1;

		iref.id = id = ntohs(ih->un.echo.id);

		if ((s = icmp_id_map[V4][id].sock) <= 0) {
			s = sock_l4(c, AF_INET, IPPROTO_ICMP, &c->ip4.addr_out,
				    c->ip4.ifname_out, 0, iref.u32);
			if (s < 0)
				goto fail_sock;
			if (s > FD_REF_MAX) {
				close(s);
				return 1;
			}

			icmp_id_map[V4][id].sock = s;

			debug("ICMP: new socket %i for echo ID %i", s, id);
		}
		icmp_id_map[V4][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V4], id);

		sa.sin_addr = *(struct in_addr *)daddr;
		if (sendto(s, ih, sizeof(*ih) + plen, MSG_NOSIGNAL,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			debug("ICMP: failed to relay request to socket");
		} else {
			debug("ICMP: echo request to socket, ID: %i, seq: %i",
			      id, ntohs(ih->un.echo.sequence));
		}
	} else if (af == AF_INET6) {
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_scope_id = c->ifi6,
		};
		union icmp_epoll_ref iref;
		const struct icmp6hdr *ih;
		int id, s;

		ih = packet_get(p, 0, 0, sizeof(struct icmp6hdr), &plen);
		if (!ih)
			return 1;

		if (ih->icmp6_type != ICMPV6_ECHO_REQUEST)
			return 1;

		iref.id = id = ntohs(ih->icmp6_identifier);
		if ((s = icmp_id_map[V6][id].sock) <= 0) {
			s = sock_l4(c, AF_INET6, IPPROTO_ICMPV6,
				    &c->ip6.addr_out,
				    c->ip6.ifname_out, 0, iref.u32);
			if (s < 0)
				goto fail_sock;
			if (s > FD_REF_MAX) {
				close(s);
				return 1;
			}

			icmp_id_map[V6][id].sock = s;

			debug("ICMPv6: new socket %i for echo ID %i", s, id);
		}
		icmp_id_map[V6][id].ts = now->tv_sec;
		bitmap_set(icmp_act[V6], id);

		sa.sin6_addr = *(struct in6_addr *)daddr;
		if (sendto(s, ih, sizeof(*ih) + plen, MSG_NOSIGNAL,
			   (struct sockaddr *)&sa, sizeof(sa)) < 1) {
			debug("ICMPv6: failed to relay request to socket");
		} else {
			debug("ICMPv6: echo request to socket, ID: %i, seq: %i",
			      id, ntohs(ih->icmp6_sequence));
		}
	}

	return 1;

fail_sock:
	warn("Cannot open \"ping\" socket. You might need to:");
	warn("  sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
	warn("...echo requests/replies will fail.");
	return 1;
}

/**
 * icmp_timer_one() - Handler for timed events related to a given identifier
 * @c:		Execution context
 * @v6:		Set for IPv6 echo identifier bindings
 * @id:		Echo identifier, host order
 * @now:	Current timestamp
 */
static void icmp_timer_one(const struct ctx *c, int v6, uint16_t id,
			   const struct timespec *now)
{
	struct icmp_id_sock *id_map = &icmp_id_map[v6 ? V6 : V4][id];

	if (now->tv_sec - id_map->ts <= ICMP_ECHO_TIMEOUT)
		return;

	bitmap_clear(icmp_act[v6 ? V6 : V4], id);

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, id_map->sock, NULL);
	close(id_map->sock);
	id_map->sock = 0;
	id_map->seq = -1;
}

/**
 * icmp_timer() - Scan activity bitmap for identifiers with timed events
 * @c:		Execution context
 * @now:	Current timestamp
 */
void icmp_timer(const struct ctx *c, const struct timespec *now)
{
	long *word, tmp;
	unsigned int i;
	int n, v6 = 0;

v6:
	word = (long *)icmp_act[v6 ? V6 : V4];
	for (i = 0; i < ARRAY_SIZE(icmp_act); i += sizeof(long), word++) {
		tmp = *word;
		while ((n = ffsl(tmp))) {
			tmp &= ~(1UL << (n - 1));
			icmp_timer_one(c, v6, i * 8 + n - 1, now);
		}
	}

	if (!v6) {
		v6 = 1;
		goto v6;
	}
}

/**
 * icmp_init() - Initialise sequences in ID map to -1 (no sequence sent yet)
 */
void icmp_init(void)
{
	unsigned i;

	for (i = 0; i < ICMP_NUM_IDS; i++)
		icmp_id_map[V4][i].seq = icmp_id_map[V6][i].seq = -1;
}
