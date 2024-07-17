// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * udp.c - UDP L2-L4 translation routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For UDP, a reduced version of port-based connection tracking is implemented
 * with two purposes:
 * - binding ephemeral ports when they're used as source port by the guest, so
 *   that replies on those ports can be forwarded back to the guest, with a
 *   fixed timeout for this binding
 * - packets received from the local host get their source changed to a local
 *   address (gateway address) so that they can be forwarded to the guest, and
 *   packets sent as replies by the guest need their destination address to
 *   be changed back to the address of the local host. This is dynamic to allow
 *   connections from the gateway as well, and uses the same fixed 180s timeout
 * 
 * Sockets for bound ports are created at initialisation time, one set for IPv4
 * and one for IPv6.
 *
 * Packets are forwarded back and forth, by prepending and stripping UDP headers
 * in the obvious way, with no port translation.
 *
 * In PASTA mode, the L2-L4 translation is skipped for connections to ports
 * bound between namespaces using the loopback interface, messages are directly
 * transferred between L4 sockets instead. These are called spliced connections
 * for consistency with the TCP implementation, but the splice() syscall isn't
 * actually used as it wouldn't make sense for datagram-based connections: a
 * pair of recvmmsg() and sendmmsg() deals with this case.
 *
 * The connection tracking for PASTA mode is slightly complicated by the absence
 * of actual connections, see struct udp_splice_port, and these examples:
 *
 * - from init to namespace:
 *
 *   - forward direction: 127.0.0.1:5000 -> 127.0.0.1:80 in init from socket s,
 *     with epoll reference: index = 80, splice = 1, orig = 1, ns = 0
 *     - if udp_splice_ns[V4][5000].sock:
 *       - send packet to udp_splice_ns[V4][5000].sock, with destination port
 *         80
 *     - otherwise:
 *       - create new socket udp_splice_ns[V4][5000].sock
 *       - bind in namespace to 127.0.0.1:5000
 *       - add to epoll with reference: index = 5000, splice = 1, orig = 0,
 *         ns = 1
 *     - update udp_splice_init[V4][80].ts and udp_splice_ns[V4][5000].ts with
 *       current time
 *
 *   - reverse direction: 127.0.0.1:80 -> 127.0.0.1:5000 in namespace socket s,
 *     having epoll reference: index = 5000, splice = 1, orig = 0, ns = 1
 *     - if udp_splice_init[V4][80].sock:
 *       - send to udp_splice_init[V4][80].sock, with destination port 5000
 *       - update udp_splice_init[V4][80].ts and udp_splice_ns[V4][5000].ts with
 *         current time
 *     - otherwise, discard
 *
 * - from namespace to init:
 *
 *   - forward direction: 127.0.0.1:2000 -> 127.0.0.1:22 in namespace from
 *     socket s, with epoll reference: index = 22, splice = 1, orig = 1, ns = 1
 *     - if udp4_splice_init[V4][2000].sock:
 *       - send packet to udp_splice_init[V4][2000].sock, with destination
 *         port 22
 *     - otherwise:
 *       - create new socket udp_splice_init[V4][2000].sock
 *       - bind in init to 127.0.0.1:2000
 *       - add to epoll with reference: index = 2000, splice = 1, orig = 0,
 *         ns = 0
 *     - update udp_splice_ns[V4][22].ts and udp_splice_init[V4][2000].ts with
 *       current time
 *
 *   - reverse direction: 127.0.0.1:22 -> 127.0.0.1:2000 in init from socket s,
 *     having epoll reference: index = 2000, splice = 1, orig = 0, ns = 0
 *   - if udp_splice_ns[V4][22].sock:
 *     - send to udp_splice_ns[V4][22].sock, with destination port 2000
 *     - update udp_splice_ns[V4][22].ts and udp_splice_init[V4][2000].ts with
 *       current time
 *   - otherwise, discard
 */

#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <linux/errqueue.h>

#include "checksum.h"
#include "util.h"
#include "iov.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "passt.h"
#include "tap.h"
#include "pcap.h"
#include "log.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */
#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */

/**
 * struct udp_tap_port - Port tracking based on tap-facing source port
 * @sock:	Socket bound to source port used as index
 * @flags:	Flags for recent activity type seen from/to port
 * @ts:		Activity timestamp from tap, used for socket aging
 */
struct udp_tap_port {
	int sock;
	uint8_t flags;
#define PORT_LOCAL	BIT(0)	/* Port was contacted from local address */
#define PORT_LOOPBACK	BIT(1)	/* Port was contacted from loopback address */
#define PORT_GUA	BIT(2)	/* Port was contacted from global unicast */
#define PORT_DNS_FWD	BIT(3)	/* Port used as source for DNS remapped query */

	time_t ts;
};

/**
 * struct udp_splice_port - Bound socket for spliced communication
 * @sock:	Socket bound to index port
 * @ts:		Activity timestamp
 */
struct udp_splice_port {
	int sock;
	time_t ts;
};

/* Port tracking, arrays indexed by packet source port (host order) */
static struct udp_tap_port	udp_tap_map	[IP_VERSIONS][NUM_PORTS];

/* "Spliced" sockets indexed by bound port (host order) */
static struct udp_splice_port udp_splice_ns  [IP_VERSIONS][NUM_PORTS];
static struct udp_splice_port udp_splice_init[IP_VERSIONS][NUM_PORTS];

enum udp_act_type {
	UDP_ACT_TAP,
	UDP_ACT_SPLICE_NS,
	UDP_ACT_SPLICE_INIT,
	UDP_ACT_TYPE_MAX,
};

/* Activity-based aging for bindings */
static uint8_t udp_act[IP_VERSIONS][UDP_ACT_TYPE_MAX][DIV_ROUND_UP(NUM_PORTS, 8)];

/* Static buffers */

/**
 * struct udp_payload_t - UDP header and data for inbound messages
 * @uh:		UDP header
 * @data:	UDP data
 */
static struct udp_payload_t {
	struct udphdr uh;
	char data[USHRT_MAX - sizeof(struct udphdr)];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)))
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))))
#endif
udp_payload[UDP_MAX_FRAMES];

/* Ethernet header for IPv4 frames */
static struct ethhdr udp4_eth_hdr;

/* Ethernet header for IPv6 frames */
static struct ethhdr udp6_eth_hdr;

/**
 * struct udp_meta_t - Pre-cooked headers and metadata for UDP packets
 * @ip6h:	Pre-filled IPv6 header (except for payload_len and addresses)
 * @ip4h:	Pre-filled IPv4 header (except for tot_len and saddr)
 * @taph:	Tap backend specific header
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @splicesrc:	Source port for splicing, or -1 if not spliceable
 */
static struct udp_meta_t {
	struct ipv6hdr ip6h;
	struct iphdr ip4h;
	struct tap_hdr taph;

	union sockaddr_inany s_in;
	int splicesrc;
}
#ifdef __AVX2__
__attribute__ ((aligned(32)))
#endif
udp_meta[UDP_MAX_FRAMES];

/**
 * enum udp_iov_idx - Indices for the buffers making up a single UDP frame
 * @UDP_IOV_TAP         tap specific header
 * @UDP_IOV_ETH         Ethernet header
 * @UDP_IOV_IP          IP (v4/v6) header
 * @UDP_IOV_PAYLOAD     IP payload (UDP header + data)
 * @UDP_NUM_IOVS        the number of entries in the iovec array
 */
enum udp_iov_idx {
	UDP_IOV_TAP	= 0,
	UDP_IOV_ETH	= 1,
	UDP_IOV_IP	= 2,
	UDP_IOV_PAYLOAD	= 3,
	UDP_NUM_IOVS
};

/* IOVs and msghdr arrays for receiving datagrams from sockets */
static struct iovec	udp_iov_recv		[UDP_MAX_FRAMES];
static struct mmsghdr	udp4_mh_recv		[UDP_MAX_FRAMES];
static struct mmsghdr	udp6_mh_recv		[UDP_MAX_FRAMES];

/* IOVs and msghdr arrays for sending "spliced" datagrams to sockets */
static union sockaddr_inany udp_splice_to;

static struct iovec	udp_iov_splice		[UDP_MAX_FRAMES];
static struct mmsghdr	udp_mh_splice		[UDP_MAX_FRAMES];

/* IOVs for L2 frames */
static struct iovec	udp_l2_iov		[UDP_MAX_FRAMES][UDP_NUM_IOVS];


/**
 * udp_portmap_clear() - Clear UDP port map before configuration
 */
void udp_portmap_clear(void)
{
	unsigned i;

	for (i = 0; i < NUM_PORTS; i++) {
		udp_tap_map[V4][i].sock = udp_tap_map[V6][i].sock = -1;
		udp_splice_ns[V4][i].sock = udp_splice_ns[V6][i].sock = -1;
		udp_splice_init[V4][i].sock = udp_splice_init[V6][i].sock = -1;
	}
}

/**
 * udp_invert_portmap() - Compute reverse port translations for return packets
 * @fwd:	Port forwarding configuration to compute reverse map for
 */
static void udp_invert_portmap(struct udp_fwd_ports *fwd)
{
	unsigned int i;

	static_assert(ARRAY_SIZE(fwd->f.delta) == ARRAY_SIZE(fwd->rdelta),
		      "Forward and reverse delta arrays must have same size");
	for (i = 0; i < ARRAY_SIZE(fwd->f.delta); i++) {
		in_port_t delta = fwd->f.delta[i];

		if (delta) {
			/* Keep rport calculation separate from its usage: we
			 * need to perform the sum in in_port_t width (that is,
			 * modulo 65536), but C promotion rules would sum the
			 * two terms as 'int', if we just open-coded the array
			 * index as 'i + delta'.
			 */
			in_port_t rport = i + delta;

			fwd->rdelta[rport] = NUM_PORTS - delta;
		}
	}
}

/**
 * udp_update_l2_buf() - Update L2 buffers with Ethernet and IPv4 addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 */
void udp_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s)
{
	eth_update_mac(&udp4_eth_hdr, eth_d, eth_s);
	eth_update_mac(&udp6_eth_hdr, eth_d, eth_s);
}

/**
 * udp_iov_init_one() - Initialise scatter-gather lists for one buffer
 * @c:		Execution context
 * @i:		Index of buffer to initialize
 */
static void udp_iov_init_one(const struct ctx *c, size_t i)
{
	struct udp_payload_t *payload = &udp_payload[i];
	struct udp_meta_t *meta = &udp_meta[i];
	struct iovec *siov = &udp_iov_recv[i];
	struct iovec *tiov = udp_l2_iov[i];

	*meta = (struct udp_meta_t) {
		.ip4h = L2_BUF_IP4_INIT(IPPROTO_UDP),
		.ip6h = L2_BUF_IP6_INIT(IPPROTO_UDP),
	};

	*siov = IOV_OF_LVALUE(payload->data);

	tiov[UDP_IOV_TAP] = tap_hdr_iov(c, &meta->taph);
	tiov[UDP_IOV_PAYLOAD].iov_base = payload;

	/* It's useful to have separate msghdr arrays for receiving.  Otherwise,
	 * an IPv4 recv() will alter msg_namelen, so we'd have to reset it every
	 * time or risk truncating the address on future IPv6 recv()s.
	 */
	if (c->ifi4) {
		struct msghdr *mh = &udp4_mh_recv[i].msg_hdr;

		mh->msg_name	= &meta->s_in;
		mh->msg_namelen	= sizeof(struct sockaddr_in);
		mh->msg_iov	= siov;
		mh->msg_iovlen	= 1;
	}

	if (c->ifi6) {
		struct msghdr *mh = &udp6_mh_recv[i].msg_hdr;

		mh->msg_name	= &meta->s_in;
		mh->msg_namelen	= sizeof(struct sockaddr_in6);
		mh->msg_iov	= siov;
		mh->msg_iovlen	= 1;
	}
}

/**
 * udp_iov_init() - Initialise scatter-gather L2 buffers
 * @c:		Execution context
 */
static void udp_iov_init(const struct ctx *c)
{
	size_t i;

	udp4_eth_hdr.h_proto = htons_constant(ETH_P_IP);
	udp6_eth_hdr.h_proto = htons_constant(ETH_P_IPV6);

	for (i = 0; i < UDP_MAX_FRAMES; i++)
		udp_iov_init_one(c, i);
}

/**
 * udp_splice_new() - Create and prepare socket for "spliced" binding
 * @c:		Execution context
 * @v6:		Set for IPv6 sockets
 * @src:	Source port of original connection, host order
 * @ns:		Does the splice originate in the ns or not
 *
 * Return: prepared socket, negative error code on failure
 *
 * #syscalls:pasta getsockname
 */
int udp_splice_new(const struct ctx *c, int v6, in_port_t src, bool ns)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP };
	union epoll_ref ref = { .type = EPOLL_TYPE_UDP,
				.udp = { .splice = true, .v6 = v6, .port = src }
			      };
	struct udp_splice_port *sp;
	int act, s;

	if (ns) {
		ref.udp.pif = PIF_SPLICE;
		sp = &udp_splice_ns[v6 ? V6 : V4][src];
		act = UDP_ACT_SPLICE_NS;
	} else {
		ref.udp.pif = PIF_HOST;
		sp = &udp_splice_init[v6 ? V6 : V4][src];
		act = UDP_ACT_SPLICE_INIT;
	}

	s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK,
		   IPPROTO_UDP);

	if (s > FD_REF_MAX) {
		close(s);
		return -EIO;
	}

	if (s < 0)
		return s;

	ref.fd = s;

	if (v6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(src),
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		};
		if (bind(s, (struct sockaddr *)&addr6, sizeof(addr6)))
			goto fail;
	} else {
		struct sockaddr_in addr4 = {
			.sin_family = AF_INET,
			.sin_port = htons(src),
			.sin_addr = IN4ADDR_LOOPBACK_INIT,
		};
		if (bind(s, (struct sockaddr *)&addr4, sizeof(addr4)))
			goto fail;
	}

	sp->sock = s;
	bitmap_set(udp_act[v6 ? V6 : V4][act], src);

	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, s, &ev);
	return s;

fail:
	close(s);
	return -1;
}

/**
 * struct udp_splice_new_ns_arg - Arguments for udp_splice_new_ns()
 * @c:		Execution context
 * @v6:		Set for IPv6
 * @src:	Source port of originating datagram, host order
 * @dst:	Destination port of originating datagram, host order
 * @s:		Newly created socket or negative error code
 */
struct udp_splice_new_ns_arg {
	const struct ctx *c;
	int v6;
	in_port_t src;
	int s;
};

/**
 * udp_splice_new_ns() - Enter namespace and call udp_splice_new()
 * @arg:	See struct udp_splice_new_ns_arg
 *
 * Return: 0
 */
static int udp_splice_new_ns(void *arg)
{
	struct udp_splice_new_ns_arg *a;

	a = (struct udp_splice_new_ns_arg *)arg;

	ns_enter(a->c);

	a->s = udp_splice_new(a->c, a->v6, a->src, true);

	return 0;
}

/**
 * udp_mmh_splice_port() - Is source address of message suitable for splicing?
 * @ref:	epoll reference for incoming message's origin socket
 * @mmh:	mmsghdr of incoming message
 *
 * Return: if source address of message in @mmh refers to localhost (127.0.0.1
 *         or ::1) its source port (host order), otherwise -1.
 */
static int udp_mmh_splice_port(union epoll_ref ref, const struct mmsghdr *mmh)
{
	const struct sockaddr_in6 *sa6 = mmh->msg_hdr.msg_name;
	const struct sockaddr_in *sa4 = mmh->msg_hdr.msg_name;

	ASSERT(ref.type == EPOLL_TYPE_UDP);

	if (!ref.udp.splice)
		return -1;

	if (ref.udp.v6 && IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
		return ntohs(sa6->sin6_port);

	if (!ref.udp.v6 && IN4_IS_ADDR_LOOPBACK(&sa4->sin_addr))
		return ntohs(sa4->sin_port);

	return -1;
}

/**
 * udp_splice_prepare() - Prepare one datagram for splicing
 * @mmh:	Receiving mmsghdr array
 * @idx:	Index of the datagram to prepare
 */
static void udp_splice_prepare(struct mmsghdr *mmh, unsigned idx)
{
	udp_mh_splice[idx].msg_hdr.msg_iov->iov_len = mmh[idx].msg_len;
}

/**
 * udp_splice_send() - Send a batch of datagrams from socket to socket
 * @c:		Execution context
 * @start:	Index of batch's first datagram in udp[46]_l2_buf
 * @n:		Number of datagrams in batch
 * @src:	Source port for datagram (target side)
 * @dst:	Destination port for datagrams (target side)
 * @ref:	epoll reference for origin socket
 * @now:	Timestamp
 */
static void udp_splice_send(const struct ctx *c, size_t start, size_t n,
			    in_port_t src, in_port_t dst,
			    union epoll_ref ref,
			    const struct timespec *now)
{
	int s;

	if (ref.udp.v6) {
		udp_splice_to.sa6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = in6addr_loopback,
			.sin6_port = htons(dst),
		};
	} else {
		udp_splice_to.sa4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = in4addr_loopback,
			.sin_port = htons(dst),
		};
	}

	if (ref.udp.pif == PIF_SPLICE) {
		src += c->udp.fwd_in.rdelta[src];
		s = udp_splice_init[ref.udp.v6][src].sock;
		if (s < 0 && ref.udp.orig)
			s = udp_splice_new(c, ref.udp.v6, src, false);

		if (s < 0)
			return;

		udp_splice_ns[ref.udp.v6][dst].ts = now->tv_sec;
		udp_splice_init[ref.udp.v6][src].ts = now->tv_sec;
	} else {
		ASSERT(ref.udp.pif == PIF_HOST);
		src += c->udp.fwd_out.rdelta[src];
		s = udp_splice_ns[ref.udp.v6][src].sock;
		if (s < 0 && ref.udp.orig) {
			struct udp_splice_new_ns_arg arg = {
				c, ref.udp.v6, src, -1,
			};

			NS_CALL(udp_splice_new_ns, &arg);
			s = arg.s;
		}
		if (s < 0)
			return;

		udp_splice_init[ref.udp.v6][dst].ts = now->tv_sec;
		udp_splice_ns[ref.udp.v6][src].ts = now->tv_sec;
	}

	sendmmsg(s, udp_mh_splice + start, n, MSG_NOSIGNAL);
}

/**
 * udp_update_hdr4() - Update headers for one IPv4 datagram
 * @c:		Execution context
 * @ip4h:	Pre-filled IPv4 header (except for tot_len and saddr)
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @bp:		Pointer to udp_payload_t to update
 * @dstport:	Destination port number
 * @dlen:	Length of UDP payload
 * @now:	Current timestamp
 *
 * Return: size of IPv4 payload (UDP header + data)
 */
static size_t udp_update_hdr4(const struct ctx *c,
			      struct iphdr *ip4h, const struct sockaddr_in *s_in,
			      struct udp_payload_t *bp,
			      in_port_t dstport, size_t dlen,
			      const struct timespec *now)
{
	const struct in_addr dst = c->ip4.addr_seen;
	in_port_t srcport = ntohs(s_in->sin_port);
	size_t l4len = dlen + sizeof(bp->uh);
	size_t l3len = l4len + sizeof(*ip4h);
	struct in_addr src = s_in->sin_addr;

	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match) &&
	    IN4_ARE_ADDR_EQUAL(&src, &c->ip4.dns_host) && srcport == 53 &&
	    (udp_tap_map[V4][dstport].flags & PORT_DNS_FWD)) {
		src = c->ip4.dns_match;
	} else if (IN4_IS_ADDR_LOOPBACK(&src) ||
		   IN4_ARE_ADDR_EQUAL(&src, &c->ip4.addr_seen)) {
		udp_tap_map[V4][srcport].ts = now->tv_sec;
		udp_tap_map[V4][srcport].flags |= PORT_LOCAL;

		if (IN4_IS_ADDR_LOOPBACK(&src))
			udp_tap_map[V4][srcport].flags |= PORT_LOOPBACK;
		else
			udp_tap_map[V4][srcport].flags &= ~PORT_LOOPBACK;

		bitmap_set(udp_act[V4][UDP_ACT_TAP], srcport);

		src = c->ip4.gw;
	}

	ip4h->tot_len = htons(l3len);
	ip4h->daddr = dst.s_addr;
	ip4h->saddr = src.s_addr;
	ip4h->check = csum_ip4_header(l3len, IPPROTO_UDP, src, dst);

	bp->uh.source = s_in->sin_port;
	bp->uh.dest = htons(dstport);
	bp->uh.len = htons(l4len);
	csum_udp4(&bp->uh, src, dst, bp->data, dlen);

	return l4len;
}

/**
 * udp_update_hdr6() - Update headers for one IPv6 datagram
 * @c:		Execution context
 * @ip6h:	Pre-filled IPv6 header (except for payload_len and addresses)
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @bp:		Pointer to udp_payload_t to update
 * @dstport:	Destination port number
 * @dlen:	Length of UDP payload
 * @now:	Current timestamp
 *
 * Return: size of IPv6 payload (UDP header + data)
 */
static size_t udp_update_hdr6(const struct ctx *c,
			      struct ipv6hdr *ip6h, struct sockaddr_in6 *s_in6,
			      struct udp_payload_t *bp,
			      in_port_t dstport, size_t dlen,
			      const struct timespec *now)
{
	const struct in6_addr *src = &s_in6->sin6_addr;
	const struct in6_addr *dst = &c->ip6.addr_seen;
	in_port_t srcport = ntohs(s_in6->sin6_port);
	uint16_t l4len = dlen + sizeof(bp->uh);

	if (IN6_IS_ADDR_LINKLOCAL(src)) {
		dst = &c->ip6.addr_ll_seen;
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match) &&
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.dns_host) &&
		   srcport == 53 &&
		   (udp_tap_map[V4][dstport].flags & PORT_DNS_FWD)) {
		src = &c->ip6.dns_match;
	} else if (IN6_IS_ADDR_LOOPBACK(src)			||
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr_seen)	||
		   IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr)) {
		udp_tap_map[V6][srcport].ts = now->tv_sec;
		udp_tap_map[V6][srcport].flags |= PORT_LOCAL;

		if (IN6_IS_ADDR_LOOPBACK(src))
			udp_tap_map[V6][srcport].flags |= PORT_LOOPBACK;
		else
			udp_tap_map[V6][srcport].flags &= ~PORT_LOOPBACK;

		if (IN6_ARE_ADDR_EQUAL(src, &c->ip6.addr))
			udp_tap_map[V6][srcport].flags |= PORT_GUA;
		else
			udp_tap_map[V6][srcport].flags &= ~PORT_GUA;

		bitmap_set(udp_act[V6][UDP_ACT_TAP], srcport);

		dst = &c->ip6.addr_ll_seen;

		if (IN6_IS_ADDR_LINKLOCAL(&c->ip6.gw))
			src = &c->ip6.gw;
		else
			src = &c->ip6.addr_ll;

	}

	ip6h->payload_len = htons(l4len);
	ip6h->daddr = *dst;
	ip6h->saddr = *src;
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 255;

	bp->uh.source = s_in6->sin6_port;
	bp->uh.dest = htons(dstport);
	bp->uh.len = ip6h->payload_len;
	csum_udp6(&bp->uh, src, dst, bp->data, dlen);

	return l4len;
}

/**
 * udp_tap_prepare() - Convert one datagram into a tap frame
 * @c:		Execution context
 * @mmh:	Receiving mmsghdr array
 * @idx:	Index of the datagram to prepare
 * @dstport:	Destination port
 * @v6:		Prepare for IPv6?
 * @now:	Current timestamp
 */
static void udp_tap_prepare(const struct ctx *c, const struct mmsghdr *mmh,
			    unsigned idx, in_port_t dstport, bool v6,
			    const struct timespec *now)
{
	struct iovec (*tap_iov)[UDP_NUM_IOVS] = &udp_l2_iov[idx];
	struct udp_payload_t *bp = &udp_payload[idx];
	struct udp_meta_t *bm = &udp_meta[idx];
	size_t l4len;

	if (v6) {
		l4len = udp_update_hdr6(c, &bm->ip6h, &bm->s_in.sa6, bp,
					dstport, mmh[idx].msg_len, now);
		tap_hdr_update(&bm->taph, l4len + sizeof(bm->ip6h) +
			       sizeof(udp6_eth_hdr));
		(*tap_iov)[UDP_IOV_ETH] = IOV_OF_LVALUE(udp6_eth_hdr);
		(*tap_iov)[UDP_IOV_IP] = IOV_OF_LVALUE(bm->ip6h);
	} else {
		l4len = udp_update_hdr4(c, &bm->ip4h, &bm->s_in.sa4, bp,
					dstport, mmh[idx].msg_len, now);
		tap_hdr_update(&bm->taph, l4len + sizeof(bm->ip4h) +
			       sizeof(udp4_eth_hdr));
		(*tap_iov)[UDP_IOV_ETH] = IOV_OF_LVALUE(udp4_eth_hdr);
		(*tap_iov)[UDP_IOV_IP] = IOV_OF_LVALUE(bm->ip4h);
	}
	(*tap_iov)[UDP_IOV_PAYLOAD].iov_len = l4len;
}

/**
 * udp_sock_recverr() - Receive and clear an error from a socket
 * @s:		Socket to receive from
 *
 * Return: true if errors received and processed, false if no more errors
 *
 * #syscalls recvmsg
 */
static bool udp_sock_recverr(int s)
{
	const struct sock_extended_err *ee;
	const struct cmsghdr *hdr;
	char buf[CMSG_SPACE(sizeof(*ee))];
	struct msghdr mh = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = NULL,
		.msg_iovlen = 0,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};
	ssize_t rc;

	rc = recvmsg(s, &mh, MSG_ERRQUEUE);
	if (rc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			err_perror("Failed to read error queue");
		return false;
	}

	if (!(mh.msg_flags & MSG_ERRQUEUE)) {
		err("Missing MSG_ERRQUEUE flag reading error queue");
		return false;
	}

	hdr = CMSG_FIRSTHDR(&mh);
	if (!((hdr->cmsg_level == IPPROTO_IP &&
	       hdr->cmsg_type == IP_RECVERR) ||
	      (hdr->cmsg_level == IPPROTO_IPV6 &&
	       hdr->cmsg_type == IPV6_RECVERR))) {
		err("Unexpected cmsg reading error queue");
		return false;
	}

	ee = (const struct sock_extended_err *)CMSG_DATA(hdr);

	/* TODO: When possible propagate and otherwise handle errors */
	debug("%s error on UDP socket %i: %s",
	      str_ee_origin(ee), s, strerror(ee->ee_errno));

	return true;
}

/**
 * udp_sock_recv() - Receive datagrams from a socket
 * @c:		Execution context
 * @s:		Socket to receive from
 * @events:	epoll events bitmap
 * @mmh		mmsghdr array to receive into
 *
 * #syscalls recvmmsg
 */
static int udp_sock_recv(const struct ctx *c, int s, uint32_t events,
			 struct mmsghdr *mmh)
{
	/* For not entirely clear reasons (data locality?) pasta gets better
	 * throughput if we receive tap datagrams one at a atime.  For small
	 * splice datagrams throughput is slightly better if we do batch, but
	 * it's slightly worse for large splice datagrams.  Since we don't know
	 * before we receive whether we'll use tap or splice, always go one at a
	 * time for pasta mode.
	 */
	int n = (c->mode == MODE_PASTA ? 1 : UDP_MAX_FRAMES);

	ASSERT(!c->no_udp);

	/* Clear any errors first */
	if (events & EPOLLERR) {
		while (udp_sock_recverr(s))
			;
	}

	if (!(events & EPOLLIN))
		return 0;

	n = recvmmsg(s, mmh, n, 0, NULL);
	if (n < 0) {
		err_perror("Error receiving datagrams");
		return 0;
	}

	return n;
}

/**
 * udp_buf_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 *
 * #syscalls recvmmsg
 */
void udp_buf_sock_handler(const struct ctx *c, union epoll_ref ref, uint32_t events,
			  const struct timespec *now)
{
	struct mmsghdr *mmh_recv = ref.udp.v6 ? udp6_mh_recv : udp4_mh_recv;
	in_port_t dstport = ref.udp.port;
	int n, i;

	if ((n = udp_sock_recv(c, ref.fd, events, mmh_recv)) <= 0)
		return;

	if (ref.udp.pif == PIF_SPLICE)
		dstport += c->udp.fwd_out.f.delta[dstport];
	else if (ref.udp.pif == PIF_HOST)
		dstport += c->udp.fwd_in.f.delta[dstport];

	/* We divide datagrams into batches based on how we need to send them,
	 * determined by udp_meta[i].splicesrc.  To avoid either two passes
	 * through the array, or recalculating splicesrc for a single entry, we
	 * have to populate it one entry *ahead* of the loop counter.
	 */
	udp_meta[0].splicesrc = udp_mmh_splice_port(ref, mmh_recv);
	for (i = 0; i < n; ) {
		int batchsrc = udp_meta[i].splicesrc;
		int batchstart = i;

		do {
			if (batchsrc >= 0) {
				udp_splice_prepare(mmh_recv, i);
			} else {
				udp_tap_prepare(c, mmh_recv, i, dstport,
						ref.udp.v6, now);
			}

			if (++i >= n)
				break;

			udp_meta[i].splicesrc = udp_mmh_splice_port(ref,
								    &mmh_recv[i]);
		} while (udp_meta[i].splicesrc == batchsrc);

		if (batchsrc >= 0) {
			udp_splice_send(c, batchstart, i - batchstart,
					batchsrc, dstport, ref, now);
		} else {
			tap_send_frames(c, &udp_l2_iov[batchstart][0],
					UDP_NUM_IOVS, i - batchstart);
		}
	}
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @p:		Pool of UDP packets, with UDP headers
 * @idx:	Index of first packet to process
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 *
 * #syscalls sendmmsg
 */
int udp_tap_handler(struct ctx *c, uint8_t pif,
		    sa_family_t af, const void *saddr, const void *daddr,
		    const struct pool *p, int idx, const struct timespec *now)
{
	struct mmsghdr mm[UIO_MAXIOV];
	struct iovec m[UIO_MAXIOV];
	struct sockaddr_in6 s_in6;
	struct sockaddr_in s_in;
	const struct udphdr *uh;
	struct sockaddr *sa;
	int i, s, count = 0;
	in_port_t src, dst;
	socklen_t sl;

	(void)saddr;
	(void)pif;

	ASSERT(!c->no_udp);

	uh = packet_get(p, idx, 0, sizeof(*uh), NULL);
	if (!uh)
		return 1;

	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	src = ntohs(uh->source);
	src += c->udp.fwd_in.rdelta[src];
	dst = ntohs(uh->dest);

	if (af == AF_INET) {
		s_in = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = uh->dest,
			.sin_addr = *(struct in_addr *)daddr,
		};

		sa = (struct sockaddr *)&s_in;
		sl = sizeof(s_in);

		if (IN4_ARE_ADDR_EQUAL(&s_in.sin_addr, &c->ip4.dns_match) &&
		    ntohs(s_in.sin_port) == 53) {
			s_in.sin_addr = c->ip4.dns_host;
			udp_tap_map[V4][src].ts = now->tv_sec;
			udp_tap_map[V4][src].flags |= PORT_DNS_FWD;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		} else if (IN4_ARE_ADDR_EQUAL(&s_in.sin_addr, &c->ip4.gw) &&
			   !c->no_map_gw) {
			if (!(udp_tap_map[V4][dst].flags & PORT_LOCAL) ||
			    (udp_tap_map[V4][dst].flags & PORT_LOOPBACK))
				s_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				s_in.sin_addr = c->ip4.addr_seen;
		}

		debug("UDP from tap src=%hu dst=%hu, s=%d",
		      src, dst, udp_tap_map[V4][src].sock);
		if ((s = udp_tap_map[V4][src].sock) < 0) {
			struct in_addr bind_addr = IN4ADDR_ANY_INIT;
			union udp_epoll_ref uref = {
				.port = src,
				.pif = PIF_HOST,
			};
			const char *bind_if = NULL;

			if (!IN4_IS_ADDR_LOOPBACK(&s_in.sin_addr))
				bind_if = c->ip4.ifname_out;

			if (!IN4_IS_ADDR_LOOPBACK(&s_in.sin_addr))
				bind_addr = c->ip4.addr_out;

			s = sock_l4(c, AF_INET, EPOLL_TYPE_UDP, &bind_addr,
				    bind_if, src, uref.u32);
			if (s < 0)
				return p->count - idx;

			udp_tap_map[V4][src].sock = s;
			bitmap_set(udp_act[V4][UDP_ACT_TAP], src);
		}

		udp_tap_map[V4][src].ts = now->tv_sec;
	} else {
		s_in6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = uh->dest,
			.sin6_addr = *(struct in6_addr *)daddr,
		};
		const struct in6_addr *bind_addr = &in6addr_any;

		sa = (struct sockaddr *)&s_in6;
		sl = sizeof(s_in6);

		if (IN6_ARE_ADDR_EQUAL(daddr, &c->ip6.dns_match) &&
		    ntohs(s_in6.sin6_port) == 53) {
			s_in6.sin6_addr = c->ip6.dns_host;
			udp_tap_map[V6][src].ts = now->tv_sec;
			udp_tap_map[V6][src].flags |= PORT_DNS_FWD;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		} else if (IN6_ARE_ADDR_EQUAL(daddr, &c->ip6.gw) &&
			   !c->no_map_gw) {
			if (!(udp_tap_map[V6][dst].flags & PORT_LOCAL) ||
			    (udp_tap_map[V6][dst].flags & PORT_LOOPBACK))
				s_in6.sin6_addr = in6addr_loopback;
			else if (udp_tap_map[V6][dst].flags & PORT_GUA)
				s_in6.sin6_addr = c->ip6.addr;
			else
				s_in6.sin6_addr = c->ip6.addr_seen;
		} else if (IN6_IS_ADDR_LINKLOCAL(&s_in6.sin6_addr)) {
			bind_addr = &c->ip6.addr_ll;
		}

		if ((s = udp_tap_map[V6][src].sock) < 0) {
			union udp_epoll_ref uref = {
				.v6 = 1,
				.port = src,
				.pif = PIF_HOST,
			};
			const char *bind_if = NULL;

			if (!IN6_IS_ADDR_LOOPBACK(&s_in6.sin6_addr))
				bind_if = c->ip6.ifname_out;

			if (!IN6_IS_ADDR_LOOPBACK(&s_in6.sin6_addr) &&
			    !IN6_IS_ADDR_LINKLOCAL(&s_in6.sin6_addr))
				bind_addr = &c->ip6.addr_out;

			s = sock_l4(c, AF_INET6, EPOLL_TYPE_UDP, bind_addr,
				    bind_if, src, uref.u32);
			if (s < 0)
				return p->count - idx;

			udp_tap_map[V6][src].sock = s;
			bitmap_set(udp_act[V6][UDP_ACT_TAP], src);
		}

		udp_tap_map[V6][src].ts = now->tv_sec;
	}

	for (i = 0; i < (int)p->count - idx; i++) {
		struct udphdr *uh_send;
		size_t len;

		uh_send = packet_get(p, idx + i, 0, sizeof(*uh), &len);
		if (!uh_send)
			return p->count - idx;

		mm[i].msg_hdr.msg_name = sa;
		mm[i].msg_hdr.msg_namelen = sl;

		if (len) {
			m[i].iov_base = (char *)(uh_send + 1);
			m[i].iov_len = len;

			mm[i].msg_hdr.msg_iov = m + i;
			mm[i].msg_hdr.msg_iovlen = 1;
		} else {
			mm[i].msg_hdr.msg_iov = NULL;
			mm[i].msg_hdr.msg_iovlen = 0;
		}

		mm[i].msg_hdr.msg_control = NULL;
		mm[i].msg_hdr.msg_controllen = 0;
		mm[i].msg_hdr.msg_flags = 0;

		count++;
	}

	count = sendmmsg(s, mm, count, MSG_NOSIGNAL);
	if (count < 0)
		return 1;

	return count;
}

/**
 * udp_sock_init() - Initialise listening sockets for a given port
 * @c:		Execution context
 * @ns:		In pasta mode, if set, bind with loopback address in namespace
 * @af:		Address family to select a specific IP version, or AF_UNSPEC
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on (partial) success, negative error code on (complete) failure
 */
int udp_sock_init(const struct ctx *c, int ns, sa_family_t af,
		  const void *addr, const char *ifname, in_port_t port)
{
	union udp_epoll_ref uref = { .splice = (c->mode == MODE_PASTA),
				     .orig = true, .port = port };
	int s, r4 = FD_REF_MAX + 1, r6 = FD_REF_MAX + 1;

	ASSERT(!c->no_udp);

	if (ns)
		uref.pif = PIF_SPLICE;
	else
		uref.pif = PIF_HOST;

	if ((af == AF_INET || af == AF_UNSPEC) && c->ifi4) {
		uref.v6 = 0;

		if (!ns) {
			r4 = s = sock_l4(c, AF_INET, EPOLL_TYPE_UDP, addr,
					 ifname, port, uref.u32);

			udp_tap_map[V4][port].sock = s < 0 ? -1 : s;
			udp_splice_init[V4][port].sock = s < 0 ? -1 : s;
		} else {
			r4 = s = sock_l4(c, AF_INET, EPOLL_TYPE_UDP,
					 &in4addr_loopback,
					 ifname, port, uref.u32);
			udp_splice_ns[V4][port].sock = s < 0 ? -1 : s;
		}
	}

	if ((af == AF_INET6 || af == AF_UNSPEC) && c->ifi6) {
		uref.v6 = 1;

		if (!ns) {
			r6 = s = sock_l4(c, AF_INET6, EPOLL_TYPE_UDP, addr,
					 ifname, port, uref.u32);

			udp_tap_map[V6][port].sock = s < 0 ? -1 : s;
			udp_splice_init[V6][port].sock = s < 0 ? -1 : s;
		} else {
			r6 = s = sock_l4(c, AF_INET6, EPOLL_TYPE_UDP,
					 &in6addr_loopback,
					 ifname, port, uref.u32);
			udp_splice_ns[V6][port].sock = s < 0 ? -1 : s;
		}
	}

	if (IN_INTERVAL(0, FD_REF_MAX, r4) || IN_INTERVAL(0, FD_REF_MAX, r6))
		return 0;

	return r4 < 0 ? r4 : r6;
}

/**
 * udp_splice_iov_init() - Set up buffers and descriptors for recvmmsg/sendmmsg
 */
static void udp_splice_iov_init(void)
{
	int i;

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		struct msghdr *mh = &udp_mh_splice[i].msg_hdr;

		mh->msg_name = &udp_splice_to;
		mh->msg_namelen = sizeof(udp_splice_to);

		udp_iov_splice[i].iov_base = udp_payload[i].data;

		mh->msg_iov = &udp_iov_splice[i];
		mh->msg_iovlen = 1;
	}
}

/**
 * udp_timer_one() - Handler for timed events on one port
 * @c:		Execution context
 * @v6:		Set for IPv6 connections
 * @type:	Socket type
 * @port:	Port number, host order
 * @now:	Current timestamp
 */
static void udp_timer_one(struct ctx *c, int v6, enum udp_act_type type,
			  in_port_t port, const struct timespec *now)
{
	struct udp_splice_port *sp;
	struct udp_tap_port *tp;
	int *sockp = NULL;

	switch (type) {
	case UDP_ACT_TAP:
		tp = &udp_tap_map[v6 ? V6 : V4][port];

		if (now->tv_sec - tp->ts > UDP_CONN_TIMEOUT) {
			sockp = &tp->sock;
			tp->flags = 0;
		}

		break;
	case UDP_ACT_SPLICE_INIT:
		sp = &udp_splice_init[v6 ? V6 : V4][port];

		if (now->tv_sec - sp->ts > UDP_CONN_TIMEOUT)
			sockp = &sp->sock;

		break;
	case UDP_ACT_SPLICE_NS:
		sp = &udp_splice_ns[v6 ? V6 : V4][port];

		if (now->tv_sec - sp->ts > UDP_CONN_TIMEOUT)
			sockp = &sp->sock;

		break;
	default:
		return;
	}

	if (sockp && *sockp >= 0) {
		int s = *sockp;
		*sockp = -1;
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, s, NULL);
		close(s);
		bitmap_clear(udp_act[v6 ? V6 : V4][type], port);
	}
}

/**
 * udp_port_rebind() - Rebind ports to match forward maps
 * @c:		Execution context
 * @outbound:	True to remap outbound forwards, otherwise inbound
 *
 * Must be called in namespace context if @outbound is true.
 */
static void udp_port_rebind(struct ctx *c, bool outbound)
{
	const uint8_t *fmap
		= outbound ? c->udp.fwd_out.f.map : c->udp.fwd_in.f.map;
	const uint8_t *rmap
		= outbound ? c->udp.fwd_in.f.map : c->udp.fwd_out.f.map;
	struct udp_splice_port (*socks)[NUM_PORTS]
		= outbound ? udp_splice_ns : udp_splice_init;
	unsigned port;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(fmap, port)) {
			if (socks[V4][port].sock >= 0) {
				close(socks[V4][port].sock);
				socks[V4][port].sock = -1;
			}

			if (socks[V6][port].sock >= 0) {
				close(socks[V6][port].sock);
				socks[V6][port].sock = -1;
			}

			continue;
		}

		/* Don't loop back our own ports */
		if (bitmap_isset(rmap, port))
			continue;

		if ((c->ifi4 && socks[V4][port].sock == -1) ||
		    (c->ifi6 && socks[V6][port].sock == -1))
			udp_sock_init(c, outbound, AF_UNSPEC, NULL, NULL, port);
	}
}

/**
 * udp_port_rebind_outbound() - Rebind ports in namespace
 * @arg:	Execution context
 *
 * Called with NS_CALL()
 *
 * Return: 0
 */
static int udp_port_rebind_outbound(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	ns_enter(c);
	udp_port_rebind(c, true);

	return 0;
}

/**
 * udp_timer() - Scan activity bitmaps for ports with associated timed events
 * @c:		Execution context
 * @now:	Current timestamp
 */
void udp_timer(struct ctx *c, const struct timespec *now)
{
	int n, t, v6 = 0;
	unsigned int i;
	long *word, tmp;

	ASSERT(!c->no_udp);

	if (c->mode == MODE_PASTA) {
		if (c->udp.fwd_out.f.mode == FWD_AUTO) {
			fwd_scan_ports_udp(&c->udp.fwd_out.f, &c->udp.fwd_in.f,
					   &c->tcp.fwd_out, &c->tcp.fwd_in);
			NS_CALL(udp_port_rebind_outbound, c);
		}

		if (c->udp.fwd_in.f.mode == FWD_AUTO) {
			fwd_scan_ports_udp(&c->udp.fwd_in.f, &c->udp.fwd_out.f,
					   &c->tcp.fwd_in, &c->tcp.fwd_out);
			udp_port_rebind(c, false);
		}
	}

	if (!c->ifi4)
		v6 = 1;
v6:
	for (t = 0; t < UDP_ACT_TYPE_MAX; t++) {
		word = (long *)udp_act[v6 ? V6 : V4][t];
		for (i = 0; i < ARRAY_SIZE(udp_act[0][0]);
		     i += sizeof(long), word++) {
			tmp = *word;
			while ((n = ffsl(tmp))) {
				tmp &= ~(1UL << (n - 1));
				udp_timer_one(c, v6, t, i * 8 + n - 1, now);
			}
		}
	}

	if (!v6 && c->ifi6) {
		v6 = 1;
		goto v6;
	}
}

/**
 * udp_init() - Initialise per-socket data, and sockets in namespace
 * @c:		Execution context
 *
 * Return: 0
 */
int udp_init(struct ctx *c)
{
	ASSERT(!c->no_udp);

	udp_iov_init(c);

	udp_invert_portmap(&c->udp.fwd_in);
	udp_invert_portmap(&c->udp.fwd_out);

	if (c->mode == MODE_PASTA) {
		udp_splice_iov_init();
		NS_CALL(udp_port_rebind_outbound, c);
	}

	return 0;
}
