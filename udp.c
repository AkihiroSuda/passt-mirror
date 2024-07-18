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
 * UDP Flows
 * =========
 *
 * UDP doesn't have true connections, but many protocols use a connection-like
 * format.  The flow is initiated by a client sending a datagram from a port of
 * its choosing (usually ephemeral) to a specific port (usually well known) on a
 * server.  Both client and server address must be unicast.  The server sends
 * replies using the same addresses & ports with src/dest swapped.
 *
 * We track pseudo-connections of this type as flow table entries of type
 * FLOW_UDP.  We store the time of the last traffic on the flow in uflow->ts,
 * and let the flow expire if there is no traffic for UDP_CONN_TIMEOUT seconds.
 *
 * NOTE: This won't handle multicast protocols, or some protocols with different
 * port usage.  We'll need specific logic if we want to handle those.
 *
 * "Listening" sockets
 * ===================
 *
 * UDP doesn't use listen(), but we consider long term sockets which are allowed
 * to create new flows "listening" by analogy with TCP. This listening socket
 * could receive packets from multiple flows, so we use a hash table match to
 * find the specific flow for a datagram.
 *
 * When a UDP flow is initiated from a listening socket we take a duplicate of
 * the socket and store it in uflow->s[INISIDE].  This will last for the
 * lifetime of the flow, even if the original listening socket is closed due to
 * port auto-probing.  The duplicate is used to deliver replies back to the
 * originating side.
 *
 * Reply sockets
 * =============
 *
 * When a UDP flow targets a socket, we create a "reply" socket in
 * uflow->s[TGTSIDE] both to deliver datagrams to the target side and receive
 * replies on the target side.  This socket is both bound and connected and has
 * EPOLL_TYPE_UDP_REPLY.  The connect() means it will only receive datagrams
 * associated with this flow, so the epoll reference directly points to the flow
 * and we don't need a hash lookup.
 *
 * NOTE: it's possible that the reply socket could have a bound address
 * overlapping with an unrelated listening socket.  We assume datagrams for the
 * flow will come to the reply socket in preference to a listening socket.  The
 * sample program doc/platform-requirements/reuseaddr-priority.c documents and
 * tests that assumption.
 *
 * "Spliced" flows
 * ===============
 *
 * In PASTA mode, L2-L4 translation is skipped for connections to ports bound
 * between namespaces using the loopback interface, messages are directly
 * transferred between L4 sockets instead. These are called spliced connections
 * in analogy with the TCP implementation.  The the splice() syscall isn't
 * actually used; it doesn't make sense for datagrams and instead a pair of
 * recvmmsg() and sendmmsg() is used to forward the datagrams.
 *
 * Note that a spliced flow will have *both* a duplicated listening socket and a
 * reply socket (see above).
 *
 * Port tracking
 * =============
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
#include <fcntl.h>
#include <arpa/inet.h>
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
#include "flow_table.h"

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

/* Port tracking, arrays indexed by packet source port (host order) */
static struct udp_tap_port	udp_tap_map	[IP_VERSIONS][NUM_PORTS];

/* "Spliced" sockets indexed by bound port (host order) */
static int udp_splice_ns  [IP_VERSIONS][NUM_PORTS];
static int udp_splice_init[IP_VERSIONS][NUM_PORTS];

enum udp_act_type {
	UDP_ACT_TAP,
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
 * @tosidx:	sidx for the destination side of this datagram's flow
 */
static struct udp_meta_t {
	struct ipv6hdr ip6h;
	struct iphdr ip4h;
	struct tap_hdr taph;

	union sockaddr_inany s_in;
	flow_sidx_t tosidx;
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
		udp_splice_ns[V4][i] = udp_splice_ns[V6][i] = -1;
		udp_splice_init[V4][i] = udp_splice_init[V6][i] = -1;
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
 * udp_at_sidx() - Get UDP specific flow at given sidx
 * @sidx:    Flow and side to retrieve
 *
 * Return: UDP specific flow at @sidx, or NULL of @sidx is invalid.  Asserts if
 *         the flow at @sidx is not FLOW_UDP.
 */
struct udp_flow *udp_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_UDP);
	return &flow->udp;
}

/*
 * udp_flow_close() - Close and clean up UDP flow
 * @c:		Execution context
 * @uflow:	UDP flow
 */
static void udp_flow_close(const struct ctx *c, struct udp_flow *uflow)
{
	if (uflow->s[INISIDE] >= 0) {
		/* The listening socket needs to stay in epoll */
		close(uflow->s[INISIDE]);
		uflow->s[INISIDE] = -1;
	}

	if (uflow->s[TGTSIDE] >= 0) {
		/* But the flow specific one needs to be removed */
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, uflow->s[TGTSIDE], NULL);
		close(uflow->s[TGTSIDE]);
		uflow->s[TGTSIDE] = -1;
	}
	flow_hash_remove(c, FLOW_SIDX(uflow, INISIDE));
	if (!pif_is_socket(uflow->f.pif[TGTSIDE]))
		flow_hash_remove(c, FLOW_SIDX(uflow, TGTSIDE));
}

/**
 * udp_flow_new() - Common setup for a new UDP flow
 * @c:		Execution context
 * @flow:	Initiated flow
 * @s_ini:	Initiating socket (or -1)
 * @now:	Timestamp
 *
 * Return: UDP specific flow, if successful, NULL on failure
 */
static flow_sidx_t udp_flow_new(const struct ctx *c, union flow *flow,
				int s_ini, const struct timespec *now)
{
	const struct flowside *ini = &flow->f.side[INISIDE];
	struct udp_flow *uflow = NULL;
	const struct flowside *tgt;
	uint8_t tgtpif;

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0) {
		flow_trace(flow, "Invalid endpoint to initiate UDP flow");
		goto cancel;
	}

	if (!(tgt = flow_target(c, flow, IPPROTO_UDP)))
		goto cancel;
	tgtpif = flow->f.pif[TGTSIDE];

	uflow = FLOW_SET_TYPE(flow, FLOW_UDP, udp);
	uflow->ts = now->tv_sec;
	uflow->s[INISIDE] = uflow->s[TGTSIDE] = -1;

	if (s_ini >= 0) {
		/* When using auto port-scanning the listening port could go
		 * away, so we need to duplicate the socket
		 */
		uflow->s[INISIDE] = fcntl(s_ini, F_DUPFD_CLOEXEC, 0);
		if (uflow->s[INISIDE] < 0) {
			flow_err(uflow,
				 "Couldn't duplicate listening socket: %s",
				 strerror(errno));
			goto cancel;
		}
	}

	if (pif_is_socket(tgtpif)) {
		struct mmsghdr discard[UIO_MAXIOV] = { 0 };
		union {
			flow_sidx_t sidx;
			uint32_t data;
		} fref = {
			.sidx = FLOW_SIDX(flow, TGTSIDE),
		};
		int rc;

		uflow->s[TGTSIDE] = flowside_sock_l4(c, EPOLL_TYPE_UDP_REPLY,
						     tgtpif, tgt, fref.data);
		if (uflow->s[TGTSIDE] < 0) {
			flow_dbg(uflow,
				 "Couldn't open socket for spliced flow: %s",
				 strerror(errno));
			goto cancel;
		}

		if (flowside_connect(c, uflow->s[TGTSIDE], tgtpif, tgt) < 0) {
			flow_dbg(uflow,
				 "Couldn't connect flow socket: %s",
				 strerror(errno));
			goto cancel;
		}

		/* It's possible, if unlikely, that we could receive some
		 * unrelated packets in between the bind() and connect() of this
		 * socket.  For now we just discard these.  We could consider
		 * trying to redirect these to an appropriate handler, if we
		 * need to.
		 */
		rc = recvmmsg(uflow->s[TGTSIDE], discard, ARRAY_SIZE(discard),
			      MSG_DONTWAIT, NULL);
		if (rc >= ARRAY_SIZE(discard)) {
			flow_dbg(uflow,
				 "Too many (%d) spurious reply datagrams", rc);
			goto cancel;
		} else if (rc > 0) {
			flow_trace(uflow,
				   "Discarded %d spurious reply datagrams", rc);
		} else if (errno != EAGAIN) {
			flow_err(uflow,
				 "Unexpected error discarding datagrams: %s",
				 strerror(errno));
		}
	}

	flow_hash_insert(c, FLOW_SIDX(uflow, INISIDE));

	/* If the target side is a socket, it will be a reply socket that knows
	 * its own flowside.  But if it's tap, then we need to look it up by
	 * hash.
	 */
	if (!pif_is_socket(tgtpif))
		flow_hash_insert(c, FLOW_SIDX(uflow, TGTSIDE));
	FLOW_ACTIVATE(uflow);

	return FLOW_SIDX(uflow, TGTSIDE);

cancel:
	if (uflow)
		udp_flow_close(c, uflow);
	flow_alloc_cancel(flow);
	return FLOW_SIDX_NONE;
}

/**
 * udp_flow_from_sock() - Find or create UDP flow for "listening" socket
 * @c:		Execution context
 * @ref:	epoll reference of the receiving socket
 * @meta:	Metadata buffer for the datagram
 * @now:	Timestamp
 *
 * #syscalls fcntl
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
static flow_sidx_t udp_flow_from_sock(const struct ctx *c, union epoll_ref ref,
				      struct udp_meta_t *meta,
				      const struct timespec *now)
{
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(ref.type == EPOLL_TYPE_UDP);

	/* FIXME: Match reply packets to their flow as well */
	if (!ref.udp.orig)
		return FLOW_SIDX_NONE;

	sidx = flow_lookup_sa(c, IPPROTO_UDP, ref.udp.pif, &meta->s_in, ref.udp.port);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sastr[SOCKADDR_STRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s",
		      pif_name(ref.udp.pif),
		      sockaddr_ntop(&meta->s_in, sastr, sizeof(sastr)));
		return FLOW_SIDX_NONE;
	}

	flow_initiate_sa(flow, ref.udp.pif, &meta->s_in, ref.udp.port);
	return udp_flow_new(c, flow, ref.fd, now);
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
			    flow_sidx_t tosidx)
{
	const struct flowside *toside = flowside_at_sidx(tosidx);
	const struct udp_flow *uflow = udp_at_sidx(tosidx);
	uint8_t topif = pif_at_sidx(tosidx);
	int s = uflow->s[tosidx.sidei];
	socklen_t sl;

	pif_sockaddr(c, &udp_splice_to, &sl, topif,
		     &toside->eaddr, toside->eport);

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
	 * determined by udp_meta[i].tosidx.  To avoid either two passes through
	 * the array, or recalculating tosidx for a single entry, we have to
	 * populate it one entry *ahead* of the loop counter.
	 */
	udp_meta[0].tosidx = udp_flow_from_sock(c, ref, &udp_meta[0], now);
	for (i = 0; i < n; ) {
		flow_sidx_t batchsidx = udp_meta[i].tosidx;
		uint8_t batchpif = pif_at_sidx(batchsidx);
		int batchstart = i;

		do {
			if (pif_is_socket(batchpif)) {
				udp_splice_prepare(mmh_recv, i);
			} else {
				udp_tap_prepare(c, mmh_recv, i, dstport,
						ref.udp.v6, now);
			}

			if (++i >= n)
				break;

			udp_meta[i].tosidx = udp_flow_from_sock(c, ref,
								&udp_meta[i],
								now);
		} while (flow_sidx_eq(udp_meta[i].tosidx, batchsidx));

		if (pif_is_socket(batchpif)) {
			udp_splice_send(c, batchstart, i - batchstart,
					batchsidx);
		} else {
			tap_send_frames(c, &udp_l2_iov[batchstart][0],
					UDP_NUM_IOVS, i - batchstart);
		}
	}
}

/**
 * udp_reply_sock_handler() - Handle new data from flow specific socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 *
 * #syscalls recvmmsg
 */
void udp_reply_sock_handler(const struct ctx *c, union epoll_ref ref,
			    uint32_t events, const struct timespec *now)
{
	const struct flowside *fromside = flowside_at_sidx(ref.flowside);
	flow_sidx_t tosidx = flow_sidx_opposite(ref.flowside);
	const struct flowside *toside = flowside_at_sidx(tosidx);
	struct udp_flow *uflow = udp_at_sidx(ref.flowside);
	int from_s = uflow->s[ref.flowside.sidei];
	bool v6 = !inany_v4(&fromside->eaddr);
	struct mmsghdr *mmh_recv = v6 ? udp6_mh_recv : udp4_mh_recv;
	uint8_t topif = pif_at_sidx(tosidx);
	int n, i;

	ASSERT(!c->no_udp && uflow);

	if ((n = udp_sock_recv(c, from_s, events, mmh_recv)) <= 0)
		return;

	flow_trace(uflow, "Received %d datagrams on reply socket", n);
	uflow->ts = now->tv_sec;

	for (i = 0; i < n; i++) {
		if (pif_is_socket(topif))
			udp_splice_prepare(mmh_recv, i);
		else
			udp_tap_prepare(c, mmh_recv, i, toside->eport, v6, now);
	}

	if (pif_is_socket(topif))
		udp_splice_send(c, 0, n, tosidx);
	else
		tap_send_frames(c, &udp_l2_iov[0][0], UDP_NUM_IOVS, n);
}

/**
 * udp_flow_from_tap() - Find or create UDP flow for tap packets
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address on guest side
 * @daddr:	Destination address guest side
 * @srcport:	Source port on guest side
 * @dstport:	Destination port on guest side
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
static flow_sidx_t udp_flow_from_tap(const struct ctx *c,
				     uint8_t pif, sa_family_t af,
				     const void *saddr, const void *daddr,
				     in_port_t srcport, in_port_t dstport,
				     const struct timespec *now)
{
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(pif == PIF_TAP);

	sidx = flow_lookup_af(c, IPPROTO_UDP, pif, af, saddr, daddr,
			      srcport, dstport);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s:%hu -> %s:%hu",
		      pif_name(pif),
		      inet_ntop(af, saddr, sstr, sizeof(sstr)), srcport,
		      inet_ntop(af, daddr, dstr, sizeof(dstr)), dstport);
		return FLOW_SIDX_NONE;
	}

	flow_initiate_af(flow, PIF_TAP, af, saddr, srcport, daddr, dstport);

	return udp_flow_new(c, flow, -1, now);
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
int udp_tap_handler(const struct ctx *c, uint8_t pif,
		    sa_family_t af, const void *saddr, const void *daddr,
		    const struct pool *p, int idx, const struct timespec *now)
{
	const struct flowside *toside;
	struct mmsghdr mm[UIO_MAXIOV];
	union sockaddr_inany to_sa;
	struct iovec m[UIO_MAXIOV];
	const struct udphdr *uh;
	struct udp_flow *uflow;
	int i, s, count = 0;
	flow_sidx_t tosidx;
	in_port_t src, dst;
	uint8_t topif;
	socklen_t sl;

	ASSERT(!c->no_udp);

	uh = packet_get(p, idx, 0, sizeof(*uh), NULL);
	if (!uh)
		return 1;

	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	src = ntohs(uh->source);
	dst = ntohs(uh->dest);

	tosidx = udp_flow_from_tap(c, pif, af, saddr, daddr, src, dst, now);
	if (!(uflow = udp_at_sidx(tosidx))) {
		char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

		debug("Dropping datagram with no flow %s %s:%hu -> %s:%hu",
		      pif_name(pif),
		      inet_ntop(af, saddr, sstr, sizeof(sstr)), src,
		      inet_ntop(af, daddr, dstr, sizeof(dstr)), dst);
		return 1;
	}

	topif = pif_at_sidx(tosidx);
	if (topif != PIF_HOST) {
		flow_sidx_t fromsidx = flow_sidx_opposite(tosidx);
		uint8_t frompif = pif_at_sidx(fromsidx);

		flow_err(uflow, "No support for forwarding UDP from %s to %s",
			 pif_name(frompif), pif_name(topif));
		return 1;
	}
	toside = flowside_at_sidx(tosidx);

	s = udp_at_sidx(tosidx)->s[tosidx.sidei];
	ASSERT(s >= 0);

	pif_sockaddr(c, &to_sa, &sl, topif, &toside->eaddr, toside->eport);

	for (i = 0; i < (int)p->count - idx; i++) {
		struct udphdr *uh_send;
		size_t len;

		uh_send = packet_get(p, idx + i, 0, sizeof(*uh), &len);
		if (!uh_send)
			return p->count - idx;

		mm[i].msg_hdr.msg_name = &to_sa;
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
	union udp_epoll_ref uref = { .orig = true, .port = port };
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
			udp_splice_init[V4][port] = s < 0 ? -1 : s;
		} else {
			r4 = s = sock_l4(c, AF_INET, EPOLL_TYPE_UDP,
					 &in4addr_loopback,
					 ifname, port, uref.u32);
			udp_splice_ns[V4][port] = s < 0 ? -1 : s;
		}
	}

	if ((af == AF_INET6 || af == AF_UNSPEC) && c->ifi6) {
		uref.v6 = 1;

		if (!ns) {
			r6 = s = sock_l4(c, AF_INET6, EPOLL_TYPE_UDP, addr,
					 ifname, port, uref.u32);

			udp_tap_map[V6][port].sock = s < 0 ? -1 : s;
			udp_splice_init[V6][port] = s < 0 ? -1 : s;
		} else {
			r6 = s = sock_l4(c, AF_INET6, EPOLL_TYPE_UDP,
					 &in6addr_loopback,
					 ifname, port, uref.u32);
			udp_splice_ns[V6][port] = s < 0 ? -1 : s;
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
	int (*socks)[NUM_PORTS] = outbound ? udp_splice_ns : udp_splice_init;
	const uint8_t *fmap
		= outbound ? c->udp.fwd_out.f.map : c->udp.fwd_in.f.map;
	const uint8_t *rmap
		= outbound ? c->udp.fwd_in.f.map : c->udp.fwd_out.f.map;
	unsigned port;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(fmap, port)) {
			if (socks[V4][port] >= 0) {
				close(socks[V4][port]);
				socks[V4][port] = -1;
			}

			if (socks[V6][port] >= 0) {
				close(socks[V6][port]);
				socks[V6][port] = -1;
			}

			continue;
		}

		/* Don't loop back our own ports */
		if (bitmap_isset(rmap, port))
			continue;

		if ((c->ifi4 && socks[V4][port] == -1) ||
		    (c->ifi6 && socks[V6][port] == -1))
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
 * udp_flow_timer() - Handler for timed events related to a given flow
 * @c:		Execution context
 * @uflow:	UDP flow
 * @now:	Current timestamp
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool udp_flow_timer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now)
{
	if (now->tv_sec - uflow->ts <= UDP_CONN_TIMEOUT)
		return false;

	udp_flow_close(c, uflow);
	return true;
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
