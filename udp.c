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

#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */

/* "Spliced" sockets indexed by bound port (host order) */
static int udp_splice_ns  [IP_VERSIONS][NUM_PORTS];
static int udp_splice_init[IP_VERSIONS][NUM_PORTS];

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
	UDP_IOV_TAP,
	UDP_IOV_ETH,
	UDP_IOV_IP,
	UDP_IOV_PAYLOAD,
	UDP_NUM_IOVS,
};

/* IOVs and msghdr arrays for receiving datagrams from sockets */
static struct iovec	udp_iov_recv		[UDP_MAX_FRAMES];
static struct mmsghdr	udp_mh_recv		[UDP_MAX_FRAMES];

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
		udp_splice_ns[V4][i] = udp_splice_ns[V6][i] = -1;
		udp_splice_init[V4][i] = udp_splice_init[V6][i] = -1;
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
	struct msghdr *mh = &udp_mh_recv[i].msg_hdr;
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

	mh->msg_name	= &meta->s_in;
	mh->msg_namelen	= sizeof(meta->s_in);
	mh->msg_iov	= siov;
	mh->msg_iovlen	= 1;
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
 * @ip4h:		Pre-filled IPv4 header (except for tot_len and saddr)
 * @bp:			Pointer to udp_payload_t to update
 * @toside:		Flowside for destination side
 * @dlen:		Length of UDP payload
 * @no_udp_csum:	Do not set UDP checksum
 *
 * Return: size of IPv4 payload (UDP header + data)
 */
static size_t udp_update_hdr4(struct iphdr *ip4h, struct udp_payload_t *bp,
			      const struct flowside *toside, size_t dlen,
			      bool no_udp_csum)
{
	const struct in_addr *src = inany_v4(&toside->oaddr);
	const struct in_addr *dst = inany_v4(&toside->eaddr);
	size_t l4len = dlen + sizeof(bp->uh);
	size_t l3len = l4len + sizeof(*ip4h);

	ASSERT(src && dst);

	ip4h->tot_len = htons(l3len);
	ip4h->daddr = dst->s_addr;
	ip4h->saddr = src->s_addr;
	ip4h->check = csum_ip4_header(l3len, IPPROTO_UDP, *src, *dst);

	bp->uh.source = htons(toside->oport);
	bp->uh.dest = htons(toside->eport);
	bp->uh.len = htons(l4len);
	if (no_udp_csum) {
		bp->uh.check = 0;
	} else {
		const struct iovec iov = {
			.iov_base = bp->data,
			.iov_len = dlen
		};
		csum_udp4(&bp->uh, *src, *dst, &iov, 1, 0);
	}

	return l4len;
}

/**
 * udp_update_hdr6() - Update headers for one IPv6 datagram
 * @ip6h:		Pre-filled IPv6 header (except for payload_len and
 * 			addresses)
 * @bp:			Pointer to udp_payload_t to update
 * @toside:		Flowside for destination side
 * @dlen:		Length of UDP payload
 * @no_udp_csum:	Do not set UDP checksum
 *
 * Return: size of IPv6 payload (UDP header + data)
 */
static size_t udp_update_hdr6(struct ipv6hdr *ip6h, struct udp_payload_t *bp,
			      const struct flowside *toside, size_t dlen,
			      bool no_udp_csum)
{
	uint16_t l4len = dlen + sizeof(bp->uh);

	ip6h->payload_len = htons(l4len);
	ip6h->daddr = toside->eaddr.a6;
	ip6h->saddr = toside->oaddr.a6;
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 255;

	bp->uh.source = htons(toside->oport);
	bp->uh.dest = htons(toside->eport);
	bp->uh.len = ip6h->payload_len;
	if (no_udp_csum) {
		/* 0 is an invalid checksum for UDP IPv6 and dropped by
		 * the kernel stack, even if the checksum is disabled by virtio
		 * flags. We need to put any non-zero value here.
		 */
		bp->uh.check = 0xffff;
	} else {
		const struct iovec iov = {
			.iov_base = bp->data,
			.iov_len = dlen
		};
		csum_udp6(&bp->uh, &toside->oaddr.a6, &toside->eaddr.a6,
			  &iov, 1, 0);
	}

	return l4len;
}

/**
 * udp_tap_prepare() - Convert one datagram into a tap frame
 * @mmh:	Receiving mmsghdr array
 * @idx:	Index of the datagram to prepare
 * @toside:	Flowside for destination side
 * @no_udp_csum: Do not set UDP checksum
 */
static void udp_tap_prepare(const struct mmsghdr *mmh,
			    unsigned idx, const struct flowside *toside,
			    bool no_udp_csum)
{
	struct iovec (*tap_iov)[UDP_NUM_IOVS] = &udp_l2_iov[idx];
	struct udp_payload_t *bp = &udp_payload[idx];
	struct udp_meta_t *bm = &udp_meta[idx];
	size_t l4len;

	if (!inany_v4(&toside->eaddr) || !inany_v4(&toside->oaddr)) {
		l4len = udp_update_hdr6(&bm->ip6h, bp, toside,
					mmh[idx].msg_len, no_udp_csum);
		tap_hdr_update(&bm->taph, l4len + sizeof(bm->ip6h) +
			       sizeof(udp6_eth_hdr));
		(*tap_iov)[UDP_IOV_ETH] = IOV_OF_LVALUE(udp6_eth_hdr);
		(*tap_iov)[UDP_IOV_IP] = IOV_OF_LVALUE(bm->ip6h);
	} else {
		l4len = udp_update_hdr4(&bm->ip4h, bp, toside,
					mmh[idx].msg_len, no_udp_csum);
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
 * Return: 1 if error received and processed, 0 if no more errors in queue, < 0
 *         if there was an error reading the queue
 *
 * #syscalls recvmsg
 */
static int udp_sock_recverr(int s)
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
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		err_perror("UDP: Failed to read error queue");
		return -1;
	}

	if (!(mh.msg_flags & MSG_ERRQUEUE)) {
		err("Missing MSG_ERRQUEUE flag reading error queue");
		return -1;
	}

	hdr = CMSG_FIRSTHDR(&mh);
	if (!((hdr->cmsg_level == IPPROTO_IP &&
	       hdr->cmsg_type == IP_RECVERR) ||
	      (hdr->cmsg_level == IPPROTO_IPV6 &&
	       hdr->cmsg_type == IPV6_RECVERR))) {
		err("Unexpected cmsg reading error queue");
		return -1;
	}

	ee = (const struct sock_extended_err *)CMSG_DATA(hdr);

	/* TODO: When possible propagate and otherwise handle errors */
	debug("%s error on UDP socket %i: %s",
	      str_ee_origin(ee), s, strerror(ee->ee_errno));

	return 1;
}

/**
 * udp_sock_errs() - Process errors on a socket
 * @c:		Execution context
 * @s:		Socket to receive from
 * @events:	epoll events bitmap
 *
 * Return: Number of errors handled, or < 0 if we have an unrecoverable error
 */
static int udp_sock_errs(const struct ctx *c, int s, uint32_t events)
{
	unsigned n_err = 0;
	socklen_t errlen;
	int rc, err;

	ASSERT(!c->no_udp);

	if (!(events & EPOLLERR))
		return 0; /* Nothing to do */

	/* Empty the error queue */
	while ((rc = udp_sock_recverr(s)) > 0)
		n_err += rc;

	if (rc < 0)
		return -1; /* error reading error, unrecoverable */

	errlen = sizeof(err);
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 ||
	    errlen != sizeof(err)) {
		err_perror("Error reading SO_ERROR");
		return -1;  /* error reading error, unrecoverable */
	}

	if (err) {
		debug("Unqueued error on UDP socket %i: %s", s, strerror(err));
		n_err++;
	}

	if (!n_err) {
		/* EPOLLERR, but no errors to clear !? */
		err("EPOLLERR event without reported errors on socket %i", s);
		return -1; /* no way to clear, unrecoverable */
	}

	return n_err;
}

/**
 * udp_sock_recv() - Receive datagrams from a socket
 * @c:		Execution context
 * @s:		Socket to receive from
 * @events:	epoll events bitmap
 * @mmh		mmsghdr array to receive into
 *
 * Return: Number of datagrams received
 *
 * #syscalls recvmmsg arm:recvmmsg_time64 i686:recvmmsg_time64
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
 * udp_listen_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 *
 * #syscalls recvmmsg
 */
void udp_listen_sock_handler(const struct ctx *c, union epoll_ref ref,
			     uint32_t events, const struct timespec *now)
{
	const socklen_t sasize = sizeof(udp_meta[0].s_in);
	int n, i;

	if (udp_sock_errs(c, ref.fd, events) < 0) {
		err("UDP: Unrecoverable error on listening socket:"
		    " (%s port %hu)", pif_name(ref.udp.pif), ref.udp.port);
		/* FIXME: what now?  close/re-open socket? */
		return;
	}

	if ((n = udp_sock_recv(c, ref.fd, events, udp_mh_recv)) <= 0)
		return;

	/* We divide datagrams into batches based on how we need to send them,
	 * determined by udp_meta[i].tosidx.  To avoid either two passes through
	 * the array, or recalculating tosidx for a single entry, we have to
	 * populate it one entry *ahead* of the loop counter.
	 */
	udp_meta[0].tosidx = udp_flow_from_sock(c, ref, &udp_meta[0].s_in, now);
	udp_mh_recv[0].msg_hdr.msg_namelen = sasize;
	for (i = 0; i < n; ) {
		flow_sidx_t batchsidx = udp_meta[i].tosidx;
		uint8_t batchpif = pif_at_sidx(batchsidx);
		int batchstart = i;

		do {
			if (pif_is_socket(batchpif)) {
				udp_splice_prepare(udp_mh_recv, i);
			} else if (batchpif == PIF_TAP) {
				udp_tap_prepare(udp_mh_recv, i,
						flowside_at_sidx(batchsidx),
						false);
			}

			if (++i >= n)
				break;

			udp_meta[i].tosidx = udp_flow_from_sock(c, ref,
								&udp_meta[i].s_in,
								now);
			udp_mh_recv[i].msg_hdr.msg_namelen = sasize;
		} while (flow_sidx_eq(udp_meta[i].tosidx, batchsidx));

		if (pif_is_socket(batchpif)) {
			udp_splice_send(c, batchstart, i - batchstart,
					batchsidx);
		} else if (batchpif == PIF_TAP) {
			tap_send_frames(c, &udp_l2_iov[batchstart][0],
					UDP_NUM_IOVS, i - batchstart);
		} else if (flow_sidx_valid(batchsidx)) {
			flow_sidx_t fromsidx = flow_sidx_opposite(batchsidx);
			struct udp_flow *uflow = udp_at_sidx(batchsidx);

			flow_err(uflow,
				 "No support for forwarding UDP from %s to %s",
				 pif_name(pif_at_sidx(fromsidx)),
				 pif_name(batchpif));
		} else {
			debug("Discarding %d datagrams without flow",
			      i - batchstart);
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
	flow_sidx_t tosidx = flow_sidx_opposite(ref.flowside);
	const struct flowside *toside = flowside_at_sidx(tosidx);
	struct udp_flow *uflow = udp_at_sidx(ref.flowside);
	uint8_t topif = pif_at_sidx(tosidx);
	int n, i, from_s;

	ASSERT(!c->no_udp && uflow);

	from_s = uflow->s[ref.flowside.sidei];

	if (udp_sock_errs(c, from_s, events) < 0) {
		flow_err(uflow, "Unrecoverable error on reply socket");
		flow_err_details(uflow);
		udp_flow_close(c, uflow);
		return;
	}

	if ((n = udp_sock_recv(c, from_s, events, udp_mh_recv)) <= 0)
		return;

	flow_trace(uflow, "Received %d datagrams on reply socket", n);
	uflow->ts = now->tv_sec;

	for (i = 0; i < n; i++) {
		if (pif_is_socket(topif))
			udp_splice_prepare(udp_mh_recv, i);
		else if (topif == PIF_TAP)
			udp_tap_prepare(udp_mh_recv, i, toside, false);
		/* Restore sockaddr length clobbered by recvmsg() */
		udp_mh_recv[i].msg_hdr.msg_namelen = sizeof(udp_meta[i].s_in);
	}

	if (pif_is_socket(topif)) {
		udp_splice_send(c, 0, n, tosidx);
	} else if (topif == PIF_TAP) {
		tap_send_frames(c, &udp_l2_iov[0][0], UDP_NUM_IOVS, n);
	} else {
		uint8_t frompif = pif_at_sidx(ref.flowside);

		flow_err(uflow, "No support for forwarding UDP from %s to %s",
			 pif_name(frompif), pif_name(topif));
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
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on (partial) success, negative error code on (complete) failure
 */
int udp_sock_init(const struct ctx *c, int ns, const union inany_addr *addr,
		  const char *ifname, in_port_t port)
{
	union udp_listen_epoll_ref uref = {
		.pif = ns ? PIF_SPLICE : PIF_HOST,
		.port = port,
	};
	int r4 = FD_REF_MAX + 1, r6 = FD_REF_MAX + 1;

	ASSERT(!c->no_udp);

	if (!addr && c->ifi4 && c->ifi6 && !ns) {
		int s;

		/* Attempt to get a dual stack socket */
		s = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, PIF_HOST,
				NULL, ifname, port, uref.u32);
		udp_splice_init[V4][port] = s < 0 ? -1 : s;
		udp_splice_init[V6][port] = s < 0 ? -1 : s;
		if (IN_INTERVAL(0, FD_REF_MAX, s))
			return 0;
	}

	if ((!addr || inany_v4(addr)) && c->ifi4) {
		if (!ns) {
			r4 = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, PIF_HOST,
					 addr ? addr : &inany_any4, ifname,
					 port, uref.u32);

			udp_splice_init[V4][port] = r4 < 0 ? -1 : r4;
		} else {
			r4  = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, PIF_SPLICE,
					  &inany_loopback4, ifname,
					  port, uref.u32);
			udp_splice_ns[V4][port] = r4 < 0 ? -1 : r4;
		}
	}

	if ((!addr || !inany_v4(addr)) && c->ifi6) {
		if (!ns) {
			r6 = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, PIF_HOST,
					 addr ? addr : &inany_any6, ifname,
					 port, uref.u32);

			udp_splice_init[V6][port] = r6 < 0 ? -1 : r6;
		} else {
			r6 = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, PIF_SPLICE,
					 &inany_loopback6, ifname,
					 port, uref.u32);
			udp_splice_ns[V6][port] = r6 < 0 ? -1 : r6;
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
		= outbound ? c->udp.fwd_out.map : c->udp.fwd_in.map;
	const uint8_t *rmap
		= outbound ? c->udp.fwd_in.map : c->udp.fwd_out.map;
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
			udp_sock_init(c, outbound, NULL, NULL, port);
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
	(void)now;

	ASSERT(!c->no_udp);

	if (c->mode == MODE_PASTA) {
		if (c->udp.fwd_out.mode == FWD_AUTO) {
			fwd_scan_ports_udp(&c->udp.fwd_out, &c->udp.fwd_in,
					   &c->tcp.fwd_out, &c->tcp.fwd_in);
			NS_CALL(udp_port_rebind_outbound, c);
		}

		if (c->udp.fwd_in.mode == FWD_AUTO) {
			fwd_scan_ports_udp(&c->udp.fwd_in, &c->udp.fwd_out,
					   &c->tcp.fwd_in, &c->tcp.fwd_out);
			udp_port_rebind(c, false);
		}
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

	if (c->mode == MODE_PASTA) {
		udp_splice_iov_init();
		NS_CALL(udp_port_rebind_outbound, c);
	}

	return 0;
}
