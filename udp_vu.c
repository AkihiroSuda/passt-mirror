// SPDX-License-Identifier: GPL-2.0-or-later
/* udp_vu.c - UDP L2 vhost-user management functions
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#include <unistd.h>
#include <assert.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>
#include <linux/virtio_net.h>

#include "checksum.h"
#include "util.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "passt.h"
#include "pcap.h"
#include "log.h"
#include "vhost_user.h"
#include "udp_internal.h"
#include "flow.h"
#include "flow_table.h"
#include "udp_flow.h"
#include "udp_vu.h"
#include "vu_common.h"

static struct iovec     iov_vu		[VIRTQUEUE_MAX_SIZE];
static struct vu_virtq_element	elem		[VIRTQUEUE_MAX_SIZE];

/**
 * udp_vu_hdrlen() - return the size of the header in level 2 frame (UDP)
 * @v6:		Set for IPv6 packet
 *
 * Return: Return the size of the header
 */
static size_t udp_vu_hdrlen(bool v6)
{
	size_t hdrlen;

	hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf) +
		 sizeof(struct ethhdr) + sizeof(struct udphdr);

	if (v6)
		hdrlen += sizeof(struct ipv6hdr);
	else
		hdrlen += sizeof(struct iphdr);

	return hdrlen;
}

/**
 * udp_vu_sock_info() - get socket information
 * @s:		Socket to get information from
 * @s_in:	Socket address (output)
 *
 * Return: 0 if socket address can be read, -1 otherwise
 */
static int udp_vu_sock_info(int s, union sockaddr_inany *s_in)
{
	struct msghdr msg = {
		.msg_name = s_in,
		.msg_namelen = sizeof(union sockaddr_inany),
	};

	return recvmsg(s, &msg, MSG_PEEK | MSG_DONTWAIT);
}

/**
 * udp_vu_sock_recv() - Receive datagrams from socket into vhost-user buffers
 * @c:		Execution context
 * @s:		Socket to receive from
 * @events:	epoll events bitmap
 * @v6:		Set for IPv6 connections
 * @dlen:	Size of received data (output)
 *
 * Return: Number of iov entries used to store the datagram
 */
static int udp_vu_sock_recv(const struct ctx *c, int s, uint32_t events,
			    bool v6, ssize_t *dlen)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	int iov_cnt, idx, iov_used;
	struct msghdr msg  = { 0 };
	size_t off, hdrlen;

	ASSERT(!c->no_udp);

	if (!(events & EPOLLIN))
		return 0;

	/* compute L2 header length */
	hdrlen = udp_vu_hdrlen(v6);

	vu_init_elem(elem, iov_vu, VIRTQUEUE_MAX_SIZE);

	iov_cnt = vu_collect(vdev, vq, elem, VIRTQUEUE_MAX_SIZE,
			     IP_MAX_MTU - sizeof(struct udphdr) + hdrlen,
			     NULL);
	if (iov_cnt == 0)
		return 0;

	/* reserve space for the headers */
	ASSERT(iov_vu[0].iov_len >= hdrlen);
	iov_vu[0].iov_base = (char *)iov_vu[0].iov_base + hdrlen;
	iov_vu[0].iov_len -= hdrlen;

	/* read data from the socket */
	msg.msg_iov = iov_vu;
	msg.msg_iovlen = iov_cnt;

	*dlen = recvmsg(s, &msg, 0);
	if (*dlen < 0) {
		vu_queue_rewind(vq, iov_cnt);
		return 0;
	}

	/* restore the pointer to the headers address */
	iov_vu[0].iov_base = (char *)iov_vu[0].iov_base - hdrlen;
	iov_vu[0].iov_len += hdrlen;

	/* count the numbers of buffer filled by recvmsg() */
	idx = iov_skip_bytes(iov_vu, iov_cnt, *dlen + hdrlen, &off);

	/* adjust last iov length */
	if (idx < iov_cnt)
		iov_vu[idx].iov_len = off;
	iov_used = idx + !!off;

	vu_set_vnethdr(vdev, iov_vu[0].iov_base, iov_used);

	/* release unused buffers */
	vu_queue_rewind(vq, iov_cnt - iov_used);

	return iov_used;
}

/**
 * udp_vu_prepare() - Prepare the packet header
 * @c:		Execution context
 * @toside:	Address information for one side of the flow
 * @dlen:	Packet data length
 *
 * Return: Layer-4 length
 */
static size_t udp_vu_prepare(const struct ctx *c,
			     const struct flowside *toside, ssize_t dlen)
{
	struct ethhdr *eh;
	size_t l4len;

	/* ethernet header */
	eh = vu_eth(iov_vu[0].iov_base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	/* initialize header */
	if (inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr)) {
		struct iphdr *iph = vu_ip(iov_vu[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv4(iov_vu[0].iov_base);

		eh->h_proto = htons(ETH_P_IP);

		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_UDP);

		l4len = udp_update_hdr4(iph, bp, toside, dlen, true);
	} else {
		struct ipv6hdr *ip6h = vu_ip(iov_vu[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv6(iov_vu[0].iov_base);

		eh->h_proto = htons(ETH_P_IPV6);

		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_UDP);

		l4len = udp_update_hdr6(ip6h, bp, toside, dlen, true);
	}

	return l4len;
}

/**
 * udp_vu_csum() - Calculate and set checksum for a UDP packet
 * @toside:	Address information for one side of the flow
 * @iov_used:	Number of used iov_vu items
 */
static void udp_vu_csum(const struct flowside *toside, int iov_used)
{
	const struct in_addr *src4 = inany_v4(&toside->oaddr);
	const struct in_addr *dst4 = inany_v4(&toside->eaddr);
	char *base = iov_vu[0].iov_base;
	struct udp_payload_t *bp;
	struct iov_tail data;

	if (src4 && dst4) {
		bp = vu_payloadv4(base);
		data = IOV_TAIL(iov_vu, iov_used, (char *)&bp->data - base);
		csum_udp4(&bp->uh, *src4, *dst4, &data);
	} else {
		bp = vu_payloadv6(base);
		data = IOV_TAIL(iov_vu, iov_used, (char *)&bp->data - base);
		csum_udp6(&bp->uh, &toside->oaddr.a6, &toside->eaddr.a6, &data);
	}
}

/**
 * udp_vu_listen_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_vu_listen_sock_handler(const struct ctx *c, union epoll_ref ref,
				uint32_t events, const struct timespec *now)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	int i;

	if (udp_sock_errs(c, ref.fd, events) < 0) {
		err("UDP: Unrecoverable error on listening socket:"
		    " (%s port %hu)", pif_name(ref.udp.pif), ref.udp.port);
		return;
	}

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		const struct flowside *toside;
		union sockaddr_inany s_in;
		flow_sidx_t sidx;
		uint8_t pif;
		ssize_t dlen;
		int iov_used;
		bool v6;

		if (udp_vu_sock_info(ref.fd, &s_in) < 0)
			break;

		sidx = udp_flow_from_sock(c, ref, &s_in, now);
		pif = pif_at_sidx(sidx);

		if (pif != PIF_TAP) {
			if (flow_sidx_valid(sidx)) {
				flow_sidx_t fromsidx = flow_sidx_opposite(sidx);
				struct udp_flow *uflow = udp_at_sidx(sidx);

				flow_err(uflow,
					"No support for forwarding UDP from %s to %s",
					pif_name(pif_at_sidx(fromsidx)),
					pif_name(pif));
			} else {
				debug("Discarding 1 datagram without flow");
			}

			continue;
		}

		toside = flowside_at_sidx(sidx);

		v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));

		iov_used = udp_vu_sock_recv(c, ref.fd, events, v6, &dlen);
		if (iov_used <= 0)
			break;

		udp_vu_prepare(c, toside, dlen);
		if (*c->pcap) {
			udp_vu_csum(toside, iov_used);
			pcap_iov(iov_vu, iov_used,
				 sizeof(struct virtio_net_hdr_mrg_rxbuf));
		}
		vu_flush(vdev, vq, elem, iov_used);
	}
}

/**
 * udp_vu_reply_sock_handler() - Handle new data from flow specific socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_vu_reply_sock_handler(const struct ctx *c, union epoll_ref ref,
			        uint32_t events, const struct timespec *now)
{
	flow_sidx_t tosidx = flow_sidx_opposite(ref.flowside);
	const struct flowside *toside = flowside_at_sidx(tosidx);
	struct udp_flow *uflow = udp_at_sidx(ref.flowside);
	int from_s = uflow->s[ref.flowside.sidei];
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	int i;

	ASSERT(!c->no_udp);

	if (udp_sock_errs(c, from_s, events) < 0) {
		flow_err(uflow, "Unrecoverable error on reply socket");
		flow_err_details(uflow);
		udp_flow_close(c, uflow);
		return;
	}

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		uint8_t topif = pif_at_sidx(tosidx);
		ssize_t dlen;
		int iov_used;
		bool v6;

		ASSERT(uflow);

		if (topif != PIF_TAP) {
			uint8_t frompif = pif_at_sidx(ref.flowside);

			flow_err(uflow,
				 "No support for forwarding UDP from %s to %s",
				 pif_name(frompif), pif_name(topif));
			continue;
		}

		v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));

		iov_used = udp_vu_sock_recv(c, from_s, events, v6, &dlen);
		if (iov_used <= 0)
			break;
		flow_trace(uflow, "Received 1 datagram on reply socket");
		uflow->ts = now->tv_sec;

		udp_vu_prepare(c, toside, dlen);
		if (*c->pcap) {
			udp_vu_csum(toside, iov_used);
			pcap_iov(iov_vu, iov_used,
				 sizeof(struct virtio_net_hdr_mrg_rxbuf));
		}
		vu_flush(vdev, vq, elem, iov_used);
	}
}
