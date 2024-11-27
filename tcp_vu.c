// SPDX-License-Identifier: GPL-2.0-or-later
/* tcp_vu.c - TCP L2 vhost-user management functions
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include <netinet/if_ether.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "vhost_user.h"
#include "tcp.h"
#include "pcap.h"
#include "flow.h"
#include "tcp_conn.h"
#include "flow_table.h"
#include "tcp_vu.h"
#include "tap.h"
#include "tcp_internal.h"
#include "checksum.h"
#include "vu_common.h"
#include <time.h>

static struct iovec iov_vu[VIRTQUEUE_MAX_SIZE + 1];
static struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];
static int head[VIRTQUEUE_MAX_SIZE + 1];
static int head_cnt;

/**
 * tcp_vu_hdrlen() - return the size of the header in level 2 frame (TCP)
 * @v6:		Set for IPv6 packet
 *
 * Return: Return the size of the header
 */
static size_t tcp_vu_hdrlen(bool v6)
{
	size_t hdrlen;

	hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf) +
		 sizeof(struct ethhdr) + sizeof(struct tcphdr);

	if (v6)
		hdrlen += sizeof(struct ipv6hdr);
	else
		hdrlen += sizeof(struct iphdr);

	return hdrlen;
}

/**
 * tcp_vu_update_check() - Calculate TCP checksum
 * @tapside:	Address information for one side of the flow
 * @iov:	Pointer to the array of IO vectors
 * @iov_cnt:	Length of the array
 */
static void tcp_vu_update_check(const struct flowside *tapside,
			        struct iovec *iov, int iov_cnt)
{
	char *base = iov[0].iov_base;

	if (inany_v4(&tapside->oaddr)) {
		struct tcphdr *th = vu_payloadv4(base);
		const struct iphdr *iph = vu_ip(base);
		struct iov_tail payload = IOV_TAIL(iov, iov_cnt,
						   (char *)(th + 1) - base);

		tcp_update_check_tcp4(iph, th, &payload);
	} else {
		struct tcphdr *th = vu_payloadv6(base);
		const struct ipv6hdr *ip6h = vu_ip(base);
		struct iov_tail payload = IOV_TAIL(iov, iov_cnt,
						   (char *)(th + 1) - base);

		tcp_update_check_tcp6(ip6h, th, &payload);
	}
}

/**
 * tcp_vu_send_flag() - Send segment with flags to vhost-user (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
int tcp_vu_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	const struct flowside *tapside = TAPFLOW(conn);
	size_t optlen, hdrlen;
	struct vu_virtq_element flags_elem[2];
	struct ipv6hdr *ip6h = NULL;
	struct iovec flags_iov[2];
	struct tcp_syn_opts *opts;
	struct iphdr *iph = NULL;
	struct iov_tail payload;
	struct tcphdr *th;
	struct ethhdr *eh;
	uint32_t seq;
	int elem_cnt;
	int nb_ack;
	int ret;

	hdrlen = tcp_vu_hdrlen(CONN_V6(conn));

	vu_set_element(&flags_elem[0], NULL, &flags_iov[0]);

	elem_cnt = vu_collect(vdev, vq, &flags_elem[0], 1,
			      hdrlen + sizeof(struct tcp_syn_opts), NULL);
	if (elem_cnt != 1)
		return -1;

	ASSERT(flags_elem[0].in_sg[0].iov_len >=
	       hdrlen + sizeof(struct tcp_syn_opts));

	vu_set_vnethdr(vdev, flags_elem[0].in_sg[0].iov_base, 1);

	eh = vu_eth(flags_elem[0].in_sg[0].iov_base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	if (CONN_V4(conn)) {
		eh->h_proto = htons(ETH_P_IP);

		iph = vu_ip(flags_elem[0].in_sg[0].iov_base);
		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);

		th = vu_payloadv4(flags_elem[0].in_sg[0].iov_base);
	} else {
		eh->h_proto = htons(ETH_P_IPV6);

		ip6h = vu_ip(flags_elem[0].in_sg[0].iov_base);
		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);
		th = vu_payloadv6(flags_elem[0].in_sg[0].iov_base);
	}

	memset(th, 0, sizeof(*th));
	th->doff = sizeof(*th) / 4;
	th->ack = 1;

	seq = conn->seq_to_tap;
	opts = (struct tcp_syn_opts *)(th + 1);
	ret = tcp_prepare_flags(c, conn, flags, th, opts, &optlen);
	if (ret <= 0) {
		vu_queue_rewind(vq, 1);
		return ret;
	}

	flags_elem[0].in_sg[0].iov_len = hdrlen + optlen;
	payload = IOV_TAIL(flags_elem[0].in_sg, 1, hdrlen);

	if (CONN_V4(conn)) {
		tcp_fill_headers4(conn, NULL, iph, th, &payload,
				  NULL, seq, true);
	} else {
		tcp_fill_headers6(conn, NULL, ip6h, th, &payload, seq, true);
	}

	if (*c->pcap) {
		tcp_vu_update_check(tapside, &flags_elem[0].in_sg[0], 1);
		pcap_iov(&flags_elem[0].in_sg[0], 1,
			 sizeof(struct virtio_net_hdr_mrg_rxbuf));
	}
	nb_ack = 1;

	if (flags & DUP_ACK) {
		vu_set_element(&flags_elem[1], NULL, &flags_iov[1]);

		elem_cnt = vu_collect(vdev, vq, &flags_elem[1], 1,
				      flags_elem[0].in_sg[0].iov_len, NULL);
		if (elem_cnt == 1 &&
		    flags_elem[1].in_sg[0].iov_len >=
		    flags_elem[0].in_sg[0].iov_len) {
			memcpy(flags_elem[1].in_sg[0].iov_base,
			       flags_elem[0].in_sg[0].iov_base,
			       flags_elem[0].in_sg[0].iov_len);
			nb_ack++;

			if (*c->pcap) {
				pcap_iov(&flags_elem[1].in_sg[0], 1,
					 sizeof(struct virtio_net_hdr_mrg_rxbuf));
			}
		}
	}

	vu_flush(vdev, vq, flags_elem, nb_ack);

	return 0;
}

/** tcp_vu_sock_recv() - Receive datastream from socket into vhost-user buffers
 * @c:			Execution context
 * @conn:		Connection pointer
 * @v6:			Set for IPv6 connections
 * @already_sent:	Number of bytes already sent
 * @fillsize:		Maximum bytes to fill in guest-side receiving window
 * @iov_cnt:		number of iov (output)
 *
 * Return: Number of iov entries used to store the data or negative error code
 */
static ssize_t tcp_vu_sock_recv(const struct ctx *c,
				const struct tcp_tap_conn *conn, bool v6,
				uint32_t already_sent, size_t fillsize,
				int *iov_cnt)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	int s = conn->sock;
	ssize_t ret, len;
	size_t hdrlen;
	int elem_cnt;
	int i;

	*iov_cnt = 0;

	hdrlen = tcp_vu_hdrlen(v6);

	vu_init_elem(elem, &iov_vu[1], VIRTQUEUE_MAX_SIZE);

	elem_cnt = 0;
	head_cnt = 0;
	while (fillsize > 0 && elem_cnt < VIRTQUEUE_MAX_SIZE) {
		struct iovec *iov;
		size_t frame_size, dlen;
		int cnt;

		cnt = vu_collect(vdev, vq, &elem[elem_cnt],
				 VIRTQUEUE_MAX_SIZE - elem_cnt,
				 MIN(mss, fillsize) + hdrlen, &frame_size);
		if (cnt == 0)
			break;

		dlen = frame_size - hdrlen;

		/* reserve space for headers in iov */
		iov = &elem[elem_cnt].in_sg[0];
		ASSERT(iov->iov_len >= hdrlen);
		iov->iov_base = (char *)iov->iov_base + hdrlen;
		iov->iov_len -= hdrlen;
		head[head_cnt++] = elem_cnt;

		fillsize -= dlen;
		elem_cnt += cnt;
	}

	if (peek_offset_cap) {
		mh_sock.msg_iov = iov_vu + 1;
		mh_sock.msg_iovlen = elem_cnt;
	} else {
		iov_vu[0].iov_base = tcp_buf_discard;
		iov_vu[0].iov_len = already_sent;

		mh_sock.msg_iov = iov_vu;
		mh_sock.msg_iovlen = elem_cnt + 1;
	}

	do
		ret = recvmsg(s, &mh_sock, MSG_PEEK);
	while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		vu_queue_rewind(vq, elem_cnt);
		return -errno;
	}

	if (!peek_offset_cap)
		ret -= already_sent;

	/* adjust iov number and length of the last iov */
	len = ret;
	for (i = 0; len && i < elem_cnt; i++) {
		struct iovec *iov = &elem[i].in_sg[0];

		if (iov->iov_len > (size_t)len)
			iov->iov_len = len;

		len -= iov->iov_len;
	}
	/* adjust head count */
	while (head_cnt > 0 && head[head_cnt - 1] > i)
		head_cnt--;
	/* mark end of array */
	head[head_cnt] = i;
	*iov_cnt = i;

	/* release unused buffers */
	vu_queue_rewind(vq, elem_cnt - i);

	/* restore space for headers in iov */
	for (i = 0; i < head_cnt; i++) {
		struct iovec *iov = &elem[head[i]].in_sg[0];

		iov->iov_base = (char *)iov->iov_base - hdrlen;
		iov->iov_len += hdrlen;
	}

	return ret;
}

/**
 * tcp_vu_prepare() - Prepare the frame header
 * @c:		Execution context
 * @conn:	Connection pointer
 * @iov:	Pointer to the array of IO vectors
 * @iov_cnt:	Number of entries in @iov
 * @check:	Checksum, if already known
 */
static void tcp_vu_prepare(const struct ctx *c, struct tcp_tap_conn *conn,
			   struct iovec *iov, size_t iov_cnt,
			   const uint16_t **check)
{
	const struct flowside *toside = TAPFLOW(conn);
	bool v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));
	size_t hdrlen = tcp_vu_hdrlen(v6);
	struct iov_tail payload = IOV_TAIL(iov, iov_cnt, hdrlen);
	char *base = iov[0].iov_base;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *th;
	struct ethhdr *eh;

	/* we guess the first iovec provided by the guest can embed
	 * all the headers needed by L2 frame
	 */
	ASSERT(iov[0].iov_len >= hdrlen);

	eh = vu_eth(base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	/* initialize header */

	if (!v6) {
		eh->h_proto = htons(ETH_P_IP);

		iph = vu_ip(base);
		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);
		th = vu_payloadv4(base);
	} else {
		eh->h_proto = htons(ETH_P_IPV6);

		ip6h = vu_ip(base);
		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

		th = vu_payloadv6(base);
	}

	memset(th, 0, sizeof(*th));
	th->doff = sizeof(*th) / 4;
	th->ack = 1;

	if (!v6) {
		tcp_fill_headers4(conn, NULL, iph, th, &payload,
				  *check, conn->seq_to_tap, true);
		*check = &iph->check;
	} else {
		tcp_fill_headers6(conn, NULL, ip6h, th, &payload,
				  conn->seq_to_tap, true);
	}
}

/**
 * tcp_vu_data_from_sock() - Handle new data from socket, queue to vhost-user,
 *			     in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: Negative on connection reset, 0 otherwise
 */
int tcp_vu_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	const struct flowside *tapside = TAPFLOW(conn);
	size_t fillsize, hdrlen;
	int v6 = CONN_V6(conn);
	uint32_t already_sent;
	const uint16_t *check;
	int i, iov_cnt;
	ssize_t len;

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		debug("Got packet, but RX virtqueue not usable yet");
		return 0;
	}

	already_sent = conn->seq_to_tap - conn->seq_ack_from_tap;

	if (SEQ_LT(already_sent, 0)) {
		/* RFC 761, section 2.1. */
		flow_trace(conn, "ACK sequence gap: ACK for %u, sent: %u",
			   conn->seq_ack_from_tap, conn->seq_to_tap);
		conn->seq_to_tap = conn->seq_ack_from_tap;
		already_sent = 0;
		if (tcp_set_peek_offset(conn->sock, 0)) {
			tcp_rst(c, conn);
			return -1;
		}
	}

	if (!wnd_scaled || already_sent >= wnd_scaled) {
		conn_flag(c, conn, STALLED);
		conn_flag(c, conn, ACK_FROM_TAP_DUE);
		return 0;
	}

	/* Set up buffer descriptors we'll fill completely and partially. */

	fillsize = wnd_scaled - already_sent;

	/* collect the buffers from vhost-user and fill them with the
	 * data from the socket
	 */
	len = tcp_vu_sock_recv(c, conn, v6, already_sent, fillsize, &iov_cnt);
	if (len < 0) {
		if (len != -EAGAIN && len != -EWOULDBLOCK) {
			tcp_rst(c, conn);
			return len;
		}
		return 0;
	}

	if (!len) {
		if (already_sent) {
			conn_flag(c, conn, STALLED);
		} else if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) ==
			   SOCK_FIN_RCVD) {
			int ret = tcp_vu_send_flag(c, conn, FIN | ACK);
			if (ret) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
		}

		return 0;
	}

	conn_flag(c, conn, ~STALLED);

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, false, NULL);

	/* initialize headers */
	/* iov_vu is an array of buffers and the buffer size can be
	 * smaller than the frame size we want to use but with
	 * num_buffer we can merge several virtio iov buffers in one packet
	 * we need only to set the packet headers in the first iov and
	 * num_buffer to the number of iov entries
	 */

	hdrlen = tcp_vu_hdrlen(v6);
	for (i = 0, check = NULL; i < head_cnt; i++) {
		struct iovec *iov = &elem[head[i]].in_sg[0];
		int buf_cnt = head[i + 1] - head[i];
		ssize_t dlen = iov_size(iov, buf_cnt) - hdrlen;

		vu_set_vnethdr(vdev, iov->iov_base, buf_cnt);

		/* we compute IPv4 header checksum only for the
		 * first and the last, all other checksums are the
		 * same as the first one
		 */
		if (i + 1 == head_cnt)
			check = NULL;

		tcp_vu_prepare(c, conn, iov, buf_cnt, &check);

		if (*c->pcap) {
			tcp_vu_update_check(tapside, iov, buf_cnt);
			pcap_iov(iov, buf_cnt,
				 sizeof(struct virtio_net_hdr_mrg_rxbuf));
		}

		conn->seq_to_tap += dlen;
	}

	/* send packets */
	vu_flush(vdev, vq, elem, iov_cnt);

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;
}
