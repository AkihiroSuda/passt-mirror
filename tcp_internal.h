/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_INTERNAL_H
#define TCP_INTERNAL_H

#define MAX_WS				8
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))

#define MSS4				ROUND_DOWN(IP_MAX_MTU -		   \
						   sizeof(struct tcphdr) - \
						   sizeof(struct iphdr),   \
						   sizeof(uint32_t))
#define MSS6				ROUND_DOWN(IP_MAX_MTU -		   \
						   sizeof(struct tcphdr) - \
						   sizeof(struct ipv6hdr), \
						   sizeof(uint32_t))

#define SEQ_LE(a, b)			((b) - (a) < MAX_WINDOW)
#define SEQ_LT(a, b)			((b) - (a) - 1 < MAX_WINDOW)
#define SEQ_GE(a, b)			((a) - (b) < MAX_WINDOW)
#define SEQ_GT(a, b)			((a) - (b) - 1 < MAX_WINDOW)

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)

/* Flags for internal usage */
#define DUP_ACK		(1 << 5)
#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_MSS_LEN	4
#define OPT_WS		3
#define OPT_WS_LEN	3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

#define TAPSIDE(conn_)	((conn_)->f.pif[1] == PIF_TAP)
#define TAPFLOW(conn_)	(&((conn_)->f.side[TAPSIDE(conn_)]))
#define TAP_SIDX(conn_)	(FLOW_SIDX((conn_), TAPSIDE(conn_)))

#define CONN_V4(conn)		(!!inany_v4(&TAPFLOW(conn)->oaddr))
#define CONN_V6(conn)		(!CONN_V4(conn))

/*
 * enum tcp_iov_parts - I/O vector parts for one TCP frame
 * @TCP_IOV_TAP		tap backend specific header
 * @TCP_IOV_ETH		Ethernet header
 * @TCP_IOV_IP		IP (v4/v6) header
 * @TCP_IOV_PAYLOAD	IP payload (TCP header + data)
 * @TCP_NUM_IOVS 	the number of entries in the iovec array
 */
enum tcp_iov_parts {
	TCP_IOV_TAP	= 0,
	TCP_IOV_ETH	= 1,
	TCP_IOV_IP	= 2,
	TCP_IOV_PAYLOAD	= 3,
	TCP_NUM_IOVS
};

extern char tcp_buf_discard [MAX_WINDOW];

void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
		  unsigned long flag);
#define conn_flag(c, conn, flag)					\
	do {								\
		flow_trace(conn, "flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(c, conn, flag);				\
	} while (0)


void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
		   unsigned long event);
#define conn_event(c, conn, event)					\
	do {								\
		flow_trace(conn, "event at %s:%i", __func__, __LINE__);	\
		conn_event_do(c, conn, event);				\
	} while (0)

void tcp_rst_do(struct ctx *c, struct tcp_tap_conn *conn);
#define tcp_rst(c, conn)						\
	do {								\
		flow_dbg((conn), "TCP reset at %s:%i", __func__, __LINE__); \
		tcp_rst_do(c, conn);					\
	} while (0)

size_t tcp_l2_buf_fill_headers(const struct tcp_tap_conn *conn,
			       struct iovec *iov, size_t dlen,
			       const uint16_t *check, uint32_t seq);
int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
			  int force_seq, struct tcp_info *tinfo);
int tcp_prepare_flags(struct ctx *c, struct tcp_tap_conn *conn, int flags,
		      struct tcphdr *th, char *data, size_t *optlen);

#endif /* TCP_INTERNAL_H */
