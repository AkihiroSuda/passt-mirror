/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * TCP connection tracking data structures, used by tcp.c and
 * tcp_splice.c.  Shouldn't be included in non-TCP code.
 */
#ifndef TCP_CONN_H
#define TCP_CONN_H

/**
 * struct tcp_tap_conn - Descriptor for a TCP connection (not spliced)
 * @f:			Generic flow information
 * @in_epoll:		Is the connection in the epoll set?
 * @retrans:		Number of retransmissions occurred due to ACK_TIMEOUT
 * @ws_from_tap:	Window scaling factor advertised from tap/guest
 * @ws_to_tap:		Window scaling factor advertised to tap/guest
 * @tap_mss:		MSS advertised by tap/guest, rounded to 2 ^ TCP_MSS_BITS
 * @sock:		Socket descriptor number
 * @events:		Connection events, implying connection states
 * @timer:		timerfd descriptor for timeout events
 * @flags:		Connection flags representing internal attributes
 * @sndbuf:		Sending buffer in kernel, rounded to 2 ^ SNDBUF_BITS
 * @seq_dup_ack_approx:	Last duplicate ACK number sent to tap
 * @wnd_from_tap:	Last window size from tap, unscaled (as received)
 * @wnd_to_tap:		Sending window advertised to tap, unscaled (as sent)
 * @seq_to_tap:		Next sequence for packets to tap
 * @seq_ack_from_tap:	Last ACK number received from tap
 * @seq_from_tap:	Next sequence for packets from tap (not actually sent)
 * @seq_ack_to_tap:	Last ACK number sent to tap
 * @seq_init_from_tap:	Initial sequence number from tap
 */
struct tcp_tap_conn {
	/* Must be first element */
	struct flow_common f;

	bool		in_epoll	:1;

#define TCP_RETRANS_BITS		3
	unsigned int	retrans		:TCP_RETRANS_BITS;
#define TCP_MAX_RETRANS			MAX_FROM_BITS(TCP_RETRANS_BITS)

#define TCP_WS_BITS			4	/* RFC 7323 */
#define TCP_WS_MAX			14
	unsigned int	ws_from_tap	:TCP_WS_BITS;
	unsigned int	ws_to_tap	:TCP_WS_BITS;

#define TCP_MSS_BITS			14
	unsigned int	tap_mss		:TCP_MSS_BITS;
#define MSS_SET(conn, mss)	(conn->tap_mss = (mss >> (16 - TCP_MSS_BITS)))
#define MSS_GET(conn)		(conn->tap_mss << (16 - TCP_MSS_BITS))

	int		sock		:FD_REF_BITS;

	uint8_t		events;
#define CLOSED			0
#define SOCK_ACCEPTED		BIT(0)	/* implies SYN sent to tap */
#define TAP_SYN_RCVD		BIT(1)	/* implies socket connecting */
#define  TAP_SYN_ACK_SENT	BIT( 3)	/* implies socket connected */
#define ESTABLISHED		BIT(2)
#define  SOCK_FIN_RCVD		BIT( 3)
#define  SOCK_FIN_SENT		BIT( 4)
#define  TAP_FIN_RCVD		BIT( 5)
#define  TAP_FIN_SENT		BIT( 6)
#define  TAP_FIN_ACKED		BIT( 7)

#define	CONN_STATE_BITS		/* Setting these clears other flags */	\
	(SOCK_ACCEPTED | TAP_SYN_RCVD | ESTABLISHED)


	int		timer		:FD_REF_BITS;

	uint8_t		flags;
#define STALLED			BIT(0)
#define LOCAL			BIT(1)
#define ACTIVE_CLOSE		BIT(2)
#define ACK_TO_TAP_DUE		BIT(3)
#define ACK_FROM_TAP_DUE	BIT(4)

#define SNDBUF_BITS		24
	unsigned int	sndbuf		:SNDBUF_BITS;
#define SNDBUF_SET(conn, bytes)	(conn->sndbuf = ((bytes) >> (32 - SNDBUF_BITS)))
#define SNDBUF_GET(conn)	(conn->sndbuf << (32 - SNDBUF_BITS))

	uint8_t		seq_dup_ack_approx;

	uint16_t	wnd_from_tap;
	uint16_t	wnd_to_tap;

	uint32_t	seq_to_tap;
	uint32_t	seq_ack_from_tap;
	uint32_t	seq_from_tap;
	uint32_t	seq_ack_to_tap;
	uint32_t	seq_init_from_tap;
};

/**
 * struct tcp_splice_conn - Descriptor for a spliced TCP connection
 * @f:			Generic flow information
 * @s:			File descriptor for sockets
 * @pipe:		File descriptors for pipes
 * @read:		Bytes read (not fully written to other side in one shot)
 * @written:		Bytes written (not fully written from one other side read)
 * @events:		Events observed/actions performed on connection
 * @flags:		Connection flags (attributes, not events)
 * @in_epoll:		Is the connection in the epoll set?
 */
struct tcp_splice_conn {
	/* Must be first element */
	struct flow_common f;

	int s[SIDES];
	int pipe[SIDES][2];

	uint32_t read[SIDES];
	uint32_t written[SIDES];

	uint8_t events;
#define SPLICE_CLOSED			0
#define SPLICE_CONNECT			BIT(0)
#define SPLICE_ESTABLISHED		BIT(1)
#define OUT_WAIT(sidei_)		((sidei_) ? BIT(3) : BIT(2))
#define FIN_RCVD(sidei_)		((sidei_) ? BIT(5) : BIT(4))
#define FIN_SENT(sidei_)		((sidei_) ? BIT(7) : BIT(6))

	uint8_t flags;
#define RCVLOWAT_SET(sidei_)		((sidei_) ? BIT(1) : BIT(0))
#define RCVLOWAT_ACT(sidei_)		((sidei_) ? BIT(3) : BIT(2))
#define CLOSING				BIT(4)

	bool in_epoll	:1;
};

/* Socket pools */
#define TCP_SOCK_POOL_SIZE		32

extern int init_sock_pool4	[TCP_SOCK_POOL_SIZE];
extern int init_sock_pool6	[TCP_SOCK_POOL_SIZE];

bool tcp_flow_defer(const struct tcp_tap_conn *conn);
bool tcp_splice_flow_defer(struct tcp_splice_conn *conn);
void tcp_splice_timer(const struct ctx *c, struct tcp_splice_conn *conn);
int tcp_conn_pool_sock(int pool[]);
int tcp_conn_sock(const struct ctx *c, sa_family_t af);
int tcp_sock_refill_pool(const struct ctx *c, int pool[], sa_family_t af);
void tcp_splice_refill(const struct ctx *c);

#endif /* TCP_CONN_H */
