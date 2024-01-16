// SPDX-License-Identifier: GPL-2.0-or-later

/* PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp_splice.c - direct namespace forwarding for local connections
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For local traffic directed to TCP ports configured for direct
 * mapping between namespaces, packets are directly translated between
 * L4 sockets using a pair of splice() syscalls. These connections are
 * tracked by struct tcp_splice_conn entries in the @tc array, using
 * these events:
 *
 * - SPLICE_CONNECT:		connection accepted, connecting to target
 * - SPLICE_ESTABLISHED:	connection to target established
 * - OUT_WAIT_0:		pipe to accepted socket full, wait for EPOLLOUT
 * - OUT_WAIT_1:		pipe to target socket full, wait for EPOLLOUT
 * - FIN_RCVD_0:		FIN (EPOLLRDHUP) seen from accepted socket
 * - FIN_RCVD_1:		FIN (EPOLLRDHUP) seen from target socket
 * - FIN_SENT_0:		FIN (write shutdown) sent to accepted socket
 * - FIN_SENT_1:		FIN (write shutdown) sent to target socket
 *
 * #syscalls:pasta pipe2|pipe fcntl armv6l:fcntl64 armv7l:fcntl64 ppc64:fcntl64
 */

#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "tcp_splice.h"
#include "siphash.h"
#include "inany.h"
#include "flow.h"

#include "flow_table.h"

#define MAX_PIPE_SIZE			(8UL * 1024 * 1024)
#define TCP_SPLICE_PIPE_POOL_SIZE	32
#define TCP_SPLICE_CONN_PRESSURE	30	/* % of conn_count */
#define TCP_SPLICE_FILE_PRESSURE	30	/* % of c->nofile */

/* Pools for pre-opened sockets (in namespace) */
#define TCP_SOCK_POOL_TSH		16 /* Refill in ns if > x used */

static int ns_sock_pool4	[TCP_SOCK_POOL_SIZE];
static int ns_sock_pool6	[TCP_SOCK_POOL_SIZE];

/* Pool of pre-opened pipes */
static int splice_pipe_pool		[TCP_SPLICE_PIPE_POOL_SIZE][2];

#define CONN_V6(x)			(x->flags & SPLICE_V6)
#define CONN_V4(x)			(!CONN_V6(x))
#define CONN_HAS(conn, set)		((conn->events & (set)) == (set))
#define CONN(idx)			(&FLOW(idx)->tcp_splice)

/* Display strings for connection events */
static const char *tcp_splice_event_str[] __attribute((__unused__)) = {
	"SPLICE_CONNECT", "SPLICE_ESTABLISHED", "OUT_WAIT_0", "OUT_WAIT_1",
	"FIN_RCVD_0", "FIN_RCVD_1", "FIN_SENT_0", "FIN_SENT_1",
};

/* Display strings for connection flags */
static const char *tcp_splice_flag_str[] __attribute((__unused__)) = {
	"SPLICE_V6", "RCVLOWAT_SET_0", "RCVLOWAT_SET_1", "RCVLOWAT_ACT_0",
	"RCVLOWAT_ACT_1", "CLOSING",
};

/* Forward declaration */
static int tcp_sock_refill_ns(void *arg);

/**
 * tcp_splice_conn_epoll_events() - epoll events masks for given state
 * @events:	Connection event flags
 * @ev:		Events to fill in, 0 is accepted socket, 1 is connecting socket
 */
static void tcp_splice_conn_epoll_events(uint16_t events,
					 struct epoll_event ev[])
{
	ev[0].events = ev[1].events = 0;

	if (events & SPLICE_ESTABLISHED) {
		if (!(events & FIN_SENT_1))
			ev[0].events = EPOLLIN | EPOLLRDHUP;
		if (!(events & FIN_SENT_0))
			ev[1].events = EPOLLIN | EPOLLRDHUP;
	} else if (events & SPLICE_CONNECT) {
		ev[1].events = EPOLLOUT;
	}

	ev[0].events |= (events & OUT_WAIT_0) ? EPOLLOUT : 0;
	ev[1].events |= (events & OUT_WAIT_1) ? EPOLLOUT : 0;
}

/**
 * tcp_splice_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_splice_epoll_ctl(const struct ctx *c,
				struct tcp_splice_conn *conn)
{
	int m = conn->in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	const union epoll_ref ref[SIDES] = {
		{ .type = EPOLL_TYPE_TCP_SPLICE, .fd = conn->s[0],
		  .flowside = FLOW_SIDX(conn, 0) },
		{ .type = EPOLL_TYPE_TCP_SPLICE, .fd = conn->s[1],
		  .flowside = FLOW_SIDX(conn, 1) }
	};
	struct epoll_event ev[SIDES] = { { .data.u64 = ref[0].u64 },
					 { .data.u64 = ref[1].u64 } };

	tcp_splice_conn_epoll_events(conn->events, ev);

	if (epoll_ctl(c->epollfd, m, conn->s[0], &ev[0]) ||
	    epoll_ctl(c->epollfd, m, conn->s[1], &ev[1])) {
		int ret = -errno;
		flow_err(conn, "ERROR on epoll_ctl(): %s", strerror(errno));
		return ret;
	}

	conn->in_epoll = true;

	return 0;
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on CLOSING flag
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
static void conn_flag_do(const struct ctx *c, struct tcp_splice_conn *conn,
			 unsigned long flag)
{
	if (flag & (flag - 1)) {
		int flag_index = fls(~flag);

		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s dropped",
				 tcp_splice_flag_str[flag_index]);
	} else {
		int flag_index = fls(flag);

		if (conn->flags & flag)
			return;

		conn->flags |= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_splice_flag_str[flag_index]);
	}

	if (flag == CLOSING) {
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->s[0], NULL);
		epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->s[1], NULL);
	}
}

#define conn_flag(c, conn, flag)					\
	do {								\
		flow_trace(conn, "flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(c, conn, flag);				\
	} while (0)

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @c:		Execution context
 * @conn:	Connection pointer
 * @event:	Connection event
 */
static void conn_event_do(const struct ctx *c, struct tcp_splice_conn *conn,
			  unsigned long event)
{
	if (event & (event - 1)) {
		int flag_index = fls(~event);

		if (!(conn->events & ~event))
			return;

		conn->events &= event;
		if (flag_index >= 0)
			flow_dbg(conn, "~%s", tcp_splice_event_str[flag_index]);
	} else {
		int flag_index = fls(event);

		if (conn->events & event)
			return;

		conn->events |= event;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_splice_event_str[flag_index]);
	}

	if (tcp_splice_epoll_ctl(c, conn))
		conn_flag(c, conn, CLOSING);
}

#define conn_event(c, conn, event)					\
	do {								\
		flow_trace(conn, "event at %s:%i",__func__, __LINE__);	\
		conn_event_do(c, conn, event);				\
	} while (0)


/**
 * tcp_splice_conn_update() - Update tcp_splice_conn when being moved in the table
 * @c:		Execution context
 * @new:	New location of tcp_splice_conn
 */
void tcp_splice_conn_update(const struct ctx *c, struct tcp_splice_conn *new)
{
	if (tcp_splice_epoll_ctl(c, new))
		conn_flag(c, new, CLOSING);
}

/**
 * tcp_splice_flow_defer() - Deferred per-flow handling (clean up closed)
 * @c:		Execution context
 * @flow:	Flow table entry for this connection
 */
void tcp_splice_flow_defer(const struct ctx *c, union flow *flow)
{
	struct tcp_splice_conn *conn = &flow->tcp_splice;
	unsigned side;

	if (!(flow->tcp_splice.flags & CLOSING))
		return;

	for (side = 0; side < SIDES; side++) {
		if (conn->events & SPLICE_ESTABLISHED) {
			/* Flushing might need to block: don't recycle them. */
			if (conn->pipe[side][0] != -1) {
				close(conn->pipe[side][0]);
				close(conn->pipe[side][1]);
				conn->pipe[side][0] = conn->pipe[side][1] = -1;
			}
		}

		if (side == 0 || conn->events & SPLICE_CONNECT) {
			close(conn->s[side]);
			conn->s[side] = -1;
		}

		conn->read[side] = conn->written[side] = 0;
	}

	conn->events = SPLICE_CLOSED;
	conn->flags = 0;
	flow_dbg(conn, "CLOSED");

	flow_table_compact(c, flow);
}

/**
 * tcp_splice_connect_finish() - Completion of connect() or call on success
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, -EIO on failure
 */
static int tcp_splice_connect_finish(const struct ctx *c,
				     struct tcp_splice_conn *conn)
{
	unsigned side;
	int i = 0;

	for (side = 0; side < SIDES; side++) {
		conn->pipe[side][0] = conn->pipe[side][1] = -1;

		for (; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
			if (splice_pipe_pool[i][0] >= 0) {
				SWAP(conn->pipe[side][0],
				     splice_pipe_pool[i][0]);
				SWAP(conn->pipe[side][1],
				     splice_pipe_pool[i][1]);
				break;
			}
		}

		if (conn->pipe[side][0] < 0) {
			if (pipe2(conn->pipe[side], O_NONBLOCK | O_CLOEXEC)) {
				flow_err(conn, "cannot create %d->%d pipe: %s",
					 side, !side, strerror(errno));
				conn_flag(c, conn, CLOSING);
				return -EIO;
			}

			if (fcntl(conn->pipe[side][0], F_SETPIPE_SZ,
				  c->tcp.pipe_size)) {
				flow_trace(conn,
					   "cannot set %d->%d pipe size to %zu",
					   side, !side, c->tcp.pipe_size);
			}
		}
	}

	if (!(conn->events & SPLICE_ESTABLISHED))
		conn_event(c, conn, SPLICE_ESTABLISHED);

	return 0;
}

/**
 * tcp_splice_connect() - Create and connect socket for new spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @s:		Accepted socket
 * @port:	Destination port, host order
 *
 * Return: 0 for connect() succeeded or in progress, negative value on error
 */
static int tcp_splice_connect(const struct ctx *c, struct tcp_splice_conn *conn,
			      int sock_conn, in_port_t port)
{
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = IN4ADDR_LOOPBACK_INIT,
	};
	const struct sockaddr *sa;
	socklen_t sl;

	conn->s[1] = sock_conn;

	if (setsockopt(conn->s[1], SOL_TCP, TCP_QUICKACK,
		       &((int){ 1 }), sizeof(int))) {
		flow_trace(conn, "failed to set TCP_QUICKACK on socket %i",
			   conn->s[1]);
	}

	if (CONN_V6(conn)) {
		sa = (struct sockaddr *)&addr6;
		sl = sizeof(addr6);
	} else {
		sa = (struct sockaddr *)&addr4;
		sl = sizeof(addr4);
	}

	if (connect(conn->s[1], sa, sl)) {
		if (errno != EINPROGRESS) {
			int ret = -errno;

			close(sock_conn);
			return ret;
		}
		conn_event(c, conn, SPLICE_CONNECT);
	} else {
		conn_event(c, conn, SPLICE_ESTABLISHED);
		return tcp_splice_connect_finish(c, conn);
	}

	return 0;
}

/**
 * tcp_splice_new() - Handle new spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @port:	Destination port, host order
 * @pif:	Originating pif of the splice
 *
 * Return: return code from connect()
 */
static int tcp_splice_new(const struct ctx *c, struct tcp_splice_conn *conn,
			  in_port_t port, uint8_t pif)
{
	int s = -1;

	/* If the pool is empty we take slightly different approaches
	 * for init or ns sockets.  For init sockets we just open a
	 * new one without refilling the pool to keep latency down.
	 * For ns sockets, we're going to incur the latency of
	 * entering the ns anyway, so we might as well refill the
	 * pool.
	 */
	if (pif == PIF_SPLICE) {
		int *p = CONN_V6(conn) ? init_sock_pool6 : init_sock_pool4;
		int af = CONN_V6(conn) ? AF_INET6 : AF_INET;

		s = tcp_conn_pool_sock(p);
		if (s < 0)
			s = tcp_conn_new_sock(c, af);
	} else {
		int *p = CONN_V6(conn) ? ns_sock_pool6 : ns_sock_pool4;

		ASSERT(pif == PIF_HOST);

		/* If pool is empty, refill it first */
		if (p[TCP_SOCK_POOL_SIZE-1] < 0)
			NS_CALL(tcp_sock_refill_ns, c);

		s = tcp_conn_pool_sock(p);
	}

	if (s < 0) {
		warn("Couldn't open connectable socket for splice (%d)", s);
		return s;
	}

	return tcp_splice_connect(c, conn, s, port);
}

/**
 * tcp_splice_conn_from_sock() - Attempt to init state for a spliced connection
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @conn:	connection structure to initialize
 * @s:		Accepted socket
 * @sa:		Peer address of connection
 *
 * Return: true if able to create a spliced connection, false otherwise
 * #syscalls:pasta setsockopt
 */
bool tcp_splice_conn_from_sock(const struct ctx *c,
			       union tcp_listen_epoll_ref ref,
			       struct tcp_splice_conn *conn, int s,
			       const struct sockaddr *sa)
{
	const struct in_addr *a4;
	union inany_addr aany;
	in_port_t port;

	ASSERT(c->mode == MODE_PASTA);

	inany_from_sockaddr(&aany, &port, sa);
	a4 = inany_v4(&aany);

	if (a4) {
		if (!IN4_IS_ADDR_LOOPBACK(a4))
			return false;
		conn->flags = 0;
	} else {
		if (!IN6_IS_ADDR_LOOPBACK(&aany.a6))
			return false;
		conn->flags = SPLICE_V6;
	}

	if (setsockopt(s, SOL_TCP, TCP_QUICKACK, &((int){ 1 }), sizeof(int)))
		flow_trace(conn, "failed to set TCP_QUICKACK on %i", s);

	conn->f.type = FLOW_TCP_SPLICE;
	conn->s[0] = s;

	if (tcp_splice_new(c, conn, ref.port, ref.pif))
		conn_flag(c, conn, CLOSING);

	return true;
}

/**
 * tcp_splice_sock_handler() - Handler for socket mapped to spliced connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 *
 * #syscalls:pasta splice
 */
void tcp_splice_sock_handler(struct ctx *c, union epoll_ref ref,
			     uint32_t events)
{
	struct tcp_splice_conn *conn = CONN(ref.flowside.flow);
	unsigned side = ref.flowside.side, fromside;
	uint8_t lowat_set_flag, lowat_act_flag;
	int eof, never_read;

	ASSERT(conn->f.type == FLOW_TCP_SPLICE);

	if (conn->events == SPLICE_CLOSED)
		return;

	if (events & EPOLLERR)
		goto close;

	if (conn->events == SPLICE_CONNECT) {
		if (!(events & EPOLLOUT))
			goto close;
		if (tcp_splice_connect_finish(c, conn))
			goto close;
	}

	if (events & EPOLLOUT) {
		fromside = !side;
		conn_event(c, conn, side == 0 ? ~OUT_WAIT_0 : ~OUT_WAIT_1);
	} else {
		fromside = side;
	}

	if (events & EPOLLRDHUP)
		/* For side 0 this is fake, but implied */
		conn_event(c, conn, side == 0 ? FIN_RCVD_0 : FIN_RCVD_1);

swap:
	eof = 0;
	never_read = 1;

	lowat_set_flag = fromside == 0 ? RCVLOWAT_SET_0 : RCVLOWAT_SET_1;
	lowat_act_flag = fromside == 0 ? RCVLOWAT_ACT_0 : RCVLOWAT_ACT_1;

	while (1) {
		ssize_t readlen, to_write = 0, written;
		int more = 0;

retry:
		readlen = splice(conn->s[fromside], NULL,
				 conn->pipe[fromside][1], NULL, c->tcp.pipe_size,
				 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		flow_trace(conn, "%zi from read-side call", readlen);
		if (readlen < 0) {
			if (errno == EINTR)
				goto retry;

			if (errno != EAGAIN)
				goto close;

			to_write = c->tcp.pipe_size;
		} else if (!readlen) {
			eof = 1;
			to_write = c->tcp.pipe_size;
		} else {
			never_read = 0;
			to_write += readlen;
			if (readlen >= (long)c->tcp.pipe_size * 90 / 100)
				more = SPLICE_F_MORE;

			if (conn->flags & lowat_set_flag)
				conn_flag(c, conn, lowat_act_flag);
		}

eintr:
		written = splice(conn->pipe[fromside][0], NULL,
				 conn->s[!fromside], NULL, to_write,
				 SPLICE_F_MOVE | more | SPLICE_F_NONBLOCK);
		flow_trace(conn, "%zi from write-side call (passed %zi)",
			   written, to_write);

		/* Most common case: skip updating counters. */
		if (readlen > 0 && readlen == written) {
			if (readlen >= (long)c->tcp.pipe_size * 10 / 100)
				continue;

			if (conn->flags & lowat_set_flag &&
			    readlen > (long)c->tcp.pipe_size / 10) {
				int lowat = c->tcp.pipe_size / 4;

				setsockopt(conn->s[fromside], SOL_SOCKET,
					   SO_RCVLOWAT, &lowat, sizeof(lowat));

				conn_flag(c, conn, lowat_set_flag);
				conn_flag(c, conn, lowat_act_flag);
			}

			break;
		}

		conn->read[fromside]    += readlen > 0 ? readlen : 0;
		conn->written[fromside] += written > 0 ? written : 0;

		if (written < 0) {
			if (errno == EINTR)
				goto eintr;

			if (errno != EAGAIN)
				goto close;

			if (never_read)
				break;

			conn_event(c, conn,
				   fromside == 0 ? OUT_WAIT_1 : OUT_WAIT_0);
			break;
		}

		if (never_read && written == (long)(c->tcp.pipe_size))
			goto retry;

		if (!never_read && written < to_write) {
			to_write -= written;
			goto retry;
		}

		if (eof)
			break;
	}

	if ((conn->events & FIN_RCVD_0) && !(conn->events & FIN_SENT_1)) {
		if (conn->read[fromside] == conn->written[fromside] && eof) {
			shutdown(conn->s[1], SHUT_WR);
			conn_event(c, conn, FIN_SENT_1);
		}
	}

	if ((conn->events & FIN_RCVD_1) && !(conn->events & FIN_SENT_0)) {
		if (conn->read[fromside] == conn->written[fromside] && eof) {
			shutdown(conn->s[0], SHUT_WR);
			conn_event(c, conn, FIN_SENT_0);
		}
	}

	if (CONN_HAS(conn, FIN_SENT_0 | FIN_SENT_1))
		goto close;

	if ((events & (EPOLLIN | EPOLLOUT)) == (EPOLLIN | EPOLLOUT)) {
		events = EPOLLIN;

		fromside = !fromside;
		goto swap;
	}

	if (events & EPOLLHUP)
		goto close;

	return;

close:
	conn_flag(c, conn, CLOSING);
}

/**
 * tcp_set_pipe_size() - Set usable pipe size, probe starting from MAX_PIPE_SIZE
 * @c:		Execution context
 */
static void tcp_set_pipe_size(struct ctx *c)
{
	int probe_pipe[TCP_SPLICE_PIPE_POOL_SIZE][2], i, j;

	c->tcp.pipe_size = MAX_PIPE_SIZE;

smaller:
	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (pipe2(probe_pipe[i], O_CLOEXEC)) {
			i++;
			break;
		}

		if (fcntl(probe_pipe[i][0], F_SETPIPE_SZ, c->tcp.pipe_size) < 0)
			break;
	}

	for (j = i - 1; j >= 0; j--) {
		close(probe_pipe[j][0]);
		close(probe_pipe[j][1]);
	}

	if (i == TCP_SPLICE_PIPE_POOL_SIZE)
		return;

	if (!(c->tcp.pipe_size /= 2)) {
		c->tcp.pipe_size = MAX_PIPE_SIZE;
		return;
	}

	goto smaller;
}

/**
 * tcp_splice_pipe_refill() - Refill pool of pre-opened pipes
 * @c:		Execution context
 */
static void tcp_splice_pipe_refill(const struct ctx *c)
{
	int i;

	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0] >= 0)
			break;
		if (pipe2(splice_pipe_pool[i], O_NONBLOCK | O_CLOEXEC))
			continue;

		if (fcntl(splice_pipe_pool[i][0], F_SETPIPE_SZ,
			  c->tcp.pipe_size)) {
			trace("TCP (spliced): cannot set pool pipe size to %zu",
			      c->tcp.pipe_size);
		}
	}
}

/**
 * tcp_sock_refill_ns() - Refill pools of pre-opened sockets in namespace
 * @arg:	Execution context cast to void *
 *
 * Return: 0
 */
static int tcp_sock_refill_ns(void *arg)
{
	const struct ctx *c = (const struct ctx *)arg;

	ns_enter(c);

	if (c->ifi4)
		tcp_sock_refill_pool(c, ns_sock_pool4, AF_INET);
	if (c->ifi6)
		tcp_sock_refill_pool(c, ns_sock_pool6, AF_INET6);

	return 0;
}

/**
 * tcp_splice_refill() - Refill pools of resources needed for splicing
 * @c:		Execution context
 */
void tcp_splice_refill(const struct ctx *c)
{
	if ((c->ifi4 && ns_sock_pool4[TCP_SOCK_POOL_TSH] < 0) ||
	    (c->ifi6 && ns_sock_pool6[TCP_SOCK_POOL_TSH] < 0))
		NS_CALL(tcp_sock_refill_ns, c);

	tcp_splice_pipe_refill(c);
}

/**
 * tcp_splice_init() - Initialise pipe pool and size
 * @c:		Execution context
 */
void tcp_splice_init(struct ctx *c)
{
	memset(splice_pipe_pool, 0xff, sizeof(splice_pipe_pool));
	tcp_set_pipe_size(c);

	memset(&ns_sock_pool4,		0xff,	sizeof(ns_sock_pool4));
	memset(&ns_sock_pool6,		0xff,	sizeof(ns_sock_pool6));
	NS_CALL(tcp_sock_refill_ns, c);
}

/**
 * tcp_splice_timer() - Timer for spliced connections
 * @c:		Execution context
 * @flow:	Flow table entry
 */
void tcp_splice_timer(const struct ctx *c, union flow *flow)
{
	struct tcp_splice_conn *conn = &flow->tcp_splice;
	int side;

	ASSERT(!(conn->flags & CLOSING));

	for (side = 0; side < SIDES; side++) {
		uint8_t set = side == 0 ? RCVLOWAT_SET_0 : RCVLOWAT_SET_1;
		uint8_t act = side == 0 ? RCVLOWAT_ACT_0 : RCVLOWAT_ACT_1;

		if ((conn->flags & set) && !(conn->flags & act)) {
			if (setsockopt(conn->s[side], SOL_SOCKET, SO_RCVLOWAT,
				       &((int){ 1 }), sizeof(int))) {
				flow_trace(conn, "can't set SO_RCVLOWAT on %d",
					   conn->s[side]);
			}
			conn_flag(c, conn, ~set);
		}
	}

	conn_flag(c, conn, ~RCVLOWAT_ACT_0);
	conn_flag(c, conn, ~RCVLOWAT_ACT_1);
}
