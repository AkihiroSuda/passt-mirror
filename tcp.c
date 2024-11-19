// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * PASST mode
 * ==========
 *
 * This implementation maps TCP traffic between a single L2 interface (tap) and
 * native TCP (L4) sockets, mimicking and reproducing as closely as possible the
 * inferred behaviour of applications running on a guest, connected via said L2
 * interface. Four connection flows are supported:
 * - from the local host to the guest behind the tap interface:
 *   - this is the main use case for proxies in service meshes
 *   - we bind to configured local ports, and relay traffic between L4 sockets
 *     with local endpoints and the L2 interface
 * - from remote hosts to the guest behind the tap interface:
 *   - this might be needed for services that need to be addressed directly,
 *     and typically configured with special port forwarding rules (which are
 *     not needed here)
 *   - we also relay traffic between L4 sockets with remote endpoints and the L2
 *     interface
 * - from the guest to the local host:
 *   - this is not observed in practice, but implemented for completeness and
 *     transparency
 * - from the guest to external hosts:
 *   - this might be needed for applications running on the guest that need to
 *     directly access internet services (e.g. NTP)
 *
 * Relevant goals are:
 * - transparency: sockets need to behave as if guest applications were running
 *   directly on the host. This is achieved by:
 *   - avoiding port and address translations whenever possible
 *   - mirroring TCP dynamics by observation of socket parameters (TCP_INFO
 *     socket option) and TCP headers of packets coming from the tap interface,
 *     reapplying those parameters in both flow directions (including TCP_MSS
 *     socket option)
 * - simplicity: only a small subset of TCP logic is implemented here and
 *   delegated as much as possible to the TCP implementations of guest and host
 *   kernel. This is achieved by:
 *   - avoiding a complete TCP stack reimplementation, with a modified TCP state
 *     machine focused on the translation of observed events instead
 *   - mirroring TCP dynamics as described above and hence avoiding the need for
 *     segmentation, explicit queueing, and reassembly of segments
 * - security:
 *   - no dynamic memory allocation is performed
 *   - TODO: synflood protection
 *
 * Portability is limited by usage of Linux-specific socket options.
 *
 *
 * Limits
 * ------
 *
 * To avoid the need for dynamic memory allocation, a maximum, reasonable amount
 * of connections is defined by TCP_MAX_CONNS (currently 128k).
 *
 * Data needs to linger on sockets as long as it's not acknowledged by the
 * guest, and is read using MSG_PEEK into preallocated static buffers sized
 * to the maximum supported window, 16 MiB ("discard" buffer, for already-sent
 * data) plus a number of maximum-MSS-sized buffers. This imposes a practical
 * limitation on window scaling, that is, the maximum factor is 256. Larger
 * factors will be accepted, but resulting, larger values are never advertised
 * to the other side, and not used while queueing data.
 *
 *
 * Ports
 * -----
 *
 * To avoid the need for ad-hoc configuration of port forwarding or allowed
 * ports, listening sockets can be opened and bound to all unbound ports on the
 * host, as far as process capabilities allow. This service needs to be started
 * after any application proxy that needs to bind to local ports. Mapped ports
 * can also be configured explicitly.
 *
 * No port translation is needed for connections initiated remotely or by the
 * local host: source port from socket is reused while establishing connections
 * to the guest.
 *
 * For connections initiated by the guest, it's not possible to force the same
 * source port as connections are established by the host kernel: that's the
 * only port translation needed.
 *
 *
 * Connection tracking and storage
 * -------------------------------
 *
 * Connections are tracked by struct tcp_tap_conn entries in the @tc
 * array, containing addresses, ports, TCP states and parameters. This
 * is statically allocated and indexed by an arbitrary connection
 * number. The array is compacted whenever a connection is closed, by
 * remapping the highest connection index in use to the one freed up.
 *
 * References used for the epoll interface report the connection index used for
 * the @tc array.
 *
 * IPv4 addresses are stored as IPv4-mapped IPv6 addresses to avoid the need for
 * separate data structures depending on the protocol version.
 *
 * - Inbound connection requests (to the guest) are mapped using the triple
 *   < source IP address, source port, destination port >
 * - Outbound connection requests (from the guest) are mapped using the triple
 *   < destination IP address, destination port, source port >
 *   where the source port is the one used by the guest, not the one used by the
 *   corresponding host socket
 *
 *
 * Initialisation
 * --------------
 *
 * Up to 2^15 + 2^14 listening sockets (excluding ephemeral ports, repeated for
 * IPv4 and IPv6) can be opened and bound to wildcard addresses. Some will fail
 * to bind (for low ports, or ports already bound, e.g. by a proxy). These are
 * added to the epoll list, with no separate storage.
 *
 *
 * Events and states
 * -----------------
 *
 * Instead of tracking connection states using a state machine, connection
 * events are used to determine state and actions for a given connection. This
 * makes the implementation simpler as most of the relevant tasks deal with
 * reactions to events, rather than state-associated actions. For user
 * convenience, approximate states are mapped in logs from events by
 * @tcp_state_str.
 *
 * The events are:
 *
 * - SOCK_ACCEPTED	connection accepted from socket, SYN sent to tap/guest
 *
 * - TAP_SYN_RCVD	tap/guest initiated connection, SYN received
 *
 * - TAP_SYN_ACK_SENT	SYN, ACK sent to tap/guest, valid for TAP_SYN_RCVD only
 *
 * - ESTABLISHED	connection established, the following events are valid:
 *
 * - SOCK_FIN_RCVD	FIN (EPOLLRDHUP) received from socket
 *
 * - SOCK_FIN_SENT	FIN (write shutdown) sent to socket
 *
 * - TAP_FIN_RCVD	FIN received from tap/guest
 *
 * - TAP_FIN_SENT	FIN sent to tap/guest
 *
 * - TAP_FIN_ACKED	ACK to FIN seen from tap/guest
 *
 * Setting any event in CONN_STATE_BITS (SOCK_ACCEPTED, TAP_SYN_RCVD,
 * ESTABLISHED) clears all the other events, as those represent the fundamental
 * connection states. No events (events == CLOSED) means the connection is
 * closed.
 *
 * Connection setup
 * ----------------
 *
 * - inbound connection (from socket to guest): on accept() from listening
 *   socket, the new socket is mapped in connection tracking table, and
 *   three-way handshake initiated towards the guest, advertising MSS and window
 *   size and scaling from socket parameters
 * - outbound connection (from guest to socket): on SYN segment from guest, a
 *   new socket is created and mapped in connection tracking table, setting
 *   MSS and window clamping from header and option of the observed SYN segment
 *
 *
 * Aging and timeout
 * -----------------
 *
 * Timeouts are implemented by means of timerfd timers, set based on flags:
 *
 * - SYN_TIMEOUT: if no ACK is received from tap/guest during handshake (flag
 *   ACK_FROM_TAP_DUE without ESTABLISHED event) within this time, reset the
 *   connection
 *
 * - ACK_TIMEOUT: if no ACK segment was received from tap/guest, after sending
 *   data (flag ACK_FROM_TAP_DUE with ESTABLISHED event), re-send data from the
 *   socket and reset sequence to what was acknowledged. If this persists for
 *   more than TCP_MAX_RETRANS times in a row, reset the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was sent to tap/guest (flag ACK_FROM_TAP_DUE
 *   with TAP_FIN_SENT event), and no ACK is received within this time, reset
 *   the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was acknowledged by tap/guest and a FIN
 *   segment (write shutdown) was sent via socket (events SOCK_FIN_SENT and
 *   TAP_FIN_ACKED), but no socket activity is detected from the socket within
 *   this time, reset the connection
 *
 * - ACT_TIMEOUT, in the presence of any event: if no activity is detected on
 *   either side, the connection is reset
 *
 * - ACK_INTERVAL elapsed after data segment received from tap without having
 *   sent an ACK segment, or zero-sized window advertised to tap/guest (flag
 *   ACK_TO_TAP_DUE): forcibly check if an ACK segment can be sent
 *
 *
 * Summary of data flows (with ESTABLISHED event)
 * ----------------------------------------------
 *
 * @seq_to_tap:		next sequence for packets to tap/guest
 * @seq_ack_from_tap:	last ACK number received from tap/guest
 * @seq_from_tap:	next sequence for packets from tap/guest (expected)
 * @seq_ack_to_tap:	last ACK number sent to tap/guest
 *
 * @seq_init_from_tap:	initial sequence number from tap/guest
 * @seq_init_to_tap:	initial sequence number from tap/guest
 *
 * @wnd_from_tap:	last window size received from tap, never scaled
 * @wnd_from_tap:	last window size advertised from tap, never scaled
 *
 * - from socket to tap/guest:
 *   - on new data from socket:
 *     - peek into buffer
 *     - send data to tap/guest:
 *       - starting at offset (@seq_to_tap - @seq_ack_from_tap)
 *       - in MSS-sized segments
 *       - increasing @seq_to_tap at each segment
 *       - up to window (until @seq_to_tap - @seq_ack_from_tap <= @wnd_from_tap)
 *     - on read error, send RST to tap/guest, close socket
 *     - on zero read, send FIN to tap/guest, set TAP_FIN_SENT
 *   - on ACK from tap/guest:
 *     - set @ts_ack_from_tap
 *     - check if it's the second duplicated ACK
 *     - consume buffer by difference between new ack_seq and @seq_ack_from_tap
 *     - update @seq_ack_from_tap from ack_seq in header
 *     - on two duplicated ACKs, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend with steps listed above
 *
 * - from tap/guest to socket:
 *   - on packet from tap/guest:
 *     - set @ts_tap_act
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - in ESTABLISHED state, send ACK to tap as soon as we queue to the
 *       socket. In other states, query socket for TCP_INFO, set
 *       @seq_ack_to_tap to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap/guest
 *
 *
 * PASTA mode
 * ==========
 *
 * For traffic directed to TCP ports configured for mapping to the tuntap device
 * in the namespace, and for non-local traffic coming from the tuntap device,
 * the implementation is identical as the PASST mode described in the previous
 * section.
 *
 * For local traffic directed to TCP ports configured for direct mapping between
 * namespaces, see the implementation in tcp_splice.c.
 */

#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <arpa/inet.h>

#include "checksum.h"
#include "util.h"
#include "iov.h"
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"
#include "pcap.h"
#include "tcp_splice.h"
#include "log.h"
#include "inany.h"
#include "flow.h"
#include "linux_dep.h"

#include "flow_table.h"
#include "tcp_internal.h"
#include "tcp_buf.h"

/* MSS rounding: see SET_MSS() */
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			14600		/* RFC 6928 */

#define ACK_INTERVAL			10		/* ms */
#define SYN_TIMEOUT			10		/* s */
#define ACK_TIMEOUT			2
#define FIN_TIMEOUT			60
#define ACT_TIMEOUT			7200

#define LOW_RTT_TABLE_SIZE		8
#define LOW_RTT_THRESHOLD		10 /* us */

#define ACK_IF_NEEDED	0		/* See tcp_send_flag() */

#define CONN_IS_CLOSING(conn)						\
	(((conn)->events & ESTABLISHED) &&				\
	 ((conn)->events & (SOCK_FIN_RCVD | TAP_FIN_RCVD)))
#define CONN_HAS(conn, set)	(((conn)->events & (set)) == (set))

static const char *tcp_event_str[] __attribute((__unused__)) = {
	"SOCK_ACCEPTED", "TAP_SYN_RCVD", "ESTABLISHED", "TAP_SYN_ACK_SENT",

	"SOCK_FIN_RCVD", "SOCK_FIN_SENT", "TAP_FIN_RCVD", "TAP_FIN_SENT",
	"TAP_FIN_ACKED",
};

static const char *tcp_state_str[] __attribute((__unused__)) = {
	"SYN_RCVD", "SYN_SENT", "ESTABLISHED",
	"SYN_RCVD",	/* approximately maps to TAP_SYN_ACK_SENT */

	/* Passive close: */
	"CLOSE_WAIT", "CLOSE_WAIT", "LAST_ACK", "LAST_ACK", "LAST_ACK",
	/* Active close (+5): */
	"CLOSING", "FIN_WAIT_1", "FIN_WAIT_1", "FIN_WAIT_2", "TIME_WAIT",
};

static const char *tcp_flag_str[] __attribute((__unused__)) = {
	"STALLED", "LOCAL", "ACTIVE_CLOSE", "ACK_TO_TAP_DUE",
	"ACK_FROM_TAP_DUE",
};

/* Listening sockets, used for automatic port forwarding in pasta mode only */
static int tcp_sock_init_ext	[NUM_PORTS][IP_VERSIONS];
static int tcp_sock_ns		[NUM_PORTS][IP_VERSIONS];

/* Table of our guest side addresses with very low RTT (assumed to be local to
 * the host), LRU
 */
static union inany_addr low_rtt_dst[LOW_RTT_TABLE_SIZE];

char		tcp_buf_discard		[MAX_WINDOW];

/* Does the kernel support TCP_PEEK_OFF? */
bool peek_offset_cap;

/* Size of data returned by TCP_INFO getsockopt() */
socklen_t tcp_info_size;

#define tcp_info_cap(f_)						\
	((offsetof(struct tcp_info_linux, tcpi_##f_) +			\
	  sizeof(((struct tcp_info_linux *)NULL)->tcpi_##f_)) <= tcp_info_size)

/* Kernel reports sending window in TCP_INFO (kernel commit 8f7baad7f035) */
#define snd_wnd_cap	tcp_info_cap(snd_wnd)
/* Kernel reports bytes acked in TCP_INFO (kernel commit 0df48c26d84) */
#define bytes_acked_cap	tcp_info_cap(bytes_acked)
/* Kernel reports minimum RTT in TCP_INFO (kernel commit cd9b266095f4) */
#define min_rtt_cap	tcp_info_cap(min_rtt)

/* sendmsg() to socket */
static struct iovec	tcp_iov			[UIO_MAXIOV];

/* Pools for pre-opened sockets (in init) */
int init_sock_pool4		[TCP_SOCK_POOL_SIZE];
int init_sock_pool6		[TCP_SOCK_POOL_SIZE];

/**
 * conn_at_sidx() - Get TCP connection specific flow at given sidx
 * @sidx:	Flow and side to retrieve
 *
 * Return: TCP connection at @sidx, or NULL of @sidx is invalid.  Asserts if the
 *         flow at @sidx is not FLOW_TCP.
 */
static struct tcp_tap_conn *conn_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_TCP);
	return &flow->tcp;
}

/**
 * tcp_set_peek_offset() - Set SO_PEEK_OFF offset on a socket if supported
 * @s:          Socket to update
 * @offset:     Offset in bytes
 *
 * Return:      -1 when it fails, 0 otherwise.
 */
int tcp_set_peek_offset(int s, int offset)
{
	if (!peek_offset_cap)
		return 0;

	if (setsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &offset, sizeof(offset))) {
		err("Failed to set SO_PEEK_OFF to %i in socket %i", offset, s);
		return -1;
	}
	return 0;
}

/**
 * tcp_conn_epoll_events() - epoll events mask for given connection state
 * @events:	Current connection events
 * @conn_flags	Connection flags
 *
 * Return: epoll events mask corresponding to implied connection state
 */
static uint32_t tcp_conn_epoll_events(uint8_t events, uint8_t conn_flags)
{
	if (!events)
		return 0;

	if (events & ESTABLISHED) {
		if (events & TAP_FIN_SENT)
			return EPOLLET;

		if (conn_flags & STALLED)
			return EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;

		return EPOLLIN | EPOLLRDHUP;
	}

	if (events == TAP_SYN_RCVD)
		return EPOLLOUT | EPOLLET | EPOLLRDHUP;

	return EPOLLET | EPOLLRDHUP;
}

/**
 * tcp_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_epoll_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	int m = conn->in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	union epoll_ref ref = { .type = EPOLL_TYPE_TCP, .fd = conn->sock,
		                .flowside = FLOW_SIDX(conn, !TAPSIDE(conn)), };
	struct epoll_event ev = { .data.u64 = ref.u64 };

	if (conn->events == CLOSED) {
		if (conn->in_epoll)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->sock, &ev);
		if (conn->timer != -1)
			epoll_ctl(c->epollfd, EPOLL_CTL_DEL, conn->timer, &ev);
		return 0;
	}

	ev.events = tcp_conn_epoll_events(conn->events, conn->flags);

	if (epoll_ctl(c->epollfd, m, conn->sock, &ev))
		return -errno;

	conn->in_epoll = true;

	if (conn->timer != -1) {
		union epoll_ref ref_t = { .type = EPOLL_TYPE_TCP_TIMER,
					  .fd = conn->sock,
					  .flow = FLOW_IDX(conn) };
		struct epoll_event ev_t = { .data.u64 = ref_t.u64,
					    .events = EPOLLIN | EPOLLET };

		if (epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->timer, &ev_t))
			return -errno;
	}

	return 0;
}

/**
 * tcp_timer_ctl() - Set timerfd based on flags/events, create timerfd if needed
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * #syscalls timerfd_create timerfd_settime
 */
static void tcp_timer_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	struct itimerspec it = { { 0 }, { 0 } };

	if (conn->events == CLOSED)
		return;

	if (conn->timer == -1) {
		union epoll_ref ref = { .type = EPOLL_TYPE_TCP_TIMER,
					.fd = conn->sock,
					.flow = FLOW_IDX(conn) };
		struct epoll_event ev = { .data.u64 = ref.u64,
					  .events = EPOLLIN | EPOLLET };
		int fd;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1 || fd > FD_REF_MAX) {
			flow_dbg(conn, "failed to get timer: %s",
				 strerror(errno));
			if (fd > -1)
				close(fd);
			conn->timer = -1;
			return;
		}
		conn->timer = fd;

		if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->timer, &ev)) {
			flow_dbg(conn, "failed to add timer: %s",
				 strerror(errno));
			close(conn->timer);
			conn->timer = -1;
			return;
		}
	}

	if (conn->flags & ACK_TO_TAP_DUE) {
		it.it_value.tv_nsec = (long)ACK_INTERVAL * 1000 * 1000;
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED))
			it.it_value.tv_sec = SYN_TIMEOUT;
		else
			it.it_value.tv_sec = ACK_TIMEOUT;
	} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
		it.it_value.tv_sec = FIN_TIMEOUT;
	} else {
		it.it_value.tv_sec = ACT_TIMEOUT;
	}

	flow_dbg(conn, "timer expires in %llu.%03llus",
		 (unsigned long long)it.it_value.tv_sec,
		 (unsigned long long)it.it_value.tv_nsec / 1000 / 1000);

	if (timerfd_settime(conn->timer, 0, &it, NULL))
		flow_err(conn, "failed to set timer: %s", strerror(errno));
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on STALLED flag
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
		  unsigned long flag)
{
	if (flag & (flag - 1)) {
		int flag_index = fls(~flag);

		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s dropped", tcp_flag_str[flag_index]);
	} else {
		int flag_index = fls(flag);

		if (conn->flags & flag) {
			/* Special case: setting ACK_FROM_TAP_DUE on a
			 * connection where it's already set is used to
			 * re-schedule the existing timer.
			 * TODO: define clearer semantics for timer-related
			 * flags and factor this into the logic below.
			 */
			if (flag == ACK_FROM_TAP_DUE)
				tcp_timer_ctl(c, conn);

			return;
		}

		conn->flags |= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_flag_str[flag_index]);
	}

	if (flag == STALLED || flag == ~STALLED)
		tcp_epoll_ctl(c, conn);

	if (flag == ACK_FROM_TAP_DUE || flag == ACK_TO_TAP_DUE		  ||
	    (flag == ~ACK_FROM_TAP_DUE && (conn->flags & ACK_TO_TAP_DUE)) ||
	    (flag == ~ACK_TO_TAP_DUE   && (conn->flags & ACK_FROM_TAP_DUE)))
		tcp_timer_ctl(c, conn);
}

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @c:		Execution context
 * @conn:	Connection pointer
 * @event:	Connection event
 */
void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
		   unsigned long event)
{
	int prev, new, num = fls(event);

	if (conn->events & event)
		return;

	prev = fls(conn->events);
	if (conn->flags & ACTIVE_CLOSE)
		prev += 5;

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED))
		prev++;		/* i.e. SOCK_FIN_RCVD, not TAP_SYN_ACK_SENT */

	if (event == CLOSED || (event & CONN_STATE_BITS))
		conn->events = event;
	else
		conn->events |= event;

	new = fls(conn->events);

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED)) {
		num++;
		new++;
	}
	if (conn->flags & ACTIVE_CLOSE)
		new += 5;

	if (prev != new)
		flow_dbg(conn, "%s: %s -> %s",
			 num == -1 	       ? "CLOSED" : tcp_event_str[num],
			 prev == -1	       ? "CLOSED" : tcp_state_str[prev],
			 (new == -1 || num == -1) ? "CLOSED" : tcp_state_str[new]);
	else
		flow_dbg(conn, "%s",
			 num == -1 	       ? "CLOSED" : tcp_event_str[num]);

	if (event == CLOSED)
		flow_hash_remove(c, TAP_SIDX(conn));
	else if ((event == TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_RCVD))
		conn_flag(c, conn, ACTIVE_CLOSE);
	else
		tcp_epoll_ctl(c, conn);

	if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
		tcp_timer_ctl(c, conn);
}

/**
 * tcp_rtt_dst_low() - Check if low RTT was seen for connection endpoint
 * @conn:	Connection pointer
 *
 * Return: 1 if destination is in low RTT table, 0 otherwise
 */
static int tcp_rtt_dst_low(const struct tcp_tap_conn *conn)
{
	const struct flowside *tapside = TAPFLOW(conn);
	int i;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++)
		if (inany_equals(&tapside->oaddr, low_rtt_dst + i))
			return 1;

	return 0;
}

/**
 * tcp_rtt_dst_check() - Check tcpi_min_rtt, insert endpoint in table if low
 * @conn:	Connection pointer
 * @tinfo:	Pointer to struct tcp_info for socket
 */
static void tcp_rtt_dst_check(const struct tcp_tap_conn *conn,
			      const struct tcp_info_linux *tinfo)
{
	const struct flowside *tapside = TAPFLOW(conn);
	int i, hole = -1;

	if (!min_rtt_cap ||
	    (int)tinfo->tcpi_min_rtt > LOW_RTT_THRESHOLD)
		return;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++) {
		if (inany_equals(&tapside->oaddr, low_rtt_dst + i))
			return;
		if (hole == -1 && IN6_IS_ADDR_UNSPECIFIED(low_rtt_dst + i))
			hole = i;
	}

	/* Keep gcc 12 happy: this won't actually happen because the table is
	 * guaranteed to have a hole, see the second memcpy() below.
	 */
	if (hole == -1)
		return;

	low_rtt_dst[hole++] = tapside->oaddr;
	if (hole == LOW_RTT_TABLE_SIZE)
		hole = 0;
	inany_from_af(low_rtt_dst + hole, AF_INET6, &in6addr_any);
}

/**
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.5 usage)
 * @conn:	Connection pointer
 */
static void tcp_get_sndbuf(struct tcp_tap_conn *conn)
{
	int s = conn->sock, sndbuf;
	socklen_t sl;
	uint64_t v;

	sl = sizeof(sndbuf);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sl)) {
		SNDBUF_SET(conn, WINDOW_DEFAULT);
		return;
	}

	v = sndbuf;
	if (v >= SNDBUF_BIG)
		v /= 2;
	else if (v > SNDBUF_SMALL)
		v -= v * (v - SNDBUF_SMALL) / (SNDBUF_BIG - SNDBUF_SMALL) / 2;

	SNDBUF_SET(conn, MIN(INT_MAX, v));
}

/**
 * tcp_sock_set_bufsize() - Set SO_RCVBUF and SO_SNDBUF to maximum values
 * @s:		Socket, can be -1 to avoid check in the caller
 */
static void tcp_sock_set_bufsize(const struct ctx *c, int s)
{
	int v = INT_MAX / 2; /* Kernel clamps and rounds, no need to check */

	if (s == -1)
		return;

	if (!c->low_rmem && setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)))
		trace("TCP: failed to set SO_RCVBUF to %i", v);

	if (!c->low_wmem && setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)))
		trace("TCP: failed to set SO_SNDBUF to %i", v);
}

/**
 * tcp_update_check_tcp4() - Calculate TCP checksum for IPv4
 * @iph:	IPv4 header
 * @iov:	Pointer to the array of IO vectors
 * @iov_cnt:	Length of the array
 * @l4offset:	IPv4 payload offset in the iovec array
 */
static void tcp_update_check_tcp4(const struct iphdr *iph,
				  const struct iovec *iov, int iov_cnt,
				  size_t l4offset)
{
	uint16_t l4len = ntohs(iph->tot_len) - sizeof(struct iphdr);
	struct in_addr saddr = { .s_addr = iph->saddr };
	struct in_addr daddr = { .s_addr = iph->daddr };
	size_t check_ofs;
	uint16_t *check;
	int check_idx;
	uint32_t sum;
	char *ptr;

	sum = proto_ipv4_header_psum(l4len, IPPROTO_TCP, saddr, daddr);

	check_idx = iov_skip_bytes(iov, iov_cnt,
				   l4offset + offsetof(struct tcphdr, check),
				   &check_ofs);

	if (check_idx >= iov_cnt) {
		err("TCP4 buffer is too small, iov size %zd, check offset %zd",
		    iov_size(iov, iov_cnt),
		    l4offset + offsetof(struct tcphdr, check));
		return;
	}

	if (check_ofs + sizeof(*check) > iov[check_idx].iov_len) {
		err("TCP4 checksum field memory is not contiguous "
		    "check_ofs %zd check_idx %d iov_len %zd",
		    check_ofs, check_idx, iov[check_idx].iov_len);
		return;
	}

	ptr = (char *)iov[check_idx].iov_base + check_ofs;
	if ((uintptr_t)ptr & (__alignof__(*check) - 1)) {
		err("TCP4 checksum field is not correctly aligned in memory");
		return;
	}

	check = (uint16_t *)ptr;

	*check = 0;
	*check = csum_iov(iov, iov_cnt, l4offset, sum);
}

/**
 * tcp_update_check_tcp6() - Calculate TCP checksum for IPv6
 * @ip6h:	IPv6 header
 * @iov:	Pointer to the array of IO vectors
 * @iov_cnt:	Length of the array
 * @l4offset:	IPv6 payload offset in the iovec array
 */
static void tcp_update_check_tcp6(const struct ipv6hdr *ip6h,
				  const struct iovec *iov, int iov_cnt,
				  size_t l4offset)
{
	uint16_t l4len = ntohs(ip6h->payload_len);
	size_t check_ofs;
	uint16_t *check;
	int check_idx;
	uint32_t sum;
	char *ptr;

	sum = proto_ipv6_header_psum(l4len, IPPROTO_TCP, &ip6h->saddr,
				     &ip6h->daddr);

	check_idx = iov_skip_bytes(iov, iov_cnt,
				   l4offset + offsetof(struct tcphdr, check),
				   &check_ofs);

	if (check_idx >= iov_cnt) {
		err("TCP6 buffer is too small, iov size %zd, check offset %zd",
		    iov_size(iov, iov_cnt),
		    l4offset + offsetof(struct tcphdr, check));
		return;
	}

	if (check_ofs + sizeof(*check) > iov[check_idx].iov_len) {
		err("TCP6 checksum field memory is not contiguous "
		    "check_ofs %zd check_idx %d iov_len %zd",
		    check_ofs, check_idx, iov[check_idx].iov_len);
		return;
	}

	ptr = (char *)iov[check_idx].iov_base + check_ofs;
	if ((uintptr_t)ptr & (__alignof__(*check) - 1)) {
		err("TCP6 checksum field is not correctly aligned in memory");
		return;
	}

	check = (uint16_t *)ptr;

	*check = 0;
	*check = csum_iov(iov, iov_cnt, l4offset, sum);
}

/**
 * tcp_opt_get() - Get option, and value if any, from TCP header
 * @opts:	Pointer to start of TCP options in header
 * @len:	Length of buffer, excluding TCP header -- NOT checked here!
 * @type_find:	Option type to look for
 * @optlen_set:	Optional, filled with option length if passed
 * @value_set:	Optional, set to start of option value if passed
 *
 * Return: option value, meaningful for up to 4 bytes, -1 if not found
 */
static int tcp_opt_get(const char *opts, size_t len, uint8_t type_find,
		       uint8_t *optlen_set, const char **value_set)
{
	uint8_t type, optlen;

	if (!opts || !len)
		return -1;

	for (; len >= 2; opts += optlen, len -= optlen) {
		switch (*opts) {
		case OPT_EOL:
			return -1;
		case OPT_NOP:
			optlen = 1;
			break;
		default:
			type = *(opts++);

			if (*(uint8_t *)opts < 2 || *(uint8_t *)opts > len)
				return -1;

			optlen = *(opts++) - 2;
			len -= 2;

			if (type != type_find)
				break;

			if (optlen_set)
				*optlen_set = optlen;
			if (value_set)
				*value_set = opts;

			switch (optlen) {
			case 0:
				return 0;
			case 1:
				return *opts;
			case 2:
				return ntohs(*(uint16_t *)opts);
			default:
				return ntohl(*(uint32_t *)opts);
			}
		}
	}

	return -1;
}

/**
 * tcp_flow_defer() - Deferred per-flow handling (clean up closed connections)
 * @conn:	Connection to handle
 *
 * Return: true if the connection is ready to free, false otherwise
 */
bool tcp_flow_defer(const struct tcp_tap_conn *conn)
{
	if (conn->events != CLOSED)
		return false;

	close(conn->sock);
	if (conn->timer != -1)
		close(conn->timer);

	return true;
}

/**
 * tcp_defer_handler() - Handler for TCP deferred tasks
 * @c:		Execution context
 */
/* cppcheck-suppress [constParameterPointer, unmatchedSuppression] */
void tcp_defer_handler(struct ctx *c)
{
	tcp_payload_flush(c);
}

/**
 * tcp_fill_header() - Fill the TCP header fields for a given TCP segment.
 *
 * @th:		Pointer to the TCP header structure
 * @conn:	Pointer to the TCP connection structure
 * @seq:	Sequence number
 */
static void tcp_fill_header(struct tcphdr *th,
			    const struct tcp_tap_conn *conn, uint32_t seq)
{
	const struct flowside *tapside = TAPFLOW(conn);

	th->source = htons(tapside->oport);
	th->dest = htons(tapside->eport);
	th->seq = htonl(seq);
	th->ack_seq = htonl(conn->seq_ack_to_tap);
	if (conn->events & ESTABLISHED)	{
		th->window = htons(conn->wnd_to_tap);
	} else {
		unsigned wnd = conn->wnd_to_tap << conn->ws_to_tap;

		th->window = htons(MIN(wnd, USHRT_MAX));
	}
}

/**
 * tcp_fill_headers4() - Fill 802.3, IPv4, TCP headers in pre-cooked buffers
 * @conn:		Connection pointer
 * @taph:		tap backend specific header
 * @iph:		Pointer to IPv4 header
 * @bp:			Pointer to TCP header followed by TCP payload
 * @dlen:		TCP payload length
 * @check:		Checksum, if already known
 * @seq:		Sequence number for this segment
 * @no_tcp_csum:	Do not set TCP checksum
 *
 * Return: The IPv4 payload length, host order
 */
static size_t tcp_fill_headers4(const struct tcp_tap_conn *conn,
				struct tap_hdr *taph,
				struct iphdr *iph, struct tcp_payload_t *bp,
				size_t dlen, const uint16_t *check,
				uint32_t seq, bool no_tcp_csum)
{
	const struct flowside *tapside = TAPFLOW(conn);
	const struct in_addr *src4 = inany_v4(&tapside->oaddr);
	const struct in_addr *dst4 = inany_v4(&tapside->eaddr);
	size_t l4len = dlen + sizeof(bp->th);
	size_t l3len = l4len + sizeof(*iph);

	ASSERT(src4 && dst4);

	iph->tot_len = htons(l3len);
	iph->saddr = src4->s_addr;
	iph->daddr = dst4->s_addr;

	iph->check = check ? *check :
			     csum_ip4_header(l3len, IPPROTO_TCP, *src4, *dst4);

	tcp_fill_header(&bp->th, conn, seq);

	if (no_tcp_csum) {
		bp->th.check = 0;
	} else {
		const struct iovec iov = {
			.iov_base = bp,
			.iov_len = ntohs(iph->tot_len) - sizeof(struct iphdr),
		};

		tcp_update_check_tcp4(iph, &iov, 1, 0);
	}

	tap_hdr_update(taph, l3len + sizeof(struct ethhdr));

	return l4len;
}

/**
 * tcp_fill_headers6() - Fill 802.3, IPv6, TCP headers in pre-cooked buffers
 * @conn:		Connection pointer
 * @taph:		tap backend specific header
 * @ip6h:		Pointer to IPv6 header
 * @bp:			Pointer to TCP header followed by TCP payload
 * @dlen:		TCP payload length
 * @check:		Checksum, if already known
 * @seq:		Sequence number for this segment
 * @no_tcp_csum:	Do not set TCP checksum
 *
 * Return: The IPv6 payload length, host order
 */
static size_t tcp_fill_headers6(const struct tcp_tap_conn *conn,
				struct tap_hdr *taph,
				struct ipv6hdr *ip6h, struct tcp_payload_t *bp,
				size_t dlen, uint32_t seq, bool no_tcp_csum)
{
	const struct flowside *tapside = TAPFLOW(conn);
	size_t l4len = dlen + sizeof(bp->th);

	ip6h->payload_len = htons(l4len);
	ip6h->saddr = tapside->oaddr.a6;
	ip6h->daddr = tapside->eaddr.a6;

	ip6h->hop_limit = 255;
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_TCP;

	ip6h->flow_lbl[0] = (conn->sock >> 16) & 0xf;
	ip6h->flow_lbl[1] = (conn->sock >> 8) & 0xff;
	ip6h->flow_lbl[2] = (conn->sock >> 0) & 0xff;

	tcp_fill_header(&bp->th, conn, seq);

	if (no_tcp_csum) {
		bp->th.check = 0;
	} else {
		const struct iovec iov = {
			.iov_base = bp,
			.iov_len = ntohs(ip6h->payload_len)
		};

		tcp_update_check_tcp6(ip6h, &iov, 1, 0);
	}

	tap_hdr_update(taph, l4len + sizeof(*ip6h) + sizeof(struct ethhdr));

	return l4len;
}

/**
 * tcp_l2_buf_fill_headers() - Fill 802.3, IP, TCP headers in pre-cooked buffers
 * @conn:	Connection pointer
 * @iov:	Pointer to an array of iovec of TCP pre-cooked buffers
 * @dlen:	TCP payload length
 * @check:	Checksum, if already known
 * @seq:	Sequence number for this segment
 * @no_tcp_csum: Do not set TCP checksum
 *
 * Return: IP payload length, host order
 */
size_t tcp_l2_buf_fill_headers(const struct tcp_tap_conn *conn,
			       struct iovec *iov, size_t dlen,
			       const uint16_t *check, uint32_t seq,
			       bool no_tcp_csum)
{
	const struct flowside *tapside = TAPFLOW(conn);
	const struct in_addr *a4 = inany_v4(&tapside->oaddr);

	if (a4) {
		return tcp_fill_headers4(conn, iov[TCP_IOV_TAP].iov_base,
					 iov[TCP_IOV_IP].iov_base,
					 iov[TCP_IOV_PAYLOAD].iov_base, dlen,
					 check, seq, no_tcp_csum);
	}

	return tcp_fill_headers6(conn, iov[TCP_IOV_TAP].iov_base,
				 iov[TCP_IOV_IP].iov_base,
				 iov[TCP_IOV_PAYLOAD].iov_base, dlen,
				 seq, no_tcp_csum);
}

/**
 * tcp_update_seqack_wnd() - Update ACK sequence and window to guest/tap
 * @c:		Execution context
 * @conn:	Connection pointer
 * @force_seq:	Force ACK sequence to latest segment, instead of checking socket
 * @tinfo:	tcp_info from kernel, can be NULL if not pre-fetched
 *
 * Return: 1 if sequence or window were updated, 0 otherwise
 */
int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
			  bool force_seq, struct tcp_info_linux *tinfo)
{
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap << conn->ws_to_tap;
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	/* cppcheck-suppress [ctunullpointer, unmatchedSuppression] */
	socklen_t sl = sizeof(*tinfo);
	struct tcp_info_linux tinfo_new;
	uint32_t new_wnd_to_tap = prev_wnd_to_tap;
	int s = conn->sock;

	if (!bytes_acked_cap) {
		conn->seq_ack_to_tap = conn->seq_from_tap;
		if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
			conn->seq_ack_to_tap = prev_ack_to_tap;
	} else {
		if ((unsigned)SNDBUF_GET(conn) < SNDBUF_SMALL ||
		    tcp_rtt_dst_low(conn) || CONN_IS_CLOSING(conn) ||
		    (conn->flags & LOCAL) || force_seq) {
			conn->seq_ack_to_tap = conn->seq_from_tap;
		} else if (conn->seq_ack_to_tap != conn->seq_from_tap) {
			if (!tinfo) {
				tinfo = &tinfo_new;
				if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl))
					return 0;
			}

			conn->seq_ack_to_tap = tinfo->tcpi_bytes_acked +
				conn->seq_init_from_tap;

			if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
				conn->seq_ack_to_tap = prev_ack_to_tap;
		}
	}

	if (!snd_wnd_cap) {
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN(SNDBUF_GET(conn), MAX_WINDOW);
		conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap,
				       USHRT_MAX);
		goto out;
	}

	if (!tinfo) {
		if (prev_wnd_to_tap > WINDOW_DEFAULT) {
			goto out;
		}
		tinfo = &tinfo_new;
		if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl)) {
			goto out;
		}
	}

	if ((conn->flags & LOCAL) || tcp_rtt_dst_low(conn)) {
		new_wnd_to_tap = tinfo->tcpi_snd_wnd;
	} else {
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN((int)tinfo->tcpi_snd_wnd,
				     SNDBUF_GET(conn));
	}

	new_wnd_to_tap = MIN(new_wnd_to_tap, MAX_WINDOW);
	if (!(conn->events & ESTABLISHED))
		new_wnd_to_tap = MAX(new_wnd_to_tap, WINDOW_DEFAULT);

	conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap, USHRT_MAX);

	/* Certain cppcheck versions, e.g. 2.12.0 have a bug where they think
	 * the MIN() above restricts conn->wnd_to_tap to be zero.  That's
	 * clearly incorrect, but until the bug is fixed, work around it.
	 *   https://bugzilla.redhat.com/show_bug.cgi?id=2240705
	 *   https://sourceforge.net/p/cppcheck/discussion/general/thread/f5b1a00646/
	 */
	/* cppcheck-suppress [knownConditionTrueFalse, unmatchedSuppression] */
	if (!conn->wnd_to_tap)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

out:
	return new_wnd_to_tap       != prev_wnd_to_tap ||
	       conn->seq_ack_to_tap != prev_ack_to_tap;
}

/**
 * tcp_update_seqack_from_tap() - ACK number from tap and related flags/counters
 * @c:		Execution context
 * @conn:	Connection pointer
 * @seq		Current ACK sequence, host order
 */
static void tcp_update_seqack_from_tap(const struct ctx *c,
				       struct tcp_tap_conn *conn, uint32_t seq)
{
	if (seq == conn->seq_to_tap)
		conn_flag(c, conn, ~ACK_FROM_TAP_DUE);

	if (SEQ_GT(seq, conn->seq_ack_from_tap)) {
		/* Forward progress, but more data to acknowledge: reschedule */
		if (SEQ_LT(seq, conn->seq_to_tap))
			conn_flag(c, conn, ACK_FROM_TAP_DUE);

		conn->retrans = 0;
		conn->seq_ack_from_tap = seq;
	}
}

/**
 * tcp_prepare_flags() - Prepare header for flags-only segment (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 * @th:		TCP header to update
 * @data:	buffer to store TCP option
 * @optlen:	size of the TCP option buffer (output parameter)
 *
 * Return: < 0 error code on connection reset,
 *	     0 if there is no flag to send
 *	     1 otherwise
 */
int tcp_prepare_flags(const struct ctx *c, struct tcp_tap_conn *conn,
		      int flags, struct tcphdr *th, struct tcp_syn_opts *opts,
		      size_t *optlen)
{
	struct tcp_info_linux tinfo = { 0 };
	socklen_t sl = sizeof(tinfo);
	int s = conn->sock;

	if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap) &&
	    !flags && conn->wnd_to_tap) {
		conn_flag(c, conn, ~ACK_TO_TAP_DUE);
		return 0;
	}

	if (getsockopt(s, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		conn_event(c, conn, CLOSED);
		return -ECONNRESET;
	}

	if (!(conn->flags & LOCAL))
		tcp_rtt_dst_check(conn, &tinfo);

	if (!tcp_update_seqack_wnd(c, conn, !!flags, &tinfo) && !flags)
		return 0;

	*optlen = 0;
	if (flags & SYN) {
		int mss;

		if (c->mtu == -1) {
			mss = tinfo.tcpi_snd_mss;
		} else {
			mss = c->mtu - sizeof(struct tcphdr);
			if (CONN_V4(conn))
				mss -= sizeof(struct iphdr);
			else
				mss -= sizeof(struct ipv6hdr);

			if (c->low_wmem &&
			    !(conn->flags & LOCAL) && !tcp_rtt_dst_low(conn))
				mss = MIN(mss, PAGE_SIZE);
			else if (mss > PAGE_SIZE)
				mss = ROUND_DOWN(mss, PAGE_SIZE);
		}

		conn->ws_to_tap = MIN(MAX_WS, tinfo.tcpi_snd_wscale);

		*opts = TCP_SYN_OPTS(mss, conn->ws_to_tap);
		*optlen = sizeof(*opts);
	} else if (!(flags & RST)) {
		flags |= ACK;
	}

	th->doff = (sizeof(*th) + *optlen) / 4;

	th->ack = !!(flags & ACK);
	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	if (th->ack) {
		if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap))
			conn_flag(c, conn, ~ACK_TO_TAP_DUE);
		else
			conn_flag(c, conn, ACK_TO_TAP_DUE);
	}

	if (th->fin)
		conn_flag(c, conn, ACK_FROM_TAP_DUE);

	/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
	if (th->fin || th->syn)
		conn->seq_to_tap++;

	return 1;
}

/**
 * tcp_send_flag() - Send segment with flags to tap (no payload)
 * @c:         Execution context
 * @conn:      Connection pointer
 * @flags:     TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_flag(const struct ctx *c, struct tcp_tap_conn *conn,
			 int flags)
{
	return tcp_buf_send_flag(c, conn, flags);
}

/**
 * tcp_rst_do() - Reset a tap connection: send RST segment to tap, close socket
 * @c:		Execution context
 * @conn:	Connection pointer
 */
void tcp_rst_do(const struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->events == CLOSED)
		return;

	if (!tcp_send_flag(c, conn, RST))
		conn_event(c, conn, CLOSED);
}

/**
 * tcp_get_tap_ws() - Get Window Scaling option for connection from tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_get_tap_ws(struct tcp_tap_conn *conn,
			   const char *opts, size_t optlen)
{
	int ws = tcp_opt_get(opts, optlen, OPT_WS, NULL, NULL);

	if (ws >= 0 && ws <= TCP_WS_MAX)
		conn->ws_from_tap = ws;
	else
		conn->ws_from_tap = 0;
}

/**
 * tcp_tap_window_update() - Process an updated window from tap side
 * @conn:	Connection pointer
 * @window:	Window value, host order, unscaled
 */
static void tcp_tap_window_update(struct tcp_tap_conn *conn, unsigned wnd)
{
	wnd = MIN(MAX_WINDOW, wnd << conn->ws_from_tap);

	/* Work-around for bug introduced in peer kernel code, commit
	 * e2142825c120 ("net: tcp: send zero-window ACK when no memory").
	 * We don't update if window shrank to zero.
	 */
	if (!wnd && SEQ_LT(conn->seq_ack_from_tap, conn->seq_to_tap))
		return;

	conn->wnd_from_tap = MIN(wnd >> conn->ws_from_tap, USHRT_MAX);

	/* FIXME: reflect the tap-side receiver's window back to the sock-side
	 * sender by adjusting SO_RCVBUF? */
}

/**
 * tcp_init_seq() - Calculate initial sequence number according to RFC 6528
 * @hash:	Hash of connection details
 * @now:	Current timestamp
 */
static uint32_t tcp_init_seq(uint64_t hash, const struct timespec *now)
{
	/* 32ns ticks, overflows 32 bits every 137s */
	uint32_t ns = (now->tv_sec * 1000000000 + now->tv_nsec) >> 5;

	return ((uint32_t)(hash >> 32) ^ (uint32_t)hash) + ns;
}

/**
 * tcp_conn_pool_sock() - Get socket for new connection from pre-opened pool
 * @pool:	Pool of pre-opened sockets
 *
 * Return: socket number if available, negative code if pool is empty
 */
int tcp_conn_pool_sock(int pool[])
{
	int s = -1, i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		SWAP(s, pool[i]);
		if (s >= 0)
			return s;
	}
	return -1;
}

/**
 * tcp_conn_new_sock() - Open and prepare new socket for connection
 * @c:		Execution context
 * @af:		Address family
 *
 * Return: socket number on success, negative code if socket creation failed
 */
static int tcp_conn_new_sock(const struct ctx *c, sa_family_t af)
{
	int s;

	s = socket(af, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);

	if (s > FD_REF_MAX) {
		close(s);
		return -EIO;
	}

	if (s < 0)
		return -errno;

	tcp_sock_set_bufsize(c, s);

	return s;
}

/**
 * tcp_conn_sock() - Obtain a connectable socket in the host/init namespace
 * @c:		Execution context
 * @af:		Address family (AF_INET or AF_INET6)
 *
 * Return: Socket fd on success, -errno on failure
 */
int tcp_conn_sock(const struct ctx *c, sa_family_t af)
{
	int *pool = af == AF_INET6 ? init_sock_pool6 : init_sock_pool4;
	int s;

	if ((s = tcp_conn_pool_sock(pool)) >= 0)
		return s;

	/* If the pool is empty we just open a new one without refilling the
	 * pool to keep latency down.
	 */
	if ((s = tcp_conn_new_sock(c, af)) >= 0)
		return s;

	err("TCP: Unable to open socket for new connection: %s",
	    strerror(-s));
	return -1;
}

/**
 * tcp_conn_tap_mss() - Get MSS value advertised by tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 *
 * Return: clamped MSS value
 */
static uint16_t tcp_conn_tap_mss(const struct tcp_tap_conn *conn,
				 const char *opts, size_t optlen)
{
	unsigned int mss;
	int ret;

	if ((ret = tcp_opt_get(opts, optlen, OPT_MSS, NULL, NULL)) < 0)
		mss = MSS_DEFAULT;
	else
		mss = ret;

	if (CONN_V4(conn))
		mss = MIN(MSS4, mss);
	else
		mss = MIN(MSS6, mss);

	return MIN(mss, USHRT_MAX);
}

/**
 * tcp_bind_outbound() - Bind socket to outbound address and interface if given
 * @c:		Execution context
 * @conn:	Connection entry for socket to bind
 * @s:		Outbound TCP socket
 */
static void tcp_bind_outbound(const struct ctx *c,
			      const struct tcp_tap_conn *conn, int s)
{
	const struct flowside *tgt = &conn->f.side[TGTSIDE];
	union sockaddr_inany bind_sa;
	socklen_t sl;


	pif_sockaddr(c, &bind_sa, &sl, PIF_HOST, &tgt->oaddr, tgt->oport);
	if (!inany_is_unspecified(&tgt->oaddr) || tgt->oport) {
		if (bind(s, &bind_sa.sa, sl)) {
			char sstr[INANY_ADDRSTRLEN];

			flow_dbg(conn,
				 "Can't bind TCP outbound socket to %s:%hu: %s",
				 inany_ntop(&tgt->oaddr, sstr, sizeof(sstr)),
				 tgt->oport, strerror(errno));
		}
	}

	if (bind_sa.sa_family == AF_INET) {
		if (*c->ip4.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip4.ifname_out,
				       strlen(c->ip4.ifname_out))) {
				flow_dbg(conn, "Can't bind IPv4 TCP socket to"
					 " interface %s: %s", c->ip4.ifname_out,
					 strerror(errno));
			}
		}
	} else if (bind_sa.sa_family == AF_INET6) {
		if (*c->ip6.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip6.ifname_out,
				       strlen(c->ip6.ifname_out))) {
				flow_dbg(conn, "Can't bind IPv6 TCP socket to"
					 " interface %s: %s", c->ip6.ifname_out,
					 strerror(errno));
			}
		}
	}
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address, pointer to in_addr or in6_addr
 * @daddr:	Destination address, pointer to in_addr or in6_addr
 * @th:		TCP header from tap: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 * @now:	Current timestamp
 */
static void tcp_conn_from_tap(const struct ctx *c, sa_family_t af,
			      const void *saddr, const void *daddr,
			      const struct tcphdr *th, const char *opts,
			      size_t optlen, const struct timespec *now)
{
	in_port_t srcport = ntohs(th->source);
	in_port_t dstport = ntohs(th->dest);
	const struct flowside *ini, *tgt;
	struct tcp_tap_conn *conn;
	union sockaddr_inany sa;
	union flow *flow;
	int s = -1, mss;
	uint64_t hash;
	socklen_t sl;

	if (!(flow = flow_alloc()))
		return;

	ini = flow_initiate_af(flow, PIF_TAP,
			       af, saddr, srcport, daddr, dstport);

	if (!(tgt = flow_target(c, flow, IPPROTO_TCP)))
		goto cancel;

	if (flow->f.pif[TGTSIDE] != PIF_HOST) {
		flow_err(flow, "No support for forwarding TCP from %s to %s",
			 pif_name(flow->f.pif[INISIDE]),
			 pif_name(flow->f.pif[TGTSIDE]));
		goto cancel;
	}

	conn = FLOW_SET_TYPE(flow, FLOW_TCP, tcp);

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0 ||
	    !inany_is_unicast(&ini->oaddr) || ini->oport == 0) {
		char sstr[INANY_ADDRSTRLEN], dstr[INANY_ADDRSTRLEN];

		debug("Invalid endpoint in TCP SYN: %s:%hu -> %s:%hu",
		      inany_ntop(&ini->eaddr, sstr, sizeof(sstr)), ini->eport,
		      inany_ntop(&ini->oaddr, dstr, sizeof(dstr)), ini->oport);
		goto cancel;
	}

	if ((s = tcp_conn_sock(c, af)) < 0)
		goto cancel;

	pif_sockaddr(c, &sa, &sl, PIF_HOST, &tgt->eaddr, tgt->eport);

	/* Use bind() to check if the target address is local (EADDRINUSE or
	 * similar) and already bound, and set the LOCAL flag in that case.
	 *
	 * If bind() succeeds, in general, we could infer that nobody (else) is
	 * listening on that address and port and reset the connection attempt
	 * early, but we can't rely on that if non-local binds are enabled,
	 * because bind() would succeed for any non-local address we can reach.
	 *
	 * So, if bind() succeeds, close the socket, get a new one, and proceed.
	 */
	if (bind(s, &sa.sa, sl)) {
		if (errno != EADDRNOTAVAIL && errno != EACCES)
			conn_flag(c, conn, LOCAL);
	} else {
		/* Not a local, bound destination, inconclusive test */
		close(s);
		if ((s = tcp_conn_sock(c, af)) < 0)
			goto cancel;
	}

	conn->sock = s;
	conn->timer = -1;
	conn_event(c, conn, TAP_SYN_RCVD);

	conn->wnd_to_tap = WINDOW_DEFAULT;

	mss = tcp_conn_tap_mss(conn, opts, optlen);
	if (setsockopt(s, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss)))
		flow_trace(conn, "failed to set TCP_MAXSEG on socket %i", s);
	MSS_SET(conn, mss);

	tcp_get_tap_ws(conn, opts, optlen);

	/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp yet, to
	 * avoid getting a zero scale just because we set a small window now.
	 */
	if (!(conn->wnd_from_tap = (htons(th->window) >> conn->ws_from_tap)))
		conn->wnd_from_tap = 1;

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	hash = flow_hash_insert(c, TAP_SIDX(conn));
	conn->seq_to_tap = tcp_init_seq(hash, now);
	conn->seq_ack_from_tap = conn->seq_to_tap;

	tcp_bind_outbound(c, conn, s);

	if (connect(s, &sa.sa, sl)) {
		if (errno != EINPROGRESS) {
			tcp_rst(c, conn);
			goto cancel;
		}

		tcp_get_sndbuf(conn);
	} else {
		tcp_get_sndbuf(conn);

		if (tcp_send_flag(c, conn, SYN | ACK))
			goto cancel;

		conn_event(c, conn, TAP_SYN_ACK_SENT);
	}

	tcp_epoll_ctl(c, conn);
	FLOW_ACTIVATE(conn);
	return;

cancel:
	if (s >= 0)
		close(s);
	flow_alloc_cancel(flow);
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer
 * @conn:	Connection pointer
 * @ack_seq:	ACK sequence, host order
 *
 * Return: 0 on success, negative error code from recv() on failure
 */
#ifdef VALGRIND
/* valgrind doesn't realise that passing a NULL buffer to recv() is ok if using
 * MSG_TRUNC.  We have a suppression for this in the tests, but it relies on
 * valgrind being able to see the tcp_sock_consume() stack frame, which it won't
 * if this gets inlined.  This has a single caller making it a likely inlining
 * candidate, and certain compiler versions will do so even at -O0.
 */
 __attribute__((noinline))
#endif /* VALGRIND */
static int tcp_sock_consume(const struct tcp_tap_conn *conn, uint32_t ack_seq)
{
	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (SEQ_LE(ack_seq, conn->seq_ack_from_tap))
		return 0;

	/* cppcheck-suppress [nullPointer, unmatchedSuppression] */
	if (recv(conn->sock, NULL, ack_seq - conn->seq_ack_from_tap,
		 MSG_DONTWAIT | MSG_TRUNC) < 0)
		return -errno;

	return 0;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 *
 * #syscalls recvmsg
 */
static int tcp_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn)
{
	return tcp_buf_data_from_sock(c, conn);
}

/**
 * tcp_data_from_tap() - tap/guest data for established connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @p:		Pool of TCP packets, with TCP headers
 * @idx:	Index of first data packet in pool
 *
 * #syscalls sendmsg
 *
 * Return: count of consumed packets
 */
static int tcp_data_from_tap(const struct ctx *c, struct tcp_tap_conn *conn,
			     const struct pool *p, int idx)
{
	int i, iov_i, ack = 0, fin = 0, retr = 0, keep = -1, partial_send = 0;
	uint16_t max_ack_seq_wnd = conn->wnd_from_tap;
	uint32_t max_ack_seq = conn->seq_ack_from_tap;
	uint32_t seq_from_tap = conn->seq_from_tap;
	struct msghdr mh = { .msg_iov = tcp_iov };
	size_t len;
	ssize_t n;

	if (conn->events == CLOSED)
		return p->count - idx;

	ASSERT(conn->events & ESTABLISHED);

	for (i = idx, iov_i = 0; i < (int)p->count; i++) {
		uint32_t seq, seq_offset, ack_seq;
		const struct tcphdr *th;
		char *data;
		size_t off;

		th = packet_get(p, i, 0, sizeof(*th), &len);
		if (!th)
			return -1;
		len += sizeof(*th);

		off = th->doff * 4UL;
		if (off < sizeof(*th) || off > len)
			return -1;

		if (th->rst) {
			conn_event(c, conn, CLOSED);
			return 1;
		}

		len -= off;
		data = packet_get(p, i, off, len, NULL);
		if (!data)
			continue;

		seq = ntohl(th->seq);
		if (SEQ_LT(seq, conn->seq_from_tap) && len <= 1) {
			flow_trace(conn,
				   "keep-alive sequence: %u, previous: %u",
				   seq, conn->seq_from_tap);

			tcp_send_flag(c, conn, ACK);
			tcp_timer_ctl(c, conn);

			if (p->count == 1)
				return 1;

			continue;
		}

		ack_seq = ntohl(th->ack_seq);

		if (th->ack) {
			ack = 1;

			if (SEQ_GE(ack_seq, conn->seq_ack_from_tap) &&
			    SEQ_GE(ack_seq, max_ack_seq)) {
				/* Fast re-transmit */
				retr = !len && !th->fin &&
				       ack_seq == max_ack_seq &&
				       ntohs(th->window) == max_ack_seq_wnd;

				max_ack_seq_wnd = ntohs(th->window);
				max_ack_seq = ack_seq;
			}
		}

		if (th->fin)
			fin = 1;

		if (!len)
			continue;

		seq_offset = seq_from_tap - seq;
		/* Use data from this buffer only in these two cases:
		 *
		 *      , seq_from_tap           , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '----' <-- offset             ' <-- offset
		 * ^ seq                         ^ seq
		 *    (offset >= 0, seq + len > seq_from_tap)
		 *
		 * discard in these two cases:
		 *          , seq_from_tap                , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '--------' <-- offset            '-----| <- offset
		 * ^ seq                            ^ seq
		 *    (offset >= 0, seq + len <= seq_from_tap)
		 *
		 * keep, look for another buffer, then go back, in this case:
		 *      , seq_from_tap
		 *          |--------| <-- len
		 *      '===' <-- offset
		 *          ^ seq
		 *    (offset < 0)
		 */
		if (SEQ_GE(seq_offset, 0) && SEQ_LE(seq + len, seq_from_tap))
			continue;

		if (SEQ_LT(seq_offset, 0)) {
			if (keep == -1)
				keep = i;
			continue;
		}

		tcp_iov[iov_i].iov_base = data + seq_offset;
		tcp_iov[iov_i].iov_len = len - seq_offset;
		seq_from_tap += tcp_iov[iov_i].iov_len;
		iov_i++;

		if (keep == i)
			keep = -1;

		if (keep != -1)
			i = keep - 1;
	}

	/* On socket flush failure, pretend there was no ACK, try again later */
	if (ack && !tcp_sock_consume(conn, max_ack_seq))
		tcp_update_seqack_from_tap(c, conn, max_ack_seq);

	tcp_tap_window_update(conn, max_ack_seq_wnd);

	if (retr) {
		flow_trace(conn,
			   "fast re-transmit, ACK: %u, previous sequence: %u",
			   max_ack_seq, conn->seq_to_tap);
		conn->seq_to_tap = max_ack_seq;
		if (tcp_set_peek_offset(conn->sock, 0)) {
			tcp_rst(c, conn);
			return -1;
		}
		tcp_data_from_sock(c, conn);
	}

	if (!iov_i)
		goto out;

	mh.msg_iovlen = iov_i;
eintr:
	n = sendmsg(conn->sock, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EPIPE) {
			/* Here's the wrap, said the tap.
			 * In my pocket, said the socket.
			 *   Then swiftly looked away and left.
			 */
			conn->seq_from_tap = seq_from_tap;
			tcp_send_flag(c, conn, ACK);
		}

		if (errno == EINTR)
			goto eintr;

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			tcp_send_flag(c, conn, ACK_IF_NEEDED);
			return p->count - idx;

		}
		return -1;
	}

	if (n < (int)(seq_from_tap - conn->seq_from_tap)) {
		partial_send = 1;
		conn->seq_from_tap += n;
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	} else {
		conn->seq_from_tap += n;
	}

out:
	if (keep != -1) {
		/* We use an 8-bit approximation here: the associated risk is
		 * that we skip a duplicate ACK on 8-bit sequence number
		 * collision. Fast retransmit is a SHOULD in RFC 5681, 3.2.
		 */
		if (conn->seq_dup_ack_approx != (conn->seq_from_tap & 0xff)) {
			conn->seq_dup_ack_approx = conn->seq_from_tap & 0xff;
			tcp_send_flag(c, conn, ACK | DUP_ACK);
		}
		return p->count - idx;
	}

	if (ack && conn->events & TAP_FIN_SENT &&
	    conn->seq_ack_from_tap == conn->seq_to_tap)
		conn_event(c, conn, TAP_FIN_ACKED);

	if (fin && !partial_send) {
		conn->seq_from_tap++;

		conn_event(c, conn, TAP_FIN_RCVD);
	} else {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	}

	return p->count - idx;
}

/**
 * tcp_conn_from_sock_finish() - Complete connection setup after connect()
 * @c:		Execution context
 * @conn:	Connection pointer
 * @th:		TCP header of SYN, ACK segment: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_conn_from_sock_finish(const struct ctx *c,
				      struct tcp_tap_conn *conn,
				      const struct tcphdr *th,
				      const char *opts, size_t optlen)
{
	tcp_tap_window_update(conn, ntohs(th->window));
	tcp_get_tap_ws(conn, opts, optlen);

	/* First value is not scaled */
	if (!(conn->wnd_from_tap >>= conn->ws_from_tap))
		conn->wnd_from_tap = 1;

	MSS_SET(conn, tcp_conn_tap_mss(conn, opts, optlen));

	conn->seq_init_from_tap = ntohl(th->seq) + 1;
	conn->seq_from_tap = conn->seq_init_from_tap;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn_event(c, conn, ESTABLISHED);
	if (tcp_set_peek_offset(conn->sock, 0)) {
		tcp_rst(c, conn);
		return;
	}

	tcp_send_flag(c, conn, ACK);

	/* The client might have sent data already, which we didn't
	 * dequeue waiting for SYN,ACK from tap -- check now.
	 */
	tcp_data_from_sock(c, conn);
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @p:		Pool of TCP packets, with TCP headers
 * @idx:	Index of first packet in pool to process
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int tcp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		    const void *saddr, const void *daddr,
		    const struct pool *p, int idx, const struct timespec *now)
{
	struct tcp_tap_conn *conn;
	const struct tcphdr *th;
	size_t optlen, len;
	const char *opts;
	union flow *flow;
	flow_sidx_t sidx;
	int ack_due = 0;
	int count;

	(void)pif;

	th = packet_get(p, idx, 0, sizeof(*th), &len);
	if (!th)
		return 1;
	len += sizeof(*th);

	optlen = th->doff * 4UL - sizeof(*th);
	/* Static checkers might fail to see this: */
	optlen = MIN(optlen, ((1UL << 4) /* from doff width */ - 6) * 4UL);
	opts = packet_get(p, idx, sizeof(*th), optlen, NULL);

	sidx = flow_lookup_af(c, IPPROTO_TCP, PIF_TAP, af, saddr, daddr,
			      ntohs(th->source), ntohs(th->dest));
	flow = flow_at_sidx(sidx);

	/* New connection from tap */
	if (!flow) {
		if (opts && th->syn && !th->ack)
			tcp_conn_from_tap(c, af, saddr, daddr, th,
					  opts, optlen, now);
		return 1;
	}

	ASSERT(flow->f.type == FLOW_TCP);
	ASSERT(pif_at_sidx(sidx) == PIF_TAP);
	conn = &flow->tcp;

	flow_trace(conn, "packet length %zu from tap", len);

	if (th->rst) {
		conn_event(c, conn, CLOSED);
		return 1;
	}

	if (th->ack && !(conn->events & ESTABLISHED))
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

	/* Establishing connection from socket */
	if (conn->events & SOCK_ACCEPTED) {
		if (th->syn && th->ack && !th->fin) {
			tcp_conn_from_sock_finish(c, conn, th, opts, optlen);
			return 1;
		}

		goto reset;
	}

	/* Establishing connection from tap */
	if (conn->events & TAP_SYN_RCVD) {
		if (!(conn->events & TAP_SYN_ACK_SENT))
			goto reset;

		conn_event(c, conn, ESTABLISHED);
		if (tcp_set_peek_offset(conn->sock, 0))
			goto reset;

		if (th->fin) {
			conn->seq_from_tap++;

			shutdown(conn->sock, SHUT_WR);
			tcp_send_flag(c, conn, ACK);
			conn_event(c, conn, SOCK_FIN_SENT);

			return 1;
		}

		if (!th->ack)
			goto reset;

		tcp_tap_window_update(conn, ntohs(th->window));

		tcp_data_from_sock(c, conn);

		if (p->count - idx == 1)
			return 1;
	}

	/* Established connections not accepting data from tap */
	if (conn->events & TAP_FIN_RCVD) {
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

		if (conn->events & SOCK_FIN_RCVD &&
		    conn->seq_ack_from_tap == conn->seq_to_tap)
			conn_event(c, conn, CLOSED);

		return 1;
	}

	/* Established connections accepting data from tap */
	count = tcp_data_from_tap(c, conn, p, idx);
	if (count == -1)
		goto reset;

	conn_flag(c, conn, ~STALLED);

	if (conn->seq_ack_to_tap != conn->seq_from_tap)
		ack_due = 1;

	if ((conn->events & TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_SENT)) {
		shutdown(conn->sock, SHUT_WR);
		conn_event(c, conn, SOCK_FIN_SENT);
		tcp_send_flag(c, conn, ACK);
		ack_due = 0;
	}

	if (ack_due)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

	return count;

reset:
	/* Something's gone wrong, so reset the connection.  We discard
	 * remaining packets in the batch, since they'd be invalidated when our
	 * RST is received, even if otherwise good.
	 */
	tcp_rst(c, conn);
	return p->count - idx;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_connect_finish(const struct ctx *c, struct tcp_tap_conn *conn)
{
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, conn);
		return;
	}

	if (tcp_send_flag(c, conn, SYN | ACK))
		return;

	conn_event(c, conn, TAP_SYN_ACK_SENT);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);
}

/**
 * tcp_tap_conn_from_sock() - Initialize state for non-spliced connection
 * @c:		Execution context
 * @flow:	flow to initialise
 * @s:		Accepted socket
 * @sa:		Peer socket address (from accept())
 * @now:	Current timestamp
 */
static void tcp_tap_conn_from_sock(const struct ctx *c, union flow *flow,
				   int s, const struct timespec *now)
{
	struct tcp_tap_conn *conn = FLOW_SET_TYPE(flow, FLOW_TCP, tcp);
	uint64_t hash;

	conn->sock = s;
	conn->timer = -1;
	conn->ws_to_tap = conn->ws_from_tap = 0;
	conn_event(c, conn, SOCK_ACCEPTED);

	hash = flow_hash_insert(c, TAP_SIDX(conn));
	conn->seq_to_tap = tcp_init_seq(hash, now);

	conn->seq_ack_from_tap = conn->seq_to_tap;

	conn->wnd_from_tap = WINDOW_DEFAULT;

	tcp_send_flag(c, conn, SYN);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	tcp_get_sndbuf(conn);

	FLOW_ACTIVATE(conn);
}

/**
 * tcp_listen_handler() - Handle new connection request from listening socket
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @now:	Current timestamp
 */
void tcp_listen_handler(const struct ctx *c, union epoll_ref ref,
			const struct timespec *now)
{
	const struct flowside *ini;
	union sockaddr_inany sa;
	socklen_t sl = sizeof(sa);
	union flow *flow;
	int s;

	ASSERT(!c->no_tcp);

	if (!(flow = flow_alloc()))
		return;

	s = accept4(ref.fd, &sa.sa, &sl, SOCK_NONBLOCK);
	if (s < 0)
		goto cancel;

	/* FIXME: When listening port has a specific bound address, record that
	 * as our address
	 */
	ini = flow_initiate_sa(flow, ref.tcp_listen.pif, &sa,
			       ref.tcp_listen.port);

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0) {
		char sastr[SOCKADDR_STRLEN];

		err("Invalid endpoint from TCP accept(): %s",
		    sockaddr_ntop(&sa, sastr, sizeof(sastr)));
		goto cancel;
	}

	if (!flow_target(c, flow, IPPROTO_TCP))
		goto cancel;

	switch (flow->f.pif[TGTSIDE]) {
	case PIF_SPLICE:
	case PIF_HOST:
		tcp_splice_conn_from_sock(c, flow, s);
		break;

	case PIF_TAP:
		tcp_tap_conn_from_sock(c, flow, s, now);
		break;

	default:
		flow_err(flow, "No support for forwarding TCP from %s to %s",
			 pif_name(flow->f.pif[INISIDE]),
			 pif_name(flow->f.pif[TGTSIDE]));
		goto cancel;
	}

	return;

cancel:
	flow_alloc_cancel(flow);
}

/**
 * tcp_timer_handler() - timerfd events: close, send ACK, retransmit, or reset
 * @c:		Execution context
 * @ref:	epoll reference of timer (not connection)
 *
 * #syscalls timerfd_gettime arm:timerfd_gettime64 i686:timerfd_gettime64
 */
void tcp_timer_handler(const struct ctx *c, union epoll_ref ref)
{
	struct itimerspec check_armed = { { 0 }, { 0 } };
	struct tcp_tap_conn *conn = &FLOW(ref.flow)->tcp;

	ASSERT(!c->no_tcp);
	ASSERT(conn->f.type == FLOW_TCP);

	/* We don't reset timers on ~ACK_FROM_TAP_DUE, ~ACK_TO_TAP_DUE. If the
	 * timer is currently armed, this event came from a previous setting,
	 * and we just set the timer to a new point in the future: discard it.
	 */
	if (timerfd_gettime(conn->timer, &check_armed))
		flow_err(conn, "failed to read timer: %s", strerror(errno));

	if (check_armed.it_value.tv_sec || check_armed.it_value.tv_nsec)
		return;

	if (conn->flags & ACK_TO_TAP_DUE) {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
		tcp_timer_ctl(c, conn);
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED)) {
			flow_dbg(conn, "handshake timeout");
			tcp_rst(c, conn);
		} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
			flow_dbg(conn, "FIN timeout");
			tcp_rst(c, conn);
		} else if (conn->retrans == TCP_MAX_RETRANS) {
			flow_dbg(conn, "retransmissions count exceeded");
			tcp_rst(c, conn);
		} else {
			flow_dbg(conn, "ACK timeout, retry");
			conn->retrans++;
			conn->seq_to_tap = conn->seq_ack_from_tap;
			if (tcp_set_peek_offset(conn->sock, 0)) {
				tcp_rst(c, conn);
			} else {
				tcp_data_from_sock(c, conn);
				tcp_timer_ctl(c, conn);
			}
		}
	} else {
		struct itimerspec new = { { 0 }, { ACT_TIMEOUT, 0 } };
		struct itimerspec old = { { 0 }, { 0 } };

		/* Activity timeout: if it was already set, reset the
		 * connection, otherwise, it was a left-over from ACK_TO_TAP_DUE
		 * or ACK_FROM_TAP_DUE, so just set the long timeout in that
		 * case. This avoids having to preemptively reset the timer on
		 * ~ACK_TO_TAP_DUE or ~ACK_FROM_TAP_DUE.
		 */
		if (timerfd_settime(conn->timer, 0, &new, &old))
			flow_err(conn, "failed to set timer: %s",
				 strerror(errno));

		if (old.it_value.tv_sec == ACT_TIMEOUT) {
			flow_dbg(conn, "activity timeout");
			tcp_rst(c, conn);
		}
	}
}

/**
 * tcp_sock_handler() - Handle new data from non-spliced socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 */
void tcp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events)
{
	struct tcp_tap_conn *conn = conn_at_sidx(ref.flowside);

	ASSERT(!c->no_tcp);
	ASSERT(pif_at_sidx(ref.flowside) != PIF_TAP);

	if (conn->events == CLOSED)
		return;

	if (events & EPOLLERR) {
		tcp_rst(c, conn);
		return;
	}

	if ((conn->events & TAP_FIN_SENT) && (events & EPOLLHUP)) {
		conn_event(c, conn, CLOSED);
		return;
	}

	if (conn->events & ESTABLISHED) {
		if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
			conn_event(c, conn, CLOSED);

		if (events & (EPOLLRDHUP | EPOLLHUP))
			conn_event(c, conn, SOCK_FIN_RCVD);

		if (events & EPOLLIN)
			tcp_data_from_sock(c, conn);

		if (events & EPOLLOUT)
			tcp_update_seqack_wnd(c, conn, false, NULL);

		return;
	}

	/* EPOLLHUP during handshake: reset */
	if (events & EPOLLHUP) {
		tcp_rst(c, conn);
		return;
	}

	/* Data during handshake tap-side: check later */
	if (conn->events & SOCK_ACCEPTED)
		return;

	if (conn->events == TAP_SYN_RCVD) {
		if (events & EPOLLOUT)
			tcp_connect_finish(c, conn);
		/* Data? Check later */
	}
}

/**
 * tcp_sock_init_one() - Initialise listening socket for address and port
 * @c:		Execution context
 * @addr:	Pointer to address for binding, NULL for dual stack any
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: fd for the new listening socket, negative error code on failure
 */
static int tcp_sock_init_one(const struct ctx *c, const union inany_addr *addr,
			     const char *ifname, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_HOST,
	};
	int s;

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_HOST, addr,
				ifname, port, tref.u32);

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		if (!addr || inany_v4(addr))
			tcp_sock_init_ext[port][V4] = s < 0 ? -1 : s;
		if (!addr || !inany_v4(addr))
			tcp_sock_init_ext[port][V6] = s < 0 ? -1 : s;
	}

	if (s < 0)
		return s;

	tcp_sock_set_bufsize(c, s);
	return s;
}

/**
 * tcp_sock_init() - Create listening sockets for a given host ("inbound") port
 * @c:		Execution context
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on (partial) success, negative error code on (complete) failure
 */
int tcp_sock_init(const struct ctx *c, const union inany_addr *addr,
		  const char *ifname, in_port_t port)
{
	int r4 = FD_REF_MAX + 1, r6 = FD_REF_MAX + 1;

	ASSERT(!c->no_tcp);

	if (!addr && c->ifi4 && c->ifi6)
		/* Attempt to get a dual stack socket */
		if (tcp_sock_init_one(c, NULL, ifname, port) >= 0)
			return 0;

	/* Otherwise create a socket per IP version */
	if ((!addr || inany_v4(addr)) && c->ifi4)
		r4 = tcp_sock_init_one(c, addr ? addr : &inany_any4,
				       ifname, port);

	if ((!addr || !inany_v4(addr)) && c->ifi6)
		r6 = tcp_sock_init_one(c, addr ? addr : &inany_any6,
				       ifname, port);

	if (IN_INTERVAL(0, FD_REF_MAX, r4) || IN_INTERVAL(0, FD_REF_MAX, r6))
		return 0;

	return r4 < 0 ? r4 : r6;
}

/**
 * tcp_ns_sock_init4() - Init socket to listen for outbound IPv4 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init4(const struct ctx *c, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_SPLICE,
	};
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_SPLICE, &inany_loopback4,
			NULL, port, tref.u32);
	if (s >= 0)
		tcp_sock_set_bufsize(c, s);
	else
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V4] = s;
}

/**
 * tcp_ns_sock_init6() - Init socket to listen for outbound IPv6 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init6(const struct ctx *c, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_SPLICE,
	};
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_SPLICE, &inany_loopback6,
			NULL, port, tref.u32);
	if (s >= 0)
		tcp_sock_set_bufsize(c, s);
	else
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V6] = s;
}

/**
 * tcp_ns_sock_init() - Init socket to listen for spliced outbound connections
 * @c:		Execution context
 * @port:	Port, host order
 */
void tcp_ns_sock_init(const struct ctx *c, in_port_t port)
{
	ASSERT(!c->no_tcp);

	if (c->ifi4)
		tcp_ns_sock_init4(c, port);
	if (c->ifi6)
		tcp_ns_sock_init6(c, port);
}

/**
 * tcp_ns_socks_init() - Bind sockets in namespace for outbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
/* cppcheck-suppress [constParameterCallback, unmatchedSuppression] */
static int tcp_ns_socks_init(void *arg)
{
	const struct ctx *c = (const struct ctx *)arg;
	unsigned port;

	ns_enter(c);

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(c->tcp.fwd_out.map, port))
			continue;

		tcp_ns_sock_init(c, port);
	}

	return 0;
}

/**
 * tcp_sock_refill_pool() - Refill one pool of pre-opened sockets
 * @c:		Execution context
 * @pool:	Pool of sockets to refill
 * @af:		Address family to use
 *
 * Return: 0 on success, negative error code if there was at least one error
 */
int tcp_sock_refill_pool(const struct ctx *c, int pool[], sa_family_t af)
{
	int i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		int fd;

		if (pool[i] >= 0)
			continue;

		if ((fd = tcp_conn_new_sock(c, af)) < 0)
			return fd;

		pool[i] = fd;
	}

	return 0;
}

/**
 * tcp_sock_refill_init() - Refill pools of pre-opened sockets in init ns
 * @c:		Execution context
 */
static void tcp_sock_refill_init(const struct ctx *c)
{
	if (c->ifi4) {
		int rc = tcp_sock_refill_pool(c, init_sock_pool4, AF_INET);
		if (rc < 0)
			warn("TCP: Error refilling IPv4 host socket pool: %s",
			     strerror(-rc));
	}
	if (c->ifi6) {
		int rc = tcp_sock_refill_pool(c, init_sock_pool6, AF_INET6);
		if (rc < 0)
			warn("TCP: Error refilling IPv6 host socket pool: %s",
			     strerror(-rc));
	}
}

/**
 * tcp_probe_peek_offset_cap() - Check if SO_PEEK_OFF is supported by kernel
 * @af:		Address family, IPv4 or IPv6
 *
 * Return: true if supported, false otherwise
 */
static bool tcp_probe_peek_offset_cap(sa_family_t af)
{
	bool ret = false;
	int s, optv = 0;

	s = socket(af, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (s < 0) {
		warn_perror("Temporary TCP socket creation failed");
	} else {
		if (!setsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &optv, sizeof(int)))
			ret = true;
		close(s);
	}

	return ret;
}

/**
 * tcp_probe_tcp_info() - Check what data TCP_INFO reports
 *
 * Return: Number of bytes returned by TCP_INFO getsockopt()
 */
static socklen_t tcp_probe_tcp_info(void)
{
	struct tcp_info_linux tinfo;
	socklen_t sl = sizeof(tinfo);
	int s;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (s < 0) {
		warn_perror("Temporary TCP socket creation failed");
		return false;
	}

	if (getsockopt(s, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		warn_perror("Failed to get TCP_INFO on temporary socket");
		close(s);
		return false;
	}

	close(s);

	return sl;
}

/**
 * tcp_init() - Get initial sequence, hash secret, initialise per-socket data
 * @c:		Execution context
 *
 * Return: 0, doesn't return on failure
 */
int tcp_init(struct ctx *c)
{
	ASSERT(!c->no_tcp);

	tcp_sock_iov_init(c);

	memset(init_sock_pool4,		0xff,	sizeof(init_sock_pool4));
	memset(init_sock_pool6,		0xff,	sizeof(init_sock_pool6));
	memset(tcp_sock_init_ext,	0xff,	sizeof(tcp_sock_init_ext));
	memset(tcp_sock_ns,		0xff,	sizeof(tcp_sock_ns));

	tcp_sock_refill_init(c);

	if (c->mode == MODE_PASTA) {
		tcp_splice_init(c);

		NS_CALL(tcp_ns_socks_init, c);
	}

	peek_offset_cap = (!c->ifi4 || tcp_probe_peek_offset_cap(AF_INET)) &&
			  (!c->ifi6 || tcp_probe_peek_offset_cap(AF_INET6));
	debug("SO_PEEK_OFF%ssupported", peek_offset_cap ? " " : " not ");

	tcp_info_size = tcp_probe_tcp_info();

#define dbg_tcpi(f_)	debug("TCP_INFO tcpi_%s field%s supported",	\
			      STRINGIFY(f_), tcp_info_cap(f_) ? " " : " not ")
	dbg_tcpi(snd_wnd);
	dbg_tcpi(bytes_acked);
	dbg_tcpi(min_rtt);
#undef dbg_tcpi

	return 0;
}

/**
 * tcp_port_rebind() - Rebind ports to match forward maps
 * @c:		Execution context
 * @outbound:	True to remap outbound forwards, otherwise inbound
 *
 * Must be called in namespace context if @outbound is true.
 */
static void tcp_port_rebind(struct ctx *c, bool outbound)
{
	const uint8_t *fmap = outbound ? c->tcp.fwd_out.map : c->tcp.fwd_in.map;
	const uint8_t *rmap = outbound ? c->tcp.fwd_in.map : c->tcp.fwd_out.map;
	int (*socks)[IP_VERSIONS] = outbound ? tcp_sock_ns : tcp_sock_init_ext;
	unsigned port;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(fmap, port)) {
			if (socks[port][V4] >= 0) {
				close(socks[port][V4]);
				socks[port][V4] = -1;
			}

			if (socks[port][V6] >= 0) {
				close(socks[port][V6]);
				socks[port][V6] = -1;
			}

			continue;
		}

		/* Don't loop back our own ports */
		if (bitmap_isset(rmap, port))
			continue;

		if ((c->ifi4 && socks[port][V4] == -1) ||
		    (c->ifi6 && socks[port][V6] == -1)) {
			if (outbound)
				tcp_ns_sock_init(c, port);
			else
				tcp_sock_init(c, NULL, NULL, port);
		}
	}
}

/**
 * tcp_port_rebind_outbound() - Rebind ports in namespace
 * @arg:	Execution context
 *
 * Called with NS_CALL()
 *
 * Return: 0
 */
static int tcp_port_rebind_outbound(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	ns_enter(c);
	tcp_port_rebind(c, true);

	return 0;
}

/**
 * tcp_timer() - Periodic tasks: port detection, closed connections, pool refill
 * @c:		Execution context
 * @now:	Current timestamp
 */
void tcp_timer(struct ctx *c, const struct timespec *now)
{
	(void)now;

	if (c->mode == MODE_PASTA) {
		if (c->tcp.fwd_out.mode == FWD_AUTO) {
			fwd_scan_ports_tcp(&c->tcp.fwd_out, &c->tcp.fwd_in);
			NS_CALL(tcp_port_rebind_outbound, c);
		}

		if (c->tcp.fwd_in.mode == FWD_AUTO) {
			fwd_scan_ports_tcp(&c->tcp.fwd_in, &c->tcp.fwd_out);
			tcp_port_rebind(c, false);
		}
	}

	tcp_sock_refill_init(c);
	if (c->mode == MODE_PASTA)
		tcp_splice_refill(c);
}
