/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * UDP flow tracking functions
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "util.h"
#include "passt.h"
#include "flow_table.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */

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
void udp_flow_close(const struct ctx *c, struct udp_flow *uflow)
{
	if (uflow->closed)
		return; /* Nothing to do */

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

	uflow->closed = true;
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
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @now:	Timestamp
 *
 * #syscalls fcntl arm:fcntl64 ppc64:fcntl64 i686:fcntl64
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
flow_sidx_t udp_flow_from_sock(const struct ctx *c, union epoll_ref ref,
			       const union sockaddr_inany *s_in,
			       const struct timespec *now)
{
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(ref.type == EPOLL_TYPE_UDP_LISTEN);

	sidx = flow_lookup_sa(c, IPPROTO_UDP, ref.udp.pif, s_in, ref.udp.port);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sastr[SOCKADDR_STRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s",
		      pif_name(ref.udp.pif),
		      sockaddr_ntop(s_in, sastr, sizeof(sastr)));
		return FLOW_SIDX_NONE;
	}

	flow_initiate_sa(flow, ref.udp.pif, s_in, ref.udp.port);
	return udp_flow_new(c, flow, ref.fd, now);
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
flow_sidx_t udp_flow_from_tap(const struct ctx *c,
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
 * udp_flow_defer() - Deferred per-flow handling (clean up aborted flows)
 * @uflow:	Flow to handle
 *
 * Return: true if the connection is ready to free, false otherwise
 */
bool udp_flow_defer(const struct udp_flow *uflow)
{
	return uflow->closed;
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
