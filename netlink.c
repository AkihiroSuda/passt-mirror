// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * netlink.c - rtnetlink routines: interfaces, addresses, routes
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "netlink.h"

/* Netlink expects a buffer of at least 8kiB or the system page size,
 * whichever is larger.  32kiB is recommended for more efficient.
 * Since the largest page size on any remotely common Linux setup is
 * 64kiB (ppc64), that should cover it.
 *
 * https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html#buffer-sizing
 */
#define NLBUFSIZ 65536

/* Socket in init, in target namespace, sequence (just needs to be monotonic) */
int nl_sock	= -1;
int nl_sock_ns	= -1;
static int nl_seq = 1;

/**
 * nl_sock_init_do() - Set up netlink sockets in init or target namespace
 * @arg:	Execution context, if running from namespace, NULL otherwise
 *
 * Return: 0
 */
static int nl_sock_init_do(void *arg)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK, };
	int *s = arg ? &nl_sock_ns : &nl_sock;
#ifdef NETLINK_GET_STRICT_CHK
	int y = 1;
#endif

	if (arg)
		ns_enter((struct ctx *)arg);

	*s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (*s < 0 || bind(*s, (struct sockaddr *)&addr, sizeof(addr))) {
		*s = -1;
		return 0;
	}

#ifdef NETLINK_GET_STRICT_CHK
	if (setsockopt(*s, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &y, sizeof(y)))
		debug("netlink: cannot set NETLINK_GET_STRICT_CHK on %i", *s);
#endif
	return 0;
}

/**
 * nl_sock_init() - Call nl_sock_init_do(), won't return on failure
 * @c:		Execution context
 * @ns:		Get socket in namespace, not in init
 */
void nl_sock_init(const struct ctx *c, bool ns)
{
	if (ns) {
		NS_CALL(nl_sock_init_do, c);
		if (nl_sock_ns == -1)
			goto fail;
	} else {
		nl_sock_init_do(NULL);
	}

	if (nl_sock == -1)
		goto fail;

	return;

fail:
	die("Failed to get netlink socket");
}

/**
 * nl_send() - Prepare and send netlink request
 * @s:		Netlink socket
 * @req:	Request (will fill netlink header)
 * @type:	Request type
 * @flags:	Extra request flags (NLM_F_REQUEST and NLM_F_ACK assumed)
 * @len:	Request length
 *
 * Return: sequence number of request on success, terminates on error
 */
static uint16_t nl_send(int s, void *req, uint16_t type,
		       uint16_t flags, ssize_t len)
{
	struct nlmsghdr *nh;
	ssize_t n;

	nh = (struct nlmsghdr *)req;
	nh->nlmsg_type = type;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nh->nlmsg_len = len;
	nh->nlmsg_seq = nl_seq++;
	nh->nlmsg_pid = 0;

	n = send(s, req, len, 0);
	if (n < 0)
		die("netlink: Failed to send(): %s", strerror(errno));
	else if (n < len)
		die("netlink: Short send (%lu of %lu bytes)", n, len);

	return nh->nlmsg_seq;
}

/**
 * nl_status() - Check status given by a netlink response
 * @nh:		Netlink response header
 * @n:		Remaining space in response buffer from @nh
 * @seq:	Request sequence number we expect a response to
 *
 * Return: 0 if @nh indicated successful completion,
 *         < 0, negative error code if @nh indicated failure
 *         > 0 @n if there are more responses to request @seq
 *     terminates if sequence numbers are out of sync
 */
static int nl_status(const struct nlmsghdr *nh, ssize_t n, uint16_t seq)
{
	ASSERT(NLMSG_OK(nh, n));

	if (nh->nlmsg_seq != seq)
		die("netlink: Unexpected sequence number (%hu != %hu)",
		    nh->nlmsg_seq, seq);

	if (nh->nlmsg_type == NLMSG_DONE) {
		return 0;
	}
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *errmsg = (struct nlmsgerr *)NLMSG_DATA(nh);
		return errmsg->error;
	}

	return n;
}

/**
 * nl_next() - Get next netlink response message, recv()ing if necessary
 * @s:		Netlink socket
 * @buf:	Buffer for responses (at least NLBUFSIZ long)
 * @nh:		Previous message, or NULL if there are none
 * @n:		Variable with remaining unread bytes in buffer (updated)
 *
 * Return: pointer to next unread netlink response message (may block)
 */
static struct nlmsghdr *nl_next(int s, char *buf, struct nlmsghdr *nh, ssize_t *n)
{
	if (nh) {
		nh = NLMSG_NEXT(nh, *n);
		if (NLMSG_OK(nh, *n))
			return nh;
	}

	*n = recv(s, buf, NLBUFSIZ, 0);
	if (*n < 0)
		die("netlink: Failed to recv(): %s", strerror(errno));

	nh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nh, *n))
		die("netlink: Response datagram with no message");

	return nh;
}

/**
 * nl_foreach - 'for' type macro to step through netlink response messages
 * nl_foreach_oftype - as above, but only messages of expected type
 * @nh:		Steps through each response header (struct nlmsghdr *)
 * @status:	When loop exits indicates if there was an error (ssize_t)
 * @s:		Netlink socket
 * @buf:	Buffer for responses (at least NLBUFSIZ long)
 * @seq:	Sequence number of request we're getting responses for
 * @type:	Type of netlink message to process
 */
#define nl_foreach(nh, status, s, buf, seq)				\
	for ((nh) = nl_next((s), (buf), NULL, &(status));		\
	     ((status) = nl_status((nh), (status), (seq))) > 0;		\
	     (nh) = nl_next((s), (buf), (nh), &(status)))

#define nl_foreach_oftype(nh, status, s, buf, seq, type)		\
	nl_foreach((nh), (status), (s), (buf), (seq))			\
		if ((nh)->nlmsg_type != (type)) {			\
			warn("netlink: Unexpected message type");	\
		} else

/**
 * nl_do() - Send netlink "do" request, and wait for acknowledgement
 * @s:		Netlink socket
 * @req:	Request (will fill netlink header)
 * @type:	Request type
 * @flags:	Extra request flags (NLM_F_REQUEST and NLM_F_ACK assumed)
 * @len:	Request length
 *
 * Return: 0 on success, negative error code on error
 */
static int nl_do(int s, void *req, uint16_t type, uint16_t flags, ssize_t len)
{
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint16_t seq;

	seq = nl_send(s, req, type, flags, len);
	nl_foreach(nh, status, s, buf, seq)
		warn("netlink: Unexpected response message");

	return status;
}

/**
 * nl_get_ext_if() - Get interface index supporting IP version being probed
 * @s:	Netlink socket
 * @af:	Address family (AF_INET or AF_INET6) to look for connectivity
 *      for.
 *
 * Return: interface index, 0 if not found
 */
unsigned int nl_get_ext_if(int s, sa_family_t af)
{
	struct { struct nlmsghdr nlh; struct rtmsg rtm; } req = {
		.rtm.rtm_table	 = RT_TABLE_MAIN,
		.rtm.rtm_scope	 = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	 = RTN_UNICAST,
		.rtm.rtm_family	 = af,
	};
	unsigned int ifi = 0;
	struct nlmsghdr *nh;
	struct rtattr *rta;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint16_t seq;
	size_t na;

	seq = nl_send(s, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWROUTE) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);

		if (ifi || rtm->rtm_dst_len || rtm->rtm_family != af)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != RTA_OIF)
				continue;

			ifi = *(unsigned int *)RTA_DATA(rta);
		}
	}

	return ifi;
}

/**
 * nl_route_get_def() - Get default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @gw:		Default gateway to fill on NL_GET
 */
void nl_route_get_def(int s, unsigned int ifi, sa_family_t af, void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	struct nlmsghdr *nh;
	bool found = false;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint16_t seq;

	seq = nl_send(s, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWROUTE) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (found || rtm->rtm_dst_len)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != RTA_GATEWAY)
				continue;

			memcpy(gw, RTA_DATA(rta), RTA_PAYLOAD(rta));
			found = true;
		}
	}
}

/**
 * nl_route_set_def() - Set default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index in target namespace
 * @af:		Address family
 * @gw:		Default gateway to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_route_set_def(int s, unsigned int ifi, sa_family_t af, void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
		union {
			struct {
				struct rtattr rta_dst;
				struct in6_addr d;
				struct rtattr rta_gw;
				struct in6_addr a;
			} r6;
			struct {
				struct rtattr rta_dst;
				struct in_addr d;
				struct rtattr rta_gw;
				struct in_addr a;
			} r4;
		} set;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,
		.rtm.rtm_protocol = RTPROT_BOOT,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	ssize_t len;

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r6.d));

		len = offsetof(struct req_t, set.r6) + sizeof(req.set.r6);

		req.set.r6.rta_dst.rta_type = RTA_DST;
		req.set.r6.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r6.a, gw, sizeof(req.set.r6.a));
		req.set.r6.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r6.rta_gw.rta_len = rta_len;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r4.d));

		len = offsetof(struct req_t, set.r4) + sizeof(req.set.r4);

		req.set.r4.rta_dst.rta_type = RTA_DST;
		req.set.r4.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r4.a, gw, sizeof(req.set.r4.a));
		req.set.r4.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r4.rta_gw.rta_len = rta_len;
	}

	return nl_do(s, &req, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, len);
}

/**
 * nl_route_dup() - Copy routes for given interface and address family
 * @s_src:	Netlink socket in source namespace
 * @ifi_src:	Source interface index
 * @s_dst:	Netlink socket in destination namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 */
void nl_route_dup(int s_src, unsigned int ifi_src,
		  int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi_src,
	};
	ssize_t nlmsgs_size, status;
	unsigned dup_routes = 0;
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	uint16_t seq;
	unsigned i;

	seq = nl_send(s_src, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));

	/* nl_foreach() will step through multiple response datagrams,
	 * which we don't want here because we need to have all the
	 * routes in the buffer at once.
	 */
	nh = nl_next(s_src, buf, NULL, &nlmsgs_size);
	for (status = nlmsgs_size;
	     NLMSG_OK(nh, status) && (status = nl_status(nh, status, seq)) > 0;
	     nh = NLMSG_NEXT(nh, status)) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWROUTE)
			continue;

		dup_routes++;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_OIF)
				*(unsigned int *)RTA_DATA(rta) = ifi_dst;
		}
	}

	if (!NLMSG_OK(nh, status) || status > 0) {
		/* Process any remaining datagrams in a different
		 * buffer so we don't overwrite the first one.
		 */
		char tail[NLBUFSIZ];
		unsigned extra = 0;

		nl_foreach_oftype(nh, status, s_src, tail, seq, RTM_NEWROUTE)
			extra++;

		if (extra) {
			err("netlink: Too many routes to duplicate");
			return;
		}
	}

	/* Routes might have dependencies between each other, and the kernel
	 * processes RTM_NEWROUTE messages sequentially. For n routes, we might
	 * need to send the requests up to n times to get all of them inserted.
	 * Routes that have been already inserted will return -EEXIST, but we
	 * can safely ignore that and repeat the requests. This avoids the need
	 * to calculate dependencies: let the kernel do that.
	 */
	for (i = 0; i < dup_routes; i++) {
		for (nh = (struct nlmsghdr *)buf, status = nlmsgs_size;
		     NLMSG_OK(nh, status);
		     nh = NLMSG_NEXT(nh, status)) {
			uint16_t flags = nh->nlmsg_flags;

			if (nh->nlmsg_type != RTM_NEWROUTE)
				continue;

			nl_do(s_dst, nh, RTM_NEWROUTE,
			       (flags & ~NLM_F_DUMP_FILTERED) | NLM_F_CREATE,
			       nh->nlmsg_len);
		}
	}
}

/**
 * nl_addr_get() - Get IP address for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index in outer network namespace
 * @af:		Address family
 * @addr:	Global address to fill
 * @prefix_len:	Mask or prefix length, to fill (for IPv4)
 * @addr_l:	Link-scoped address to fill (for IPv6)
 */
void nl_addr_get(int s, unsigned int ifi, sa_family_t af,
		 void *addr, int *prefix_len, void *addr_l)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint16_t seq;

	seq = nl_send(s, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (ifa->ifa_index != ifi)
			continue;

		for (rta = IFA_RTA(ifa), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFA_ADDRESS)
				continue;

			if (af == AF_INET) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				*prefix_len = ifa->ifa_prefixlen;
			} else if (af == AF_INET6 && addr &&
				   ifa->ifa_scope == RT_SCOPE_UNIVERSE) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
			}

			if (addr_l &&
			    af == AF_INET6 && ifa->ifa_scope == RT_SCOPE_LINK)
				memcpy(addr_l, RTA_DATA(rta), RTA_PAYLOAD(rta));
		}
	}
}

/**
 * nl_add_set() - Set IP addresses for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @addr:	Global address to set
 * @prefix_len:	Mask or prefix length to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_set(int s, unsigned int ifi, sa_family_t af,
		void *addr, int prefix_len)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		union {
			struct {
				struct rtattr rta_l;
				struct in_addr l;
				struct rtattr rta_a;
				struct in_addr a;
			} a4;
			struct {
				struct rtattr rta_l;
				struct in6_addr l;
				struct rtattr rta_a;
				struct in6_addr a;
			} a6;
		} set;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
		.ifa.ifa_prefixlen = prefix_len,
		.ifa.ifa_scope	   = RT_SCOPE_UNIVERSE,
	};
	ssize_t len;

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a6.l));

		/* By default, strictly speaking, it's duplicated */
		req.ifa.ifa_flags = IFA_F_NODAD;

		len = offsetof(struct req_t, set.a6) + sizeof(req.set.a6);

		memcpy(&req.set.a6.l, addr, sizeof(req.set.a6.l));
		req.set.a6.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		memcpy(&req.set.a6.a, addr, sizeof(req.set.a6.a));
		req.set.a6.rta_a.rta_len = rta_len;
		req.set.a6.rta_a.rta_type = IFA_ADDRESS;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a4.l));

		len = offsetof(struct req_t, set.a4) + sizeof(req.set.a4);

		memcpy(&req.set.a4.l, addr, sizeof(req.set.a4.l));
		req.set.a4.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		req.set.a4.rta_a.rta_len = rta_len;
		req.set.a4.rta_a.rta_type = IFA_ADDRESS;
	}

	return nl_do(s, &req, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, len);
}

/**
 * nl_addr_dup() - Copy IP addresses for given interface and address family
 * @s_src:	Netlink socket in source network namespace
 * @ifi_src:	Interface index in source network namespace
 * @s_dst:	Netlink socket in destination network namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 */
void nl_addr_dup(int s_src, unsigned int ifi_src,
		 int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi_src,
		.ifa.ifa_prefixlen = 0,
	};
	char buf[NLBUFSIZ];
	struct nlmsghdr *nh;
	ssize_t status;
	uint16_t seq;

	seq = nl_send(s_src, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s_src, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa;
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWADDR)
			continue;

		ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);

		if (ifa->ifa_scope == RT_SCOPE_LINK ||
		    ifa->ifa_index != ifi_src)
			continue;

		ifa->ifa_index = ifi_dst;

		for (rta = IFA_RTA(ifa), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == IFA_LABEL)
				rta->rta_type = IFA_UNSPEC;
		}

		nl_do(s_dst, nh, RTM_NEWADDR,
		       (nh->nlmsg_flags & ~NLM_F_DUMP_FILTERED) | NLM_F_CREATE,
		       nh->nlmsg_len);
	}
}

/**
 * nl_link_get_mac() - Get link MAC address
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mac:	Fill with current MAC address
 */
void nl_link_get_mac(int s, unsigned int ifi, void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint16_t seq;

	seq = nl_send(s, &req, RTM_GETLINK, 0, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWLINK) {
		struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		for (rta = IFLA_RTA(ifm), na = RTM_PAYLOAD(nh);
		     RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFLA_ADDRESS)
				continue;

			memcpy(mac, RTA_DATA(rta), ETH_ALEN);
		}
	}
}

/**
 * nl_link_set_mac() - Set link MAC address
 * @s:		Netlink socket
 * @ns:		Use netlink socket in namespace
 * @ifi:	Interface index
 * @mac:	MAC address to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_set_mac(int s, unsigned int ifi, void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned char mac[ETH_ALEN];
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.rta.rta_type	  = IFLA_ADDRESS,
		.rta.rta_len	  = RTA_LENGTH(ETH_ALEN),
	};

	memcpy(req.mac, mac, ETH_ALEN);

	return nl_do(s, &req, RTM_NEWLINK, 0, sizeof(req));
}

/**
 * nl_link_up() - Bring link up
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mtu:	If non-zero, set interface MTU
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_up(int s, unsigned int ifi, int mtu)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned int mtu;
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.ifm.ifi_flags	  = IFF_UP,
		.ifm.ifi_change	  = IFF_UP,
		.rta.rta_type	  = IFLA_MTU,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.mtu		  = mtu,
	};
	ssize_t len = sizeof(req);

	if (!mtu)
		/* Shorten request to drop MTU attribute */
		len = offsetof(struct req_t, rta);

	return nl_do(s, &req, RTM_NEWLINK, 0, len);
}
