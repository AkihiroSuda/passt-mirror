// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * passt.c - Daemon implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * Grab Ethernet frames from AF_UNIX socket (in "passt" mode) or tap device (in
 * "pasta" mode), build SOCK_DGRAM/SOCK_STREAM sockets for each 5-tuple from
 * TCP, UDP packets, perform connection tracking and forward them. Forward
 * packets received on sockets back to the UNIX domain socket (typically, a
 * socket virtio_net file descriptor from qemu) or to the tap device (typically,
 * created in a separate network namespace).
 */

#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <netinet/if_ether.h>
#include <libgen.h>

#include "util.h"
#include "passt.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "isolation.h"
#include "pcap.h"
#include "tap.h"
#include "conf.h"
#include "pasta.h"
#include "arch.h"
#include "log.h"
#include "tcp_splice.h"
#include "ndp.h"

#define EPOLL_EVENTS		8

#define TIMER_INTERVAL__	MIN(TCP_TIMER_INTERVAL, UDP_TIMER_INTERVAL)
#define TIMER_INTERVAL_		MIN(TIMER_INTERVAL__, ICMP_TIMER_INTERVAL)
#define TIMER_INTERVAL		MIN(TIMER_INTERVAL_, FLOW_TIMER_INTERVAL)

char pkt_buf[PKT_BUF_BYTES]	__attribute__ ((aligned(PAGE_SIZE)));

char *epoll_type_str[] = {
	[EPOLL_TYPE_TCP]		= "connected TCP socket",
	[EPOLL_TYPE_TCP_SPLICE]		= "connected spliced TCP socket",
	[EPOLL_TYPE_TCP_LISTEN]		= "listening TCP socket",
	[EPOLL_TYPE_TCP_TIMER]		= "TCP timer",
	[EPOLL_TYPE_UDP_LISTEN]		= "listening UDP socket",
	[EPOLL_TYPE_UDP_REPLY]		= "UDP reply socket",
	[EPOLL_TYPE_PING]	= "ICMP/ICMPv6 ping socket",
	[EPOLL_TYPE_NSQUIT_INOTIFY]	= "namespace inotify watch",
	[EPOLL_TYPE_NSQUIT_TIMER]	= "namespace timer watch",
	[EPOLL_TYPE_TAP_PASTA]		= "/dev/net/tun device",
	[EPOLL_TYPE_TAP_PASST]		= "connected qemu socket",
	[EPOLL_TYPE_TAP_LISTEN]		= "listening qemu socket",
};
static_assert(ARRAY_SIZE(epoll_type_str) == EPOLL_NUM_TYPES,
	      "epoll_type_str[] doesn't match enum epoll_type");

/**
 * post_handler() - Run periodic and deferred tasks for L4 protocol handlers
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void post_handler(struct ctx *c, const struct timespec *now)
{
#define CALL_PROTO_HANDLER(lc, uc)					\
	do {								\
		extern void						\
		lc ## _defer_handler (struct ctx *c)			\
		__attribute__ ((weak));					\
									\
		if (!c->no_ ## lc) {					\
			if (lc ## _defer_handler)			\
				lc ## _defer_handler(c);		\
									\
			if (timespec_diff_ms((now), &c->lc.timer_run)	\
			    >= uc ## _TIMER_INTERVAL) {			\
				lc ## _timer(c, now);			\
				c->lc.timer_run = *now;			\
			}						\
		} 							\
	} while (0)

	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(tcp, TCP);
	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(udp, UDP);

	flow_defer_handler(c, now);
#undef CALL_PROTO_HANDLER

	if (!c->no_ndp)
		ndp_timer(c, now);
}

/**
 * random_init() - Initialise things based on random data
 * @c:		Execution context
 */
static void random_init(struct ctx *c)
{
	unsigned int seed;

	/* Create secret value for SipHash calculations */
	raw_random(&c->hash_secret, sizeof(c->hash_secret));

	/* Seed pseudo-RNG for things that need non-cryptographic random */
	raw_random(&seed, sizeof(seed));
	srandom(seed);
}

/**
 * timer_init() - Set initial timestamp for timer runs to current time
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_init(struct ctx *c, const struct timespec *now)
{
	c->tcp.timer_run = c->udp.timer_run = c->icmp.timer_run = *now;
}

/**
 * proto_update_l2_buf() - Update scatter-gather L2 buffers in protocol handlers
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 */
void proto_update_l2_buf(const unsigned char *eth_d, const unsigned char *eth_s)
{
	tcp_update_l2_buf(eth_d, eth_s);
	udp_update_l2_buf(eth_d, eth_s);
}

/**
 * exit_handler() - Signal handler for SIGQUIT and SIGTERM
 * @unused:	Unused, handler deals with SIGQUIT and SIGTERM only
 *
 * TODO: After unsharing the PID namespace and forking, SIG_DFL for SIGTERM and
 * SIGQUIT unexpectedly doesn't cause the process to terminate, figure out why.
 *
 * #syscalls exit_group
 */
void exit_handler(int signal)
{
	(void)signal;

	exit(EXIT_SUCCESS);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Options, plus optional target PID for pasta mode
 *
 * Return: non-zero on failure
 *
 * #syscalls read write writev
 * #syscalls socket getsockopt setsockopt s390x:socketcall i686:socketcall close
 * #syscalls bind connect recvfrom sendto shutdown
 * #syscalls arm:recv ppc64le:recv arm:send ppc64le:send
 * #syscalls accept4|accept listen epoll_ctl epoll_wait|epoll_pwait epoll_pwait
 * #syscalls clock_gettime arm:clock_gettime64 i686:clock_gettime64
 */
int main(int argc, char **argv)
{
	struct epoll_event events[EPOLL_EVENTS];
	int nfds, i, devnull_fd = -1;
	char argv0[PATH_MAX], *name;
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	struct sigaction sa;

	if (clock_gettime(CLOCK_MONOTONIC, &log_start))
		die_perror("Failed to get CLOCK_MONOTONIC time");

	arch_avx2_exec(argv);

	isolate_initial(argc, argv);

	c.pasta_netns_fd = c.fd_tap = c.pidfile_fd = -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = exit_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	if (argc < 1)
		exit(EXIT_FAILURE);

	strncpy(argv0, argv[0], PATH_MAX - 1);
	name = basename(argv0);
	if (strstr(name, "pasta")) {
		sa.sa_handler = pasta_child_handler;
		if (sigaction(SIGCHLD, &sa, NULL))
			die_perror("Couldn't install signal handlers");

		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
			die_perror("Couldn't set disposition for SIGPIPE");

		c.mode = MODE_PASTA;
	} else if (strstr(name, "passt")) {
		c.mode = MODE_PASST;
	} else {
		exit(EXIT_FAILURE);
	}

	madvise(pkt_buf, TAP_BUF_BYTES, MADV_HUGEPAGE);

	c.epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (c.epollfd == -1)
		die_perror("Failed to create epoll file descriptor");

	if (getrlimit(RLIMIT_NOFILE, &limit))
		die_perror("Failed to get maximum value of open files limit");

	c.nofile = limit.rlim_cur = limit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limit))
		die_perror("Failed to set current limit for open files");

	sock_probe_mem(&c);

	conf(&c, argc, argv);
	trace_init(c.trace);

	pasta_netns_quit_init(&c);

	tap_sock_init(&c);

	random_init(&c);

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		die_perror("Failed to get CLOCK_MONOTONIC time");

	flow_init();

	if ((!c.no_udp && udp_init(&c)) || (!c.no_tcp && tcp_init(&c)))
		exit(EXIT_FAILURE);

	proto_update_l2_buf(c.guest_mac, c.our_tap_mac);

	if (c.ifi4 && !c.no_dhcp)
		dhcp_init();

	if (c.ifi6 && !c.no_dhcpv6)
		dhcpv6_init(&c);

	pcap_init(&c);

	if (!c.foreground) {
		if ((devnull_fd = open("/dev/null", O_RDWR | O_CLOEXEC)) < 0)
			die_perror("Failed to open /dev/null");
	}

	if (isolate_prefork(&c))
		die("Failed to sandbox process, exiting");

	if (!c.foreground) {
		__daemon(c.pidfile_fd, devnull_fd);
		log_stderr = false;
	} else {
		pidfile_write(c.pidfile_fd, getpid());
	}

	if (pasta_child_pid) {
		kill(pasta_child_pid, SIGUSR1);
		log_stderr = false;
	}

	isolate_postfork(&c);

	timer_init(&c, &now);

loop:
	/* NOLINTBEGIN(bugprone-branch-clone): intervals can be the same */
	/* cppcheck-suppress [duplicateValueTernary, unmatchedSuppression] */
	nfds = epoll_wait(c.epollfd, events, EPOLL_EVENTS, TIMER_INTERVAL);
	/* NOLINTEND(bugprone-branch-clone) */
	if (nfds == -1 && errno != EINTR)
		die_perror("epoll_wait() failed in main loop");

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		err_perror("Failed to get CLOCK_MONOTONIC time");

	for (i = 0; i < nfds; i++) {
		union epoll_ref ref = *((union epoll_ref *)&events[i].data.u64);
		uint32_t eventmask = events[i].events;

		trace("%s: epoll event on %s %i (events: 0x%08x)",
		      c.mode == MODE_PASTA ? "pasta" : "passt",
		      EPOLL_TYPE_STR(ref.type), ref.fd, eventmask);

		switch (ref.type) {
		case EPOLL_TYPE_TAP_PASTA:
			tap_handler_pasta(&c, eventmask, &now);
			break;
		case EPOLL_TYPE_TAP_PASST:
			tap_handler_passt(&c, eventmask, &now);
			break;
		case EPOLL_TYPE_TAP_LISTEN:
			tap_listen_handler(&c, eventmask);
			break;
		case EPOLL_TYPE_NSQUIT_INOTIFY:
			pasta_netns_quit_inotify_handler(&c, ref.fd);
			break;
		case EPOLL_TYPE_NSQUIT_TIMER:
			pasta_netns_quit_timer_handler(&c, ref);
			break;
		case EPOLL_TYPE_TCP:
			tcp_sock_handler(&c, ref, eventmask);
			break;
		case EPOLL_TYPE_TCP_SPLICE:
			tcp_splice_sock_handler(&c, ref, eventmask);
			break;
		case EPOLL_TYPE_TCP_LISTEN:
			tcp_listen_handler(&c, ref, &now);
			break;
		case EPOLL_TYPE_TCP_TIMER:
			tcp_timer_handler(&c, ref);
			break;
		case EPOLL_TYPE_UDP_LISTEN:
			udp_listen_sock_handler(&c, ref, eventmask, &now);
			break;
		case EPOLL_TYPE_UDP_REPLY:
			udp_reply_sock_handler(&c, ref, eventmask, &now);
			break;
		case EPOLL_TYPE_PING:
			icmp_sock_handler(&c, ref);
			break;
		default:
			/* Can't happen */
			ASSERT(0);
		}
	}

	post_handler(&c, &now);

	goto loop;
}
