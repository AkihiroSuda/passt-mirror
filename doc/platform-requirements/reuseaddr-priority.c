// SPDX-License-Identifier: GPL-2.0-or-later

/* reuseaddr-priority.c
 *
 * Verify which SO_REUSEADDR UDP sockets get priority to receive
 * =============================================================
 *
 * SO_REUSEADDR allows multiple sockets to bind to overlapping addresses, so
 * there can be multiple sockets eligible to receive the same packet.  The exact
 * semantics of which socket will receive in this circumstance isn't very well
 * documented.
 *
 * This program verifies that things behave the way we expect.  Specifically we
 * expect:
 *
 * - If both a connected and an unconnected socket could receive a datagram, the
 *   connected one will receive it in preference to the unconnected one.
 *
 * - If an unconnected socket bound to a specific address and an unconnected
 *   socket bound to the "any" address (0.0.0.0 or ::) could receive a datagram,
 *   then the one with a specific address will receive it in preference to the
 *   other.
 *
 * These should be true regardless of the order the sockets are created in, or
 * the order they're polled in.
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define SRCPORT	13246U
#define DSTPORT	13247U

/* Different cases for receiving socket configuration */
enum sock_type {
	/* Socket is bound to 0.0.0.0:DSTPORT and not connected */
	SOCK_BOUND_ANY = 0,

	/* Socket is bound to 127.0.0.1:DSTPORT and not connected */
	SOCK_BOUND_LO = 1,

	/* Socket is bound to 0.0.0.0:DSTPORT and connected to 127.0.0.1:SRCPORT */
	SOCK_CONNECTED = 2,

	NUM_SOCK_TYPES,
};

typedef enum sock_type order_t[NUM_SOCK_TYPES];

static order_t orders[] = {
	{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
};

/* 127.0.0.2 */
#define INADDR_LOOPBACK2	((in_addr_t)(0x7f000002))

/* 0.0.0.0:DSTPORT */
static const struct sockaddr_in any_dst = SOCKADDR_INIT(INADDR_ANY, DSTPORT);
/* 127.0.0.1:DSTPORT */
static const struct sockaddr_in lo_dst = SOCKADDR_INIT(INADDR_LOOPBACK, DSTPORT);

/* 127.0.0.2:DSTPORT */
static const struct sockaddr_in lo2_dst = SOCKADDR_INIT(INADDR_LOOPBACK2, DSTPORT);

/* 127.0.0.1:SRCPORT */
static const struct sockaddr_in lo_src = SOCKADDR_INIT(INADDR_LOOPBACK, SRCPORT);

/* Random token to send in datagram */
static long token;

/* Get a socket of the specified type for receiving */
static int sock_recv(enum sock_type type)
{
	const struct sockaddr *connect_sa = NULL;
	const struct sockaddr *bind_sa = NULL;
	int s;

	s = sock_reuseaddr();

	switch (type) {
	case SOCK_CONNECTED:
		connect_sa = (struct sockaddr *)&lo_src;
		/* fallthrough */
	case SOCK_BOUND_ANY:
		bind_sa = (struct sockaddr *)&any_dst;
		break;

	case SOCK_BOUND_LO:
		bind_sa = (struct sockaddr *)&lo_dst;
		break;

	default:
		die("bug");
	}

	if (bind_sa)
		if (bind(s, bind_sa, sizeof(struct sockaddr_in)) < 0)
			die("bind(): %s\n", strerror(errno));
	if (connect_sa)
		if (connect(s, connect_sa, sizeof(struct sockaddr_in)) < 0)
			die("connect(): %s\n", strerror(errno));

	return s;
}

/* Get a socket suitable for sending to the given type of receiving socket */
static int sock_send(enum sock_type type)
{
	const struct sockaddr *connect_sa = NULL;
	const struct sockaddr *bind_sa = NULL;
	int s;

	s = sock_reuseaddr();

	switch (type) {
	case SOCK_BOUND_ANY:
		connect_sa = (struct sockaddr *)&lo2_dst;
		break;

	case SOCK_CONNECTED:
		bind_sa = (struct sockaddr *)&lo_src;
		/* fallthrough */
	case SOCK_BOUND_LO:
		connect_sa = (struct sockaddr *)&lo_dst;
		break;

	default:
		die("bug");
	}

	if (bind_sa)
		if (bind(s, bind_sa, sizeof(struct sockaddr_in)) < 0)
			die("bind(): %s\n", strerror(errno));
	if (connect_sa)
		if (connect(s, connect_sa, sizeof(struct sockaddr_in)) < 0)
			die("connect(): %s\n", strerror(errno));

	return s;
}

/* Check for expected behaviour with one specific ordering for various operations:
 *
 * @recv_create_order:	Order to create receiving sockets in
 * @send_create_order:	Order to create sending sockets in
 * @test_order:		Order to test the behaviour of different types
 * @recv_order:		Order to check the receiving sockets
 */
static void check_one_order(const order_t recv_create_order,
			    const order_t send_create_order,
			    const order_t test_order,
			    const order_t recv_order)
{
	int rs[NUM_SOCK_TYPES];
	int ss[NUM_SOCK_TYPES];
	int nfds = 0;
	int i, j;

	for (i = 0; i < NUM_SOCK_TYPES; i++) {
		enum sock_type t = recv_create_order[i];
		int s;

		s = sock_recv(t);
		if (s >= nfds)
			nfds = s + 1;

		rs[t] = s;
	}

	for (i = 0; i < NUM_SOCK_TYPES; i++) {
		enum sock_type t = send_create_order[i];

		ss[t] = sock_send(t);
	}

	for (i = 0; i < NUM_SOCK_TYPES; i++) {
		enum sock_type ti = test_order[i];
		int recv_via = -1;

		send_token(ss[ti], token);

		for (j = 0; j < NUM_SOCK_TYPES; j++) {
			enum sock_type tj = recv_order[j];

			if (recv_token(rs[tj], token)) {
				if (recv_via != -1)
					die("Received token more than once\n");
				recv_via = tj;
			}
		}

		if (recv_via == -1)
			die("Didn't receive token at all\n");
		if (recv_via != ti)
			die("Received token via unexpected socket\n");
	}

	for (i = 0; i < NUM_SOCK_TYPES; i++) {
		close(rs[i]);
		close(ss[i]);
	}
}

static void check_all_orders(void)
{
	int norders = sizeof(orders) / sizeof(orders[0]);
	int i, j, k, l;

	for (i = 0; i < norders; i++)
		for (j = 0; j < norders; j++)
			for (k = 0; k < norders; k++)
				for (l = 0; l < norders; l++)
					check_one_order(orders[i], orders[j],
							orders[k], orders[l]);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	token = random();

	check_all_orders();

	printf("SO_REUSEADDR receive priorities seem to work as expected\n");

	exit(0);
}
