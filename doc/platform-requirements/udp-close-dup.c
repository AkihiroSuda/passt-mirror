// SPDX-License-Identifier: GPL-2.0-or-later

/* udp-close-dup.c
 *
 * Verify that closing one dup() of a UDP socket won't stop other dups from
 * receiving packets.
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define DSTPORT	13257U

/* 127.0.0.1:DSTPORT */
static const struct sockaddr_in lo_dst = SOCKADDR_INIT(INADDR_LOOPBACK, DSTPORT);

enum dup_method {
	DUP_DUP,
	DUP_FCNTL,
	NUM_METHODS,
};

static void test_close_dup(enum dup_method method)
{
	long token;
	int s1, s2, send_s;
	ssize_t rc;

	s1 = sock_reuseaddr();
	if (bind(s1, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("bind(): %s\n", strerror(errno));

	send_s = sock_reuseaddr();
	if (connect(send_s, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("connect(): %s\n", strerror(errno));

	/* Receive before duplicating */
	token = random();
	send_token(send_s, token);
	recv_token(s1, token);

	switch (method) {
	case DUP_DUP:
		/* NOLINTNEXTLINE(android-cloexec-dup) */
		s2 = dup(s1);
		if (s2 < 0)
			die("dup(): %s\n", strerror(errno));
		break;
	case DUP_FCNTL:
		s2 = fcntl(s1, F_DUPFD_CLOEXEC, 0);
		if (s2 < 0)
			die("F_DUPFD_CLOEXEC: %s\n", strerror(errno));
		break;
	default:
		die("Bad method\n");
	}

	/* Receive via original handle */
	token = random();
	send_token(send_s, token);
	recv_token(s1, token);

	/* Receive via duplicated handle */
	token = random();
	send_token(send_s, token);
	recv_token(s2, token);

	/* Close duplicate */
	rc = close(s2);
	if (rc < 0)
		die("close() dup: %s\n", strerror(errno));

	/* Receive after closing duplicate */
	token = random();
	send_token(send_s, token);
	recv_token(s1, token);
}

int main(int argc, char *argv[])
{
	enum dup_method method;

	(void)argc;
	(void)argv;

	for (method = 0; method < NUM_METHODS; method++)
		test_close_dup(method);

	printf("Closing dup()ed UDP sockets seems to work as expected\n");

	exit(0);
}
