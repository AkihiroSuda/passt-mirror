// SPDX-License-Identifier: GPL-2.0-or-later

/* recv-zero.c
 *
 * Verify that we're able to discard datagrams by recv()ing into a zero-length
 * buffer.
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

#define DSTPORT	13257U

enum discard_method {
	DISCARD_NULL_BUF,
	DISCARD_ZERO_IOV,
	DISCARD_NULL_IOV,
	NUM_METHODS,
};

/* 127.0.0.1:DSTPORT */
static const struct sockaddr_in lo_dst = SOCKADDR_INIT(INADDR_LOOPBACK, DSTPORT);

static void test_discard(enum discard_method method)
{
	struct iovec zero_iov = { .iov_base = NULL, .iov_len = 0, };
	struct msghdr mh_zero = {
		.msg_iov = &zero_iov,
		.msg_iovlen = 1,
	};
	struct msghdr mh_null = {
		.msg_iov = NULL,
		.msg_iovlen = 0,
	};
	long token1, token2;
	int recv_s, send_s;
	ssize_t rc;

	token1 = random();
	token2 = random();

	recv_s = sock_reuseaddr();
	if (bind(recv_s, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("bind(): %s\n", strerror(errno));

	send_s = sock_reuseaddr();
	if (connect(send_s, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("connect(): %s\n", strerror(errno));

	send_token(send_s, token1);
	send_token(send_s, token2);

	switch (method) {
	case DISCARD_NULL_BUF:
		/* cppcheck-suppress nullPointer */
		rc = recv(recv_s, NULL, 0, MSG_DONTWAIT);
		if (rc < 0)
			die("discarding recv(): %s\n", strerror(errno));
		break;

	case DISCARD_ZERO_IOV:
		rc = recvmsg(recv_s, &mh_zero, MSG_DONTWAIT);
		if (rc < 0)
			die("recvmsg() with zero-length buffer: %s\n",
			    strerror(errno));
		if (!((unsigned)mh_zero.msg_flags & MSG_TRUNC))
			die("Missing MSG_TRUNC flag\n");
		break;

	case DISCARD_NULL_IOV:
		rc = recvmsg(recv_s, &mh_null, MSG_DONTWAIT);
		if (rc < 0)
			die("recvmsg() with zero-length iov: %s\n",
			    strerror(errno));
		if (!((unsigned)mh_null.msg_flags & MSG_TRUNC))
			die("Missing MSG_TRUNC flag\n");
		break;

	default:
		die("Bad method\n");
	}

	recv_token(recv_s, token2);

	/* cppcheck-suppress nullPointer */
	rc = recv(recv_s, NULL, 0, MSG_DONTWAIT);
	if (rc < 0 && errno != EAGAIN)
		die("redundant discarding recv(): %s\n", strerror(errno));
	if (rc >= 0)
		die("Unexpected receive: rc=%zd\n", rc);
}

int main(int argc, char *argv[])
{
	enum discard_method method;

	(void)argc;
	(void)argv;

	for (method = 0; method < NUM_METHODS; method++)
		test_discard(method);

	printf("Discarding datagrams with 0-length receives seems to work\n");

	exit(0);
}
