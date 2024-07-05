// SPDX-License-Identifier: GPL-2.0-or-later

/* common.c
 *
 * Common helper functions for testing SO_REUSEADDR behaviour
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "common.h"

int sock_reuseaddr(void)
{
	int y = 1;
	int s;
	

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		die("socket(): %s\n", strerror(errno));

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) , 0)
		die("SO_REUSEADDR: %s\n", strerror(errno));

	return s;
}

/* Send a token via the given connected socket */
void send_token(int s, long token)
{
	ssize_t rc;

	rc = send(s, &token, sizeof(token), 0);
	if (rc < 0)
		die("send(): %s\n", strerror(errno));
	if (rc < sizeof(token))
		die("short send()\n");
}

/* Attempt to receive a token via the given socket.
 *
 * Returns true if we received the token, false if we got an EAGAIN, dies in any
 * other case */
bool recv_token(int s, long token)
{
	ssize_t rc;
	long buf;

	rc = recv(s, &buf, sizeof(buf), MSG_DONTWAIT);
	if (rc < 0) {
		if (errno == EWOULDBLOCK)
			return false;
		die("recv(): %s\n", strerror(errno));
	}
	if (rc < sizeof(buf))
		die("short recv()\n");
	if (buf != token)
		die("data mismatch\n");
	return true;
}
