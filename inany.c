/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * inany.c - Types and helpers for handling addresses which could be
 *           IPv6 or IPv4 (encoded as IPv4-mapped IPv6 addresses)
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"

const union inany_addr inany_loopback4 = INANY_INIT4(IN4ADDR_LOOPBACK_INIT);
const union inany_addr inany_any4 = INANY_INIT4(IN4ADDR_ANY_INIT);

/** inany_ntop - Convert an IPv[46] address to text format
 * @src:	IPv[46] address
 * @dst:	output buffer, minimum INANY_ADDRSTRLEN bytes
 * @size:	size of buffer at @dst
 *
 * Return: On success, a non-null pointer to @dst, NULL on failure
 */
const char *inany_ntop(const union inany_addr *src, char *dst, socklen_t size)
{
	const struct in_addr *v4 = inany_v4(src);

	if (v4)
		return inet_ntop(AF_INET, v4, dst, size);

	return inet_ntop(AF_INET6, &src->a6, dst, size);
}
