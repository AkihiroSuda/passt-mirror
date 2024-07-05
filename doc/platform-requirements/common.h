// SPDX-License-Identifier: GPL-2.0-or-later

/* common.h
 *
 * Useful shared functions
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */
#ifndef REUSEADDR_COMMON_H
#define REUSEADDR_COMMON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static inline void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define htons_constant(x)       (x)
#define htonl_constant(x)       (x)
#else
#define htons_constant(x)       (__bswap_constant_16(x))
#define htonl_constant(x)       (__bswap_constant_32(x))
#endif

#define SOCKADDR_INIT(addr, port)					\
	{								\
		.sin_family = AF_INET,					\
		.sin_addr = { .s_addr = htonl_constant(addr) },		\
		.sin_port = htons_constant(port),			\
	}

int sock_reuseaddr(void);
void send_token(int s, long token);
bool recv_token(int s, long token);

#endif /* REUSEADDR_COMMON_H */
