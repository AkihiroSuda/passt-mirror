/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include "log.h"

#define VERSION_BLOB							       \
	VERSION "\n"							       \
	"Copyright Red Hat\n"						       \
	"GNU General Public License, version 2 or later\n"		       \
	"  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>\n"	       \
	"This is free software: you are free to change and redistribute it.\n" \
	"There is NO WARRANTY, to the extent permitted by law.\n\n"

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	SECCOMP_RET_KILL
#endif
#ifndef ETH_MAX_MTU
#define ETH_MAX_MTU			USHRT_MAX
#endif
#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU			68
#endif

#ifndef MIN
#define MIN(x, y)		(((x) < (y)) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y)		(((x) > (y)) ? (x) : (y))
#endif

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(n, d)	(((n) + (d) / 2) / (d))
#define ROUND_DOWN(x, y)	((x) & ~((y) - 1))
#define ROUND_UP(x, y)		(((x) + (y) - 1) & ~((y) - 1))

#define MAX_FROM_BITS(n)	(((1U << (n)) - 1))

#define BIT(n)			(1UL << (n))
#define BITMAP_BIT(n)		(BIT((n) % (sizeof(long) * 8)))
#define BITMAP_WORD(n)		(n / (sizeof(long) * 8))

#define SWAP(a, b)							\
	do {								\
		__typeof__(a) __x = (a); (a) = (b); (b) = __x;		\
	} while (0)							\

#define STRINGIFY(x)	#x
#define STR(x)		STRINGIFY(x)

#define ASSERT(expr)							\
	do {								\
		if (!(expr)) {						\
			err("ASSERTION FAILED in %s (%s:%d): %s",	\
			    __func__, __FILE__, __LINE__, STRINGIFY(expr)); \
			/* This may actually SIGSYS, due to seccomp,	\
			 * but that will still get the job done		\
			 */						\
			abort();					\
		}							\
	} while (0)

#ifdef P_tmpdir
#define TMPDIR		P_tmpdir
#else
#define TMPDIR		"/tmp"
#endif

#define V4		0
#define V6		1
#define IP_VERSIONS	2

#define ARRAY_SIZE(a)		((int)(sizeof(a) / sizeof((a)[0])))

#define IN_INTERVAL(a, b, x)	((x) >= (a) && (x) <= (b))
#define FD_PROTO(x, proto)						\
	(IN_INTERVAL(c->proto.fd_min, c->proto.fd_max, (x)))

#define PORT_EPHEMERAL_MIN	((1 << 15) + (1 << 14))		/* RFC 6335 */
#define PORT_IS_EPHEMERAL(port) ((port) >= PORT_EPHEMERAL_MIN)

#define MAC_ZERO		((uint8_t [ETH_ALEN]){ 0 })
#define MAC_IS_ZERO(addr)	(!memcmp((addr), MAC_ZERO, ETH_ALEN))

#ifndef __bswap_constant_16
#define __bswap_constant_16(x)						\
	((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#endif

#ifndef __bswap_constant_32
#define __bswap_constant_32(x)						\
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |	\
	 (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define	htons_constant(x)	(x)
#define	htonl_constant(x)	(x)
#else
#define	htons_constant(x)	(__bswap_constant_16(x))
#define	htonl_constant(x)	(__bswap_constant_32(x))
#endif

#define NS_FN_STACK_SIZE	(RLIMIT_STACK_VAL * 1024 / 8)
int do_clone(int (*fn)(void *), char *stack_area, size_t stack_size, int flags,
	     void *arg);
#define NS_CALL(fn, arg)						\
	do {								\
		char ns_fn_stack[NS_FN_STACK_SIZE];			\
									\
		do_clone((fn), ns_fn_stack, sizeof(ns_fn_stack),	\
			 CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,\
			 (void *)(arg));				\
	} while (0)

#define RCVBUF_BIG		(2UL * 1024 * 1024)
#define SNDBUF_BIG		(4UL * 1024 * 1024)
#define SNDBUF_SMALL		(128UL * 1024)

#include <net/if.h>
#include <limits.h>
#include <stdint.h>

#include "packet.h"

struct ctx;

/* cppcheck-suppress funcArgNamesDifferent */
__attribute__ ((weak)) int ffsl(long int i) { return __builtin_ffsl(i); }
int sock_l4(const struct ctx *c, sa_family_t af, uint8_t proto,
	    const void *bind_addr, const char *ifname, uint16_t port,
	    uint32_t data);
void sock_probe_mem(struct ctx *c);
int timespec_diff_ms(const struct timespec *a, const struct timespec *b);
void bitmap_set(uint8_t *map, int bit);
void bitmap_clear(uint8_t *map, int bit);
int bitmap_isset(const uint8_t *map, int bit);
void bitmap_or(uint8_t *dst, size_t size, const uint8_t *a, const uint8_t *b);
char *line_read(char *buf, size_t len, int fd);
void ns_enter(const struct ctx *c);
bool ns_is_init(void);
int open_in_ns(const struct ctx *c, const char *path, int flags);
void write_pidfile(int fd, pid_t pid);
int __daemon(int pidfile_fd, int devnull_fd);
int fls(unsigned long x);
int write_file(const char *path, const char *buf);
int write_remainder(int fd, const struct iovec *iov, int iovcnt, size_t skip);

/**
 * mod_sub() - Modular arithmetic subtraction
 * @a:		Minued, unsigned value < @m
 * @b:		Subtrahend, unsigned value < @m
 * @m:		Modulus, must be less than (UINT_MAX / 2)
 *
 * Returns (@a - @b) mod @m, correctly handling unsigned underflows.
 */
static inline unsigned mod_sub(unsigned a, unsigned b, unsigned m)
{
	if (a < b)
		a += m;
	return a - b;
}

/**
 * mod_between() - Determine if a value is in a cyclic range
 * @x, @i, @j:	Unsigned values < @m
 * @m:		Modulus
 *
 * Returns true iff @x is in the cyclic range of values from @i..@j (mod @m),
 * inclusive of @i, exclusive of @j.
 */
static inline bool mod_between(unsigned x, unsigned i, unsigned j, unsigned m)
{
	return mod_sub(x, i, m) < mod_sub(j, i, m);
}

/*
 * Workarounds for https://github.com/llvm/llvm-project/issues/58992
 *
 * For a number (maybe all) system calls that _write_ a socket address,
 * clang-tidy doesn't register that the memory of the socket address will be
 * initialised after the call.  This can't easily be worked around with
 * clang-tidy suppressions, because the warning doesn't show on the syscall
 * itself but later when we access the supposedly uninitialised field.
 */
static inline void sa_init(struct sockaddr *sa, const socklen_t *sl)
{
#ifdef CLANG_TIDY_58992
	if (sa)
		memset(sa, 0, *sl);
#else
	(void)sa;
	(void)sl;
#endif /* CLANG_TIDY_58992 */
}

static inline ssize_t wrap_recvfrom(int sockfd, void *buf, size_t len,
				    int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	sa_init(src_addr, addrlen);
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}
#define recvfrom(s, buf, len, flags, src, addrlen)		\
	wrap_recvfrom((s), (buf), (len), (flags), (src), (addrlen))

static inline int wrap_accept4(int sockfd, struct sockaddr *addr,
			       socklen_t *addrlen, int flags)
{
	sa_init(addr, addrlen);
	return accept4(sockfd, addr, addrlen, flags);
}
#define accept4(s, addr, addrlen, flags) \
	wrap_accept4((s), (addr), (addrlen), (flags))

#endif /* UTIL_H */
