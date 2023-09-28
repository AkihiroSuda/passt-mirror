// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * siphash.c - SipHash routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * This is an implementation of the SipHash-2-4-64 functions needed for TCP
 * initial sequence numbers and socket lookup table hash for IPv4 and IPv6, see:
 *
 *	Aumasson, J.P. and Bernstein, D.J., 2012, December. SipHash: a fast
 *	short-input PRF. In International Conference on Cryptology in India
 *	(pp. 489-508). Springer, Berlin, Heidelberg.
 *
 *	http://cr.yp.to/siphash/siphash-20120918.pdf
 *
 * This includes code from the reference SipHash implementation at
 * https://github.com/veorq/SipHash/ originally licensed as follows:
 *
 * --
 *  SipHash reference C implementation
 *
 * Copyright (c) 2012-2021 Jean-Philippe Aumasson
 * <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 * --
 *
 * and from the Linux kernel implementation (lib/siphash.c), originally licensed
 * as follows:
 *
 * --
 * Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 * --
 *
 */

#include <stddef.h>
#include <stdint.h>

#include "siphash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

struct siphash_state {
	uint64_t v[4];
};

#define SIPHASH_INIT(k) { {						\
		0x736f6d6570736575ULL ^ (k)[0],				\
		0x646f72616e646f6dULL ^ (k)[1],				\
		0x6c7967656e657261ULL ^ (k)[0],				\
		0x7465646279746573ULL ^ (k)[1]				\
	} }

/**
 * sipround() - Perform rounds of SipHash scrambling
 * @v:		siphash state (4 x 64-bit integers)
 * @n:		Number of rounds to apply
 */
static inline void sipround(struct siphash_state *state, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		state->v[0] += state->v[1];
		state->v[1] = ROTL(state->v[1], 13) ^ state->v[0];
		state->v[0] = ROTL(state->v[0], 32);
		state->v[2] += state->v[3];
		state->v[3] = ROTL(state->v[3], 16) ^ state->v[2];
		state->v[0] += state->v[3];
		state->v[3] = ROTL(state->v[3], 21) ^ state->v[0];
		state->v[2] += state->v[1];
		state->v[1] = ROTL(state->v[1], 17) ^ state->v[2];
		state->v[2] = ROTL(state->v[2], 32);
	}
}

/**
 * siphash_feed() - Fold 64-bits of data into the hash state
 * @v:		siphash state (4 x 64-bit integers)
 * @in:		New value to fold into hash
 */
static inline void siphash_feed(struct siphash_state *state, uint64_t in)
{
	state->v[3] ^= in;
	sipround(state, 2);
	state->v[0] ^= in;
}

/**
 * siphash_final - Finalize SipHash calculations
 * @v:		siphash state (4 x 64-bit integers)
 * @len:	Total length of input data
 * @tail:	Final data for the hash (<= 7 bytes)
 */
static inline uint64_t siphash_final(struct siphash_state *state,
				     size_t len, uint64_t tail)
{
	uint64_t b = (uint64_t)(len) << 56 | tail;

	siphash_feed(state, b);
	state->v[2] ^= 0xff;
	sipround(state, 4);
	return state->v[0] ^ state->v[1] ^ state->v[2] ^ state->v[3];
}

/**
 * siphash_8b() - Table index or timestamp offset for TCP over IPv4 (8 bytes in)
 * @in:		Input data (remote address and two ports, or two addresses)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
/* Type-Based Alias Analysis (TBAA) optimisation in gcc 11 and 12 (-flto -O2)
 * makes these functions essentially useless by allowing reordering of stores of
 * input data across function calls. Not even declaring @in as char pointer is
 * enough: disable gcc's interpretation of strict aliasing altogether. See also:
 *
 *	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=106706
 *	https://stackoverflow.com/questions/2958633/gcc-strict-aliasing-and-horror-stories
 *	https://lore.kernel.org/all/alpine.LFD.2.00.0901121128080.6528__33422.5328093909$1232291247$gmane$org@localhost.localdomain/
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))
/* cppcheck-suppress unusedFunction */
uint64_t siphash_8b(const uint8_t *in, const uint64_t *k)
{
	struct siphash_state state = SIPHASH_INIT(k);

	siphash_feed(&state, *(uint64_t *)in);

	return siphash_final(&state, 8, 0);
}

/**
 * siphash_12b() - Initial sequence number for TCP over IPv4 (12 bytes in)
 * @in:		Input data (two addresses, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See siphash_8b() */
/* cppcheck-suppress unusedFunction */
uint64_t siphash_12b(const uint8_t *in, const uint64_t *k)
{
	struct siphash_state state = SIPHASH_INIT(k);
	uint32_t *in32 = (uint32_t *)in;

	siphash_feed(&state, (uint64_t)(*(in32 + 1)) << 32 | *in32);

	return siphash_final(&state, 12, *(in32 + 2));
}

/**
 * siphash_20b() - Table index for TCP over IPv6 (20 bytes in)
 * @in:		Input data (remote address, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See siphash_8b() */
uint64_t siphash_20b(const uint8_t *in, const uint64_t *k)
{
	struct siphash_state state = SIPHASH_INIT(k);
	uint32_t *in32 = (uint32_t *)in;
	int i;

	for (i = 0; i < 2; i++, in32 += 2)
		siphash_feed(&state, (uint64_t)(*(in32 + 1)) << 32 | *in32);

	return siphash_final(&state, 20, *in32);
}

/**
 * siphash_32b() - Timestamp offset for TCP over IPv6 (32 bytes in)
 * @in:		Input data (two addresses)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See siphash_8b() */
/* cppcheck-suppress unusedFunction */
uint64_t siphash_32b(const uint8_t *in, const uint64_t *k)
{
	struct siphash_state state = SIPHASH_INIT(k);
	uint64_t *in64 = (uint64_t *)in;
	int i;

	for (i = 0; i < 4; i++, in64++)
		siphash_feed(&state, *in64);

	return siphash_final(&state, 32, 0);
}

/**
 * siphash_36b() - Initial sequence number for TCP over IPv6 (36 bytes in)
 * @in:		Input data (two addresses, two ports)
 * @k:		Hash function key, 128 bits
 *
 * Return: the 64-bit hash output
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See siphash_8b() */
uint64_t siphash_36b(const uint8_t *in, const uint64_t *k)
{
	struct siphash_state state = SIPHASH_INIT(k);
	uint32_t *in32 = (uint32_t *)in;
	int i;

	for (i = 0; i < 4; i++, in32 += 2)
		siphash_feed(&state, (uint64_t)(*(in32 + 1)) << 32 | *in32);

	return siphash_final(&state, 36, *in32);
}
