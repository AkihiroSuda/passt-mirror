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
 */

#include <stddef.h>
#include <stdint.h>

#include "siphash.h"

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
