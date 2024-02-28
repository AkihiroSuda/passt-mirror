/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * inany.h - Types and helpers for handling addresses which could be
 *           IPv6 or IPv4 (encoded as IPv4-mapped IPv6 addresses)
 */

#ifndef INANY_H
#define INANY_H

/** union inany_addr - Represents either an IPv4 or IPv6 address
 * @a6:			Address as an IPv6 address, may be IPv4-mapped
 * @v4mapped.zero:	All zero-bits for an IPv4 address
 * @v4mapped.one:	All one-bits for an IPv4 address
 * @v4mapped.a4:	If @a6 is an IPv4 mapped address, the IPv4 address
 * @u64:		As an array of u64s (solely for hashing)
 *
 * @v4mapped and @u64 shouldn't be accessed except via helpers.
 */
union inany_addr {
	struct in6_addr a6;
	struct {
		uint8_t zero[10];
		uint8_t one[2];
		struct in_addr a4;
	} v4mapped;
	uint32_t u32[4];
};
static_assert(sizeof(union inany_addr) == sizeof(struct in6_addr),
	      "union inany_addr is larger than an IPv6 address");
static_assert(_Alignof(union inany_addr) == _Alignof(uint32_t),
	      "union inany_addr has unexpected alignment");

/** inany_v4 - Extract IPv4 address, if present, from IPv[46] address
 * @addr:	IPv4 or IPv6 address
 *
 * Return: IPv4 address if @addr is IPv4, NULL otherwise
 */
static inline struct in_addr *inany_v4(const union inany_addr *addr)
{
	if (!IN6_IS_ADDR_V4MAPPED(&addr->a6))
		return NULL;
	return (struct in_addr *)&addr->v4mapped.a4;
}

/** inany_equals - Compare two IPv[46] addresses
 * @a, @b:	IPv[46] addresses
 *
 * Return: true if @a and @b are the same address
 */
static inline bool inany_equals(const union inany_addr *a,
				const union inany_addr *b)
{
	return IN6_ARE_ADDR_EQUAL(&a->a6, &b->a6);
}

/** inany_is_loopback() - Check if address is loopback
 * @a:		IPv[46] address
 *
 * Return: true if @a is either ::1 or in 127.0.0.1/8
 */
static inline bool inany_is_loopback(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return IN6_IS_ADDR_LOOPBACK(&a->a6) || (v4 && IN4_IS_ADDR_LOOPBACK(v4));
}

/** inany_is_unspecified() - Check if address is unspecified
 * @a:		IPv[46] address
 *
 * Return: true if @a is either :: or 0.0.0.0
 */
static inline bool inany_is_unspecified(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return IN6_IS_ADDR_UNSPECIFIED(&a->a6) ||
		(v4 && IN4_IS_ADDR_UNSPECIFIED(v4));
}

/** inany_is_multicast() - Check if address is multicast or broadcast
 * @a:		IPv[46] address
 *
 * Return: true if @a is IPv6 multicast or IPv4 multicast or broadcast
 */
static inline bool inany_is_multicast(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return IN6_IS_ADDR_MULTICAST(&a->a6) ||
		(v4 && (IN4_IS_ADDR_MULTICAST(v4) ||
			IN4_IS_ADDR_BROADCAST(v4)));
}

/** inany_is_unicast() - Check if address is specified and unicast
 * @a:		IPv[46] address
 *
 * Return: true if @a is specified and a unicast address
 */
/* cppcheck-suppress unusedFunction */
static inline bool inany_is_unicast(const union inany_addr *a)
{
	return !inany_is_unspecified(a) && !inany_is_multicast(a);
}

/** inany_from_af - Set IPv[46] address from IPv4 or IPv6 address
 * @aa:		Pointer to store IPv[46] address
 * @af:		Address family of @addr
 * @addr:	struct in_addr (IPv4) or struct in6_addr (IPv6)
 */
static inline void inany_from_af(union inany_addr *aa,
				 sa_family_t af, const void *addr)
{
	if (af == AF_INET6) {
		aa->a6 = *((struct in6_addr *)addr);
	} else if (af == AF_INET) {
		memset(&aa->v4mapped.zero, 0, sizeof(aa->v4mapped.zero));
		memset(&aa->v4mapped.one, 0xff, sizeof(aa->v4mapped.one));
		aa->v4mapped.a4 = *((struct in_addr *)addr);
	} else {
		/* Not valid to call with other address families */
		ASSERT(0);
	}
}

/** inany_from_sockaddr - Extract IPv[46] address and port number from sockaddr
 * @aa:		Pointer to store IPv[46] address
 * @port:	Pointer to store port number, host order
 * @addr:	struct sockaddr_in (IPv4) or struct sockaddr_in6 (IPv6)
 */
static inline void inany_from_sockaddr(union inany_addr *aa, in_port_t *port,
				       const void *addr)
{
	const struct sockaddr *sa = (const struct sockaddr *)addr;

	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;

		inany_from_af(aa, AF_INET6, &sa6->sin6_addr);
		*port = ntohs(sa6->sin6_port);
	} else if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;

		inany_from_af(aa, AF_INET, &sa4->sin_addr);
		*port = ntohs(sa4->sin_port);
	} else {
		/* Not valid to call with other address families */
		ASSERT(0);
	}
}

/** inany_siphash_feed- Fold IPv[46] address into an in-progress siphash
 * @state:	siphash state
 * @aa:		inany to hash
 */
static inline void inany_siphash_feed(struct siphash_state *state,
				      const union inany_addr *aa)
{
	siphash_feed(state, (uint64_t)aa->u32[0] << 32 | aa->u32[1]);
	siphash_feed(state, (uint64_t)aa->u32[2] << 32 | aa->u32[3]);
}

#endif /* INANY_H */
