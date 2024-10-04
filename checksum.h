/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

struct udphdr;
struct icmphdr;
struct icmp6hdr;

uint32_t sum_16b(const void *buf, size_t len);
uint16_t csum_fold(uint32_t sum);
uint16_t csum_unaligned(const void *buf, size_t len, uint32_t init);
uint16_t csum_ip4_header(uint16_t l3len, uint8_t protocol,
			 struct in_addr saddr, struct in_addr daddr);
uint32_t proto_ipv4_header_psum(uint16_t l4len, uint8_t protocol,
				struct in_addr saddr, struct in_addr daddr);
void csum_udp4(struct udphdr *udp4hr,
	       struct in_addr saddr, struct in_addr daddr,
	       const struct iovec *iov, int iov_cnt, size_t offset);
void csum_icmp4(struct icmphdr *icmp4hr, const void *payload, size_t dlen);
uint32_t proto_ipv6_header_psum(uint16_t payload_len, uint8_t protocol,
				const struct in6_addr *saddr,
				const struct in6_addr *daddr);
void csum_udp6(struct udphdr *udp6hr,
	       const struct in6_addr *saddr, const struct in6_addr *daddr,
	       const struct iovec *iov, int iov_cnt, size_t offset);
void csum_icmp6(struct icmp6hdr *icmp6hr,
		const struct in6_addr *saddr, const struct in6_addr *daddr,
		const void *payload, size_t dlen);
uint32_t csum_unfolded(const void *buf, size_t len, uint32_t init);
uint16_t csum(const void *buf, size_t len, uint32_t init);
uint16_t csum_iov(const struct iovec *iov, size_t n, size_t offset,
		  uint32_t init);

#endif /* CHECKSUM_H */
