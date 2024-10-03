/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TAP_H
#define TAP_H

#define ETH_HDR_INIT(proto) { .h_proto = htons_constant(proto) }

/**
 * struct tap_hdr - tap backend specific headers
 * @vnet_len:	Frame length (for qemu socket transport)
 */
struct tap_hdr {
	uint32_t vnet_len;
} __attribute__((packed));

/**
 * tap_hdr_iov() - struct iovec for a tap header
 * @c:		Execution context
 * @taph:	Pointer to tap specific header buffer
 *
 * Returns: A struct iovec covering the correct portion of @taph to use as the
 *          tap specific header in the current configuration.
 */
static inline struct iovec tap_hdr_iov(const struct ctx *c,
				       struct tap_hdr *thdr)
{
	return (struct iovec){
		.iov_base = thdr,
		.iov_len = c->mode == MODE_PASST ? sizeof(*thdr) : 0,
	};
}

/**
 * tap_hdr_update() - Update the tap specific header for a frame
 * @taph:	Tap specific header buffer to update
 * @l2len:	Frame length (including L2 headers)
 */
static inline void tap_hdr_update(struct tap_hdr *thdr, size_t l2len)
{
	thdr->vnet_len = htonl(l2len);
}

void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t dlen);
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    const void *in, size_t l4len);
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src);
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, void *in, size_t dlen);
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    const void *in, size_t l4len);
void tap_send_single(const struct ctx *c, const void *data, size_t l2len);
size_t tap_send_frames(const struct ctx *c, const struct iovec *iov,
		       size_t bufs_per_frame, size_t nframes);
void eth_update_mac(struct ethhdr *eh,
		    const unsigned char *eth_d, const unsigned char *eth_s);
void tap_listen_handler(struct ctx *c, uint32_t events);
void tap_handler_pasta(struct ctx *c, uint32_t events,
		       const struct timespec *now);
void tap_handler_passt(struct ctx *c, uint32_t events,
		       const struct timespec *now);
int tap_sock_unix_open(char *sock_path);
void tap_sock_init(struct ctx *c);
void tap_flush_pools(void);
void tap_handler(struct ctx *c, const struct timespec *now);
void tap_add_packet(struct ctx *c, ssize_t l2len, char *p);

#endif /* TAP_H */
