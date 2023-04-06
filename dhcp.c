// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * dhcp.c - Minimalistic DHCP server for PASST
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "util.h"
#include "checksum.h"
#include "packet.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "dhcp.h"

/**
 * struct opt - DHCP option
 * @sent:	Convenience flag, set while filling replies
 * @slen:	Length of option defined for server
 * @s:		Option payload from server
 * @clen:	Length of option received from client
 * @c:		Option payload from client
 */
struct opt {
	int sent;
	int slen;
	uint8_t s[255];
	int clen;
	uint8_t c[255];
};

static struct opt opts[255];

#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8
#define DHCPFORCERENEW	9

#define OPT_MIN		60 /* RFC 951 */

/**
 * dhcp_init() - Initialise DHCP options
 */
void dhcp_init(void)
{
	opts[1]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Mask */
	opts[3]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Router */
	opts[51] = (struct opt) { 0, 4, {  0xff,
					   0xff,
					   0xff,
					   0xff }, 0, { 0 }, };	/* Lease time */
	opts[53] = (struct opt) { 0, 1, {     0 }, 0, { 0 }, };	/* Type */
	opts[54] = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Server ID */
}

/**
 * struct msg - BOOTP/DHCP message
 * @op:		BOOTP message type
 * @htype:	Hardware address type
 * @hlen:	Hardware address length
 * @hops:	DHCP relay hops
 * @xid:	Transaction ID randomly chosen by client
 * @secs:	Seconds elapsed since beginning of acquisition or renewal
 * @flags:	DHCP message flags
 * @ciaddr:	Client IP address in BOUND, RENEW, REBINDING
 * @yiaddr:	IP address being offered or assigned
 * @siaddr:	Next server to use in bootstrap
 * @giaddr:	Relay agent IP address
 * @chaddr:	Client hardware address
 * @sname:	Server host name
 * @file:	Boot file name
 * @magic:	Magic cookie prefix before options
 * @o:		Options
 */
struct msg {
	uint8_t op;
#define BOOTREQUEST	1
#define BOOTREPLY	2
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	struct in_addr yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t o[308];
} __attribute__((__packed__));

/**
 * fill_one() - Fill a single option in message
 * @m:		Message to fill
 * @o:		Option number
 * @offset:	Current offset within options field, updated on insertion
 */
static void fill_one(struct msg *m, int o, int *offset)
{
	m->o[*offset] = o;
	m->o[*offset + 1] = opts[o].slen;
	memcpy(&m->o[*offset + 2], opts[o].s, opts[o].slen);

	opts[o].sent = 1;
	*offset += 2 + opts[o].slen;
}

/**
 * fill() - Fill options in message
 * @m:		Message to fill
 *
 * Return: current size of options field
 */
static int fill(struct msg *m)
{
	int i, o, offset = 0;

	m->op = BOOTREPLY;
	m->secs = 0;

	for (o = 0; o < 255; o++)
		opts[o].sent = 0;

	for (i = 0; i < opts[55].clen; i++) {
		o = opts[55].c[i];
		if (opts[o].slen)
			fill_one(m, o, &offset);
	}

	for (o = 0; o < 255; o++) {
		if (opts[o].slen && !opts[o].sent)
			fill_one(m, o, &offset);
	}

	m->o[offset++] = 255;
	m->o[offset++] = 0;

	if (offset < OPT_MIN) {
		memset(&m->o[offset], 0, OPT_MIN - offset);
		offset = OPT_MIN;
	}

	return offset;
}

/**
 * opt_dns_search_dup_ptr() - Look for possible domain name compression pointer
 * @buf:	Current option buffer with existing labels
 * @cmp:	Portion of domain name being added
 * @len:	Length of current option buffer
 *
 * Return: offset to corresponding compression pointer if any, -1 if not found
 */
static int opt_dns_search_dup_ptr(unsigned char *buf, const char *cmp,
				  size_t len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		if (buf[i] == 0 &&
		    len - i - 1 >= strlen(cmp) &&
		    !memcmp(buf + i + 1, cmp, strlen(cmp)))
			return i;

		if ((buf[i] & 0xc0) == 0xc0 &&
		    len - i - 2 >= strlen(cmp) &&
		    !memcmp(buf + i + 2, cmp, strlen(cmp)))
			return i + 1;
	}

	return -1;
}

/**
 * opt_set_dns_search() - Fill data and set length for Domain Search option
 * @c:		Execution context
 * @max_len:	Maximum total length of option buffer
 */
static void opt_set_dns_search(const struct ctx *c, size_t max_len)
{
	char buf[NS_MAXDNAME];
	int i;

	opts[119].slen = 0;

	for (i = 0; i < 255; i++)
		max_len -= opts[i].slen;

	for (i = 0; *c->dns_search[i].n; i++) {
		unsigned int n;
		int count = -1;
		const char *p;

		buf[0] = 0;
		for (p = c->dns_search[i].n, n = 1; *p; p++) {
			if (*p == '.') {
				/* RFC 1035 4.1.4 Message compression */
				count = opt_dns_search_dup_ptr(opts[119].s,
							       p + 1,
							       opts[119].slen);

				if (count >= 0) {
					buf[n++] = '\xc0';
					buf[n++] = count;
					break;
				}
				buf[n++] = '.';
			} else {
				buf[n++] = *p;
			}
		}

		/* The compression pointer is also an end of label */
		if (count < 0)
			buf[n++] = 0;

		if (n >= max_len)
			break;

		memcpy(opts[119].s + opts[119].slen, buf, n);
		opts[119].slen += n;
		max_len -= n;
	}

	for (i = 0; i < opts[119].slen; i++) {
		if (!opts[119].s[i] || opts[119].s[i] == '.') {
			opts[119].s[i] = strcspn((char *)opts[119].s + i + 1,
						 ".\xc0");
		}
	}
}

/**
 * dhcp() - Check if this is a DHCP message, reply as needed
 * @c:		Execution context
 * @p:		Packet pool, single packet with Ethernet buffer
 *
 * Return: 0 if it's not a DHCP message, 1 if handled, -1 on failure
 */
int dhcp(const struct ctx *c, const struct pool *p)
{
	size_t mlen, len, offset = 0, opt_len, opt_off = 0;
	struct in_addr mask;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct udphdr *uh;
	unsigned int i;
	struct msg *m;

	eh  = packet_get(p, 0, offset, sizeof(*eh),  NULL);
	offset += sizeof(*eh);

	iph = packet_get(p, 0, offset, sizeof(*iph), NULL);
	if (!eh || !iph)
		return -1;

	offset += iph->ihl * 4UL;
	uh  = packet_get(p, 0, offset, sizeof(*uh),  &mlen);
	offset += sizeof(*uh);

	if (!uh)
		return -1;

	if (uh->dest != htons(67))
		return 0;

	if (c->no_dhcp)
		return 1;

	m   = packet_get(p, 0, offset, offsetof(struct msg, o), &opt_len);
	if (!m						||
	    mlen  != ntohs(uh->len) - sizeof(*uh)	||
	    mlen  <  offsetof(struct msg, o)		||
	    m->op != BOOTREQUEST)
		return -1;

	offset += offsetof(struct msg, o);

	while (opt_off + 2 < opt_len) {
		uint8_t *olen, *type, *val;

		type = packet_get(p, 0, offset + opt_off,	1,	NULL);
		olen = packet_get(p, 0, offset + opt_off + 1,	1,	NULL);
		if (!type || !olen)
			return -1;

		val =  packet_get(p, 0, offset + opt_off + 2,	*olen,	NULL);
		if (!val)
			return -1;

		memcpy(&opts[*type].c, val, *olen);
		opt_off += *olen + 2;
	}

	if (opts[53].c[0] == DHCPDISCOVER) {
		info("DHCP: offer to discover");
		opts[53].s[0] = DHCPOFFER;
	} else if (opts[53].c[0] == DHCPREQUEST) {
		info("DHCP: ack to request");
		opts[53].s[0] = DHCPACK;
	} else {
		return -1;
	}

	info("    from %02x:%02x:%02x:%02x:%02x:%02x",
	     m->chaddr[0], m->chaddr[1], m->chaddr[2],
	     m->chaddr[3], m->chaddr[4], m->chaddr[5]);

	m->yiaddr = c->ip4.addr;
	mask.s_addr = htonl(0xffffffff << (32 - c->ip4.prefix_len));
	memcpy(opts[1].s,  &mask,        sizeof(mask));
	memcpy(opts[3].s,  &c->ip4.gw,   sizeof(c->ip4.gw));
	memcpy(opts[54].s, &c->ip4.gw,   sizeof(c->ip4.gw));

	/* If the gateway is not on the assigned subnet, send an option 121
	 * (Classless Static Routing) adding a dummy route to it.
	 */
	if ((c->ip4.addr.s_addr & mask.s_addr)
	    != (c->ip4.gw.s_addr & mask.s_addr)) {
		/* a.b.c.d/32:0.0.0.0, 0:a.b.c.d */
		opts[121].slen = 14;
		opts[121].s[0] = 32;
		memcpy(opts[121].s + 1,  &c->ip4.gw, sizeof(c->ip4.gw));
		memcpy(opts[121].s + 10, &c->ip4.gw, sizeof(c->ip4.gw));
	}

	if (c->mtu != -1) {
		opts[26].slen = 2;
		opts[26].s[0] = c->mtu / 256;
		opts[26].s[1] = c->mtu % 256;
	}

	for (i = 0, opts[6].slen = 0;
	     !c->no_dhcp_dns && !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]); i++) {
		((struct in_addr *)opts[6].s)[i] = c->ip4.dns[i];
		opts[6].slen += sizeof(uint32_t);
	}

	if (!c->no_dhcp_dns_search)
		opt_set_dns_search(c, sizeof(m->o));

	len = offsetof(struct msg, o) + fill(m);
	tap_udp4_send(c, c->ip4.gw, 67, c->ip4.addr, 68, m, len);

	return 1;
}
