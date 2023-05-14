/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NETLINK_H
#define NETLINK_H

enum nl_op {
	NL_GET,
	NL_SET,
	NL_DUP,
};

void nl_sock_init(const struct ctx *c, bool ns);
unsigned int nl_get_ext_if(sa_family_t af);
void nl_route(enum nl_op op, unsigned int ifi, unsigned int ifi_ns,
	      sa_family_t af, void *gw);
void nl_addr(enum nl_op op, unsigned int ifi, unsigned int ifi_ns,
	     sa_family_t af, void *addr, int *prefix_len, void *addr_l);
void nl_link(int ns, unsigned int ifi, void *mac, int up, int mtu);

#endif /* NETLINK_H */
