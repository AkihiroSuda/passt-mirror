/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_SPLICE_H
#define TCP_SPLICE_H

struct tcp_splice_conn;
union sockaddr_inany;

void tcp_splice_sock_handler(struct ctx *c, union epoll_ref ref,
			     uint32_t events);
bool tcp_splice_conn_from_sock(const struct ctx *c,
			       union tcp_listen_epoll_ref ref, union flow *flow,
			       int s0, const union sockaddr_inany *sa);
void tcp_splice_init(struct ctx *c);

#endif /* TCP_SPLICE_H */
