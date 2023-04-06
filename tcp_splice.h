/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_SPLICE_H
#define TCP_SPLICE_H

struct tcp_splice_conn;

void tcp_splice_sock_handler(struct ctx *c, struct tcp_splice_conn *conn,
			     int s, uint32_t events);
bool tcp_splice_conn_from_sock(struct ctx *c, union epoll_ref ref,
			       struct tcp_splice_conn *conn, int s,
			       const struct sockaddr *sa);
void tcp_splice_init(struct ctx *c);

#endif /* TCP_SPLICE_H */
