/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_BUF_H
#define TCP_BUF_H

void tcp_sock_iov_init(const struct ctx *c);
void tcp_payload_flush(const struct ctx *c);
int tcp_buf_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn);
int tcp_buf_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags);

#endif  /*TCP_BUF_H */
