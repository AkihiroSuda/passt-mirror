// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef UDP_VU_H
#define UDP_VU_H

void udp_vu_listen_sock_handler(const struct ctx *c, union epoll_ref ref,
				uint32_t events, const struct timespec *now);
void udp_vu_reply_sock_handler(const struct ctx *c, union epoll_ref ref,
			       uint32_t events, const struct timespec *now);
#endif /* UDP_VU_H */
