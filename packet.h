/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PACKET_H
#define PACKET_H

/**
 * struct pool - Generic pool of packets stored in a buffer
 * @buf:	Buffer storing packet descriptors,
 * 		a struct vu_dev_region array for passt vhost-user mode
 * @buf_size:	Total size of buffer,
 * 		0 for passt vhost-user mode
 * @size:	Number of usable descriptors for the pool
 * @count:	Number of used descriptors for the pool
 * @pkt:	Descriptors: see macros below
 */
struct pool {
	char *buf;
	size_t buf_size;
	size_t size;
	size_t count;
	struct iovec pkt[1];
};

int vu_packet_check_range(void *buf, size_t offset, size_t len,
			  const char *start);
void packet_add_do(struct pool *p, size_t len, const char *start,
		   const char *func, int line);
void *packet_get_do(const struct pool *p, const size_t idx,
		    size_t offset, size_t len, size_t *left,
		    const char *func, int line);
void pool_flush(struct pool *p);

#define packet_add(p, len, start)					\
	packet_add_do(p, len, start, __func__, __LINE__)

#define packet_get(p, idx, offset, len, left)				\
	packet_get_do(p, idx, offset, len, left, __func__, __LINE__)

#define packet_get_try(p, idx, offset, len, left)			\
	packet_get_do(p, idx, offset, len, left, NULL, 0)

#define PACKET_POOL_DECL(_name, _size, _buf)				\
struct _name ## _t {							\
	char *buf;							\
	size_t buf_size;						\
	size_t size;							\
	size_t count;							\
	struct iovec pkt[_size];					\
}

#define PACKET_POOL_INIT_NOCAST(_size, _buf, _buf_size)			\
{									\
	.buf_size = _buf_size,						\
	.buf = _buf,							\
	.size = _size,							\
}

#define PACKET_POOL(name, size, buf, buf_size)				\
	PACKET_POOL_DECL(name, size, buf) name = 			\
		PACKET_POOL_INIT_NOCAST(size, buf, buf_size)

#define PACKET_INIT(name, size, buf, buf_size)				\
	(struct name ## _t) PACKET_POOL_INIT_NOCAST(size, buf, buf_size)

#define PACKET_POOL_NOINIT(name, size, buf)				\
	PACKET_POOL_DECL(name, size, buf) name ## _storage;		\
	static struct pool *name = (struct pool *)&name ## _storage

#define PACKET_POOL_P(name, size, buf, buf_size)			\
	PACKET_POOL(name ## _storage, size, buf, buf_size);		\
	struct pool *name = (struct pool *)&name ## _storage

#endif /* PACKET_H */
