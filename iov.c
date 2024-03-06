// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iov.h - helpers for using (partial) iovecs.
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * This file also contains code originally from QEMU include/qemu/iov.h
 * and licensed under the following terms:
 *
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * Author(s):
 *  Amit Shah <amit.shah@redhat.com>
 *  Michael Tokarev <mjt@tls.msk.ru>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */
#include <sys/socket.h>

#include "util.h"
#include "iov.h"


/* iov_skip_bytes() - Skip the first n bytes into an IO vector
 * @iov:	IO vector
 * @n:		Number of entries in @iov
 * @vec_offset: Total byte offset into the IO vector
 * @buf_offset:	Offset into a single buffer of the IO vector
 *
 * Return: index I of individual struct iovec which contains the byte at
 *         @vec_offset bytes into the vector (as though all its buffers were
 *         contiguous).  If @buf_offset is non-NULL, update it to the offset of
 *         that byte within @iov[I] (guaranteed to be less than @iov[I].iov_len)
 *	   If the whole vector has <= @vec_offset bytes, return @n.
 */
size_t iov_skip_bytes(const struct iovec *iov, size_t n,
		      size_t vec_offset, size_t *buf_offset)
{
	size_t offset = vec_offset, i;

	for (i = 0; i < n; i++) {
		if (offset < iov[i].iov_len)
			break;
		offset -= iov[i].iov_len;
	}

	if (buf_offset)
		*buf_offset = offset;

	return i;
}

/**
 * iov_from_buf - Copy data from a buffer to an I/O vector (struct iovec)
 *                efficiently.
 *
 * @iov:       Pointer to the array of struct iovec describing the
 *             scatter/gather I/O vector.
 * @iov_cnt:   Number of elements in the iov array.
 * @offset:    Byte offset in the iov array where copying should start.
 * @buf:       Pointer to the source buffer containing the data to copy.
 * @bytes:     Total number of bytes to copy from buf to iov.
 *
 * Returns:    The number of bytes successfully copied.
 */
/* cppcheck-suppress unusedFunction */
size_t iov_from_buf(const struct iovec *iov, size_t iov_cnt,
		    size_t offset, const void *buf, size_t bytes)
{
	unsigned int i;
	size_t copied;

	if (__builtin_constant_p(bytes) && iov_cnt &&
		offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
		memcpy((char *)iov[0].iov_base + offset, buf, bytes);
		return bytes;
	}

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	/* copying data */
	for (copied = 0; copied < bytes && i < iov_cnt; i++) {
		size_t len = MIN(iov[i].iov_len - offset, bytes - copied);

		memcpy((char *)iov[i].iov_base + offset, (char *)buf + copied,
		       len);
		copied += len;
		offset = 0;
	}

	return copied;
}

/**
 * iov_to_buf - Copy data from a scatter/gather I/O vector (struct iovec) to
 *		a buffer efficiently.
 *
 * @iov:       Pointer to the array of struct iovec describing the scatter/gather
 *             I/O vector.
 * @iov_cnt:   Number of elements in the iov array.
 * @offset:    Offset within the first element of iov from where copying should start.
 * @buf:       Pointer to the destination buffer where data will be copied.
 * @bytes:     Total number of bytes to copy from iov to buf.
 *
 * Returns:    The number of bytes successfully copied.
 */
/* cppcheck-suppress unusedFunction */
size_t iov_to_buf(const struct iovec *iov, size_t iov_cnt,
		  size_t offset, void *buf, size_t bytes)
{
	unsigned int i;
	size_t copied;

	if (__builtin_constant_p(bytes) && iov_cnt &&
		offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
		memcpy(buf, (char *)iov[0].iov_base + offset, bytes);
		return bytes;
	}

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	/* copying data */
	for (copied = 0; copied < bytes && i < iov_cnt; i++) {
		size_t len = MIN(iov[i].iov_len - offset, bytes - copied);
		memcpy((char *)buf + copied, (char *)iov[i].iov_base + offset,
		       len);
		copied += len;
		offset = 0;
	}

	return copied;
}

/**
 * iov_size - Calculate the total size of a scatter/gather I/O vector
 *            (struct iovec).
 *
 * @iov:       Pointer to the array of struct iovec describing the
 *             scatter/gather I/O vector.
 * @iov_cnt:   Number of elements in the iov array.
 *
 * Returns:    The total size in bytes.
 */
size_t iov_size(const struct iovec *iov, size_t iov_cnt)
{
	unsigned int i;
	size_t len;

	for (i = 0, len = 0; i < iov_cnt; i++)
		len += iov[i].iov_len;

	return len;
}

/**
 * iov_copy - Copy data from one scatter/gather I/O vector (struct iovec) to
 *            another.
 *
 * @dst_iov:      Pointer to the destination array of struct iovec describing
 *                the scatter/gather I/O vector to copy to.
 * @dst_iov_cnt:  Number of elements in the destination iov array.
 * @iov:          Pointer to the source array of struct iovec describing
 *                the scatter/gather I/O vector to copy from.
 * @iov_cnt:      Number of elements in the source iov array.
 * @offset:       Offset within the source iov from where copying should start.
 * @bytes:        Total number of bytes to copy from iov to dst_iov.
 *
 * Returns:       The number of elements successfully copied to the destination
 *                iov array.
 */
/* cppcheck-suppress unusedFunction */
unsigned iov_copy(struct iovec *dst_iov, size_t dst_iov_cnt,
		  const struct iovec *iov, size_t iov_cnt,
		  size_t offset, size_t bytes)
{
	unsigned int i, j;

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	/* copying data */
	for (j = 0; i < iov_cnt && j < dst_iov_cnt && bytes; i++) {
		size_t len = MIN(bytes, iov[i].iov_len - offset);

		dst_iov[j].iov_base = (char *)iov[i].iov_base + offset;
		dst_iov[j].iov_len = len;
		j++;
		bytes -= len;
		offset = 0;
	}

	return j;
}
