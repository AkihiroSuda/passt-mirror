// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * pcap.c - Packet capture for PASST/PASTA
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "pcap.h"
#include "iov.h"

#define PCAP_VERSION_MINOR 4

static int pcap_fd = -1;

/* See pcap.h from libpcap, or pcap-savefile(5) */
static const struct {
	uint32_t magic;
#define PCAP_MAGIC		0xa1b2c3d4

	uint16_t major;
#define PCAP_VERSION_MAJOR	2

	uint16_t minor;
#define PCAP_VERSION_MINOR	4

	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;

	uint32_t linktype;
#define PCAP_LINKTYPE_ETHERNET	1
} pcap_hdr = {
	PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, ETH_MAX_MTU,
	PCAP_LINKTYPE_ETHERNET
};

struct pcap_pkthdr {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

/**
 * pcap_frame() - Capture a single frame to pcap file with given timestamp
 * @iov:	IO vector containing frame (with L2 headers and tap headers)
 * @iovcnt:	Number of buffers (@iov entries) in frame
 * @offset:	Byte offset of the L2 headers within @iov
 * @now:	Timestamp
 *
 * Returns: 0 on success, -errno on error writing to the file
 */
static void pcap_frame(const struct iovec *iov, size_t iovcnt,
		       size_t offset, const struct timespec *now)
{
	size_t l2len = iov_size(iov, iovcnt) - offset;
	struct pcap_pkthdr h = {
		.tv_sec = now->tv_sec,
		.tv_usec = DIV_ROUND_CLOSEST(now->tv_nsec, 1000),
		.caplen = l2len,
		.len = l2len
	};
	struct iovec hiov = { &h, sizeof(h) };

	if (write_remainder(pcap_fd, &hiov, 1, 0) < 0 ||
	    write_remainder(pcap_fd, iov, iovcnt, offset) < 0) {
		debug("Cannot log packet, length %zu: %s",
		      l2len, strerror(errno));
	}
}

/**
 * pcap() - Capture a single frame to pcap file
 * @pkt:	Pointer to data buffer, including L2 headers
 * @l2len:	L2 frame length
 */
void pcap(const char *pkt, size_t l2len)
{
	struct iovec iov = { (char *)pkt, l2len };
	struct timespec now;

	if (pcap_fd == -1)
		return;

	clock_gettime(CLOCK_REALTIME, &now);
	pcap_frame(&iov, 1, 0, &now);
}

/**
 * pcap_multiple() - Capture multiple frames
 * @iov:		IO vector with @frame_parts * @n entries
 * @frame_parts:	Number of IO vector items for each frame
 * @n:			Number of frames to capture
 * @offset:		Offset of the L2 frame within each iovec buffer
 */
void pcap_multiple(const struct iovec *iov, size_t frame_parts, unsigned int n,
		   size_t offset)
{
	struct timespec now;
	unsigned int i;

	if (pcap_fd == -1)
		return;

	clock_gettime(CLOCK_REALTIME, &now);

	for (i = 0; i < n; i++)
		pcap_frame(iov + i * frame_parts, frame_parts, offset, &now);
}

/*
 * pcap_iov - Write packet data described by an I/O vector
 *		to a pcap file descriptor.
 *
 * @iov:	Pointer to the array of struct iovec describing the I/O vector
 *		containing packet data to write, including L2 header
 * @iovcnt:	Number of buffers (@iov entries)
 */
/* cppcheck-suppress unusedFunction */
void pcap_iov(const struct iovec *iov, size_t iovcnt)
{
	struct timespec now;

	if (pcap_fd == -1)
		return;

	clock_gettime(CLOCK_REALTIME, &now);
	pcap_frame(iov, iovcnt, 0, &now);
}

/**
 * pcap_init() - Initialise pcap file
 * @c:		Execution context
 */
void pcap_init(struct ctx *c)
{
	int flags = O_WRONLY | O_CREAT | O_TRUNC;

	if (pcap_fd != -1)
		return;

	if (!*c->pcap)
		return;

	flags |= c->foreground ? O_CLOEXEC : 0;
	pcap_fd = open(c->pcap, flags, S_IRUSR | S_IWUSR);
	if (pcap_fd == -1) {
		perror("open");
		return;
	}

	info("Saving packet capture to %s", c->pcap);

	if (write(pcap_fd, &pcap_hdr, sizeof(pcap_hdr)) < 0)
		warn("Cannot write PCAP header: %s", strerror(errno));
}
