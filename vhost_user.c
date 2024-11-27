// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * vhost-user API, command management and virtio interface
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * Some parts from QEMU subprojects/libvhost-user/libvhost-user.c
 * licensed under the following terms:
 *
 * Copyright IBM, Corp. 2007
 * Copyright (c) 2016 Red Hat, Inc.
 *
 * Authors:
 *  Anthony Liguori <aliguori@us.ibm.com>
 *  Marc-André Lureau <mlureau@redhat.com>
 *  Victor Kaplansky <victork@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <linux/vhost_types.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "passt.h"
#include "tap.h"
#include "vhost_user.h"
#include "pcap.h"

/* vhost-user version we are compatible with */
#define VHOST_USER_VERSION 1

static struct vu_dev vdev_storage;

/**
 * vu_print_capabilities() - print vhost-user capabilities
 * 			     this is part of the vhost-user backend
 * 			     convention.
 */
void vu_print_capabilities(void)
{
	info("{");
	info("  \"type\": \"net\"");
	info("}");
	exit(EXIT_SUCCESS);
}

/**
 * vu_request_to_string() - convert a vhost-user request number to its name
 * @req:	request number
 *
 * Return: the name of request number
 */
static const char *vu_request_to_string(unsigned int req)
{
	if (req < VHOST_USER_MAX) {
#define REQ(req) [req] = #req
		static const char * const vu_request_str[VHOST_USER_MAX] = {
			REQ(VHOST_USER_NONE),
			REQ(VHOST_USER_GET_FEATURES),
			REQ(VHOST_USER_SET_FEATURES),
			REQ(VHOST_USER_SET_OWNER),
			REQ(VHOST_USER_RESET_OWNER),
			REQ(VHOST_USER_SET_MEM_TABLE),
			REQ(VHOST_USER_SET_LOG_BASE),
			REQ(VHOST_USER_SET_LOG_FD),
			REQ(VHOST_USER_SET_VRING_NUM),
			REQ(VHOST_USER_SET_VRING_ADDR),
			REQ(VHOST_USER_SET_VRING_BASE),
			REQ(VHOST_USER_GET_VRING_BASE),
			REQ(VHOST_USER_SET_VRING_KICK),
			REQ(VHOST_USER_SET_VRING_CALL),
			REQ(VHOST_USER_SET_VRING_ERR),
			REQ(VHOST_USER_GET_PROTOCOL_FEATURES),
			REQ(VHOST_USER_SET_PROTOCOL_FEATURES),
			REQ(VHOST_USER_GET_QUEUE_NUM),
			REQ(VHOST_USER_SET_VRING_ENABLE),
			REQ(VHOST_USER_SEND_RARP),
			REQ(VHOST_USER_NET_SET_MTU),
			REQ(VHOST_USER_SET_BACKEND_REQ_FD),
			REQ(VHOST_USER_IOTLB_MSG),
			REQ(VHOST_USER_SET_VRING_ENDIAN),
			REQ(VHOST_USER_GET_CONFIG),
			REQ(VHOST_USER_SET_CONFIG),
			REQ(VHOST_USER_POSTCOPY_ADVISE),
			REQ(VHOST_USER_POSTCOPY_LISTEN),
			REQ(VHOST_USER_POSTCOPY_END),
			REQ(VHOST_USER_GET_INFLIGHT_FD),
			REQ(VHOST_USER_SET_INFLIGHT_FD),
			REQ(VHOST_USER_GPU_SET_SOCKET),
			REQ(VHOST_USER_VRING_KICK),
			REQ(VHOST_USER_GET_MAX_MEM_SLOTS),
			REQ(VHOST_USER_ADD_MEM_REG),
			REQ(VHOST_USER_REM_MEM_REG),
		};
#undef REQ
		return vu_request_str[req];
	}

	return "unknown";
}

/**
 * qva_to_va() -  Translate front-end (QEMU) virtual address to our virtual
 * 		  address
 * @dev:		vhost-user device
 * @qemu_addr:		front-end userspace address
 *
 * Return: the memory address in our process virtual address space.
 */
static void *qva_to_va(struct vu_dev *dev, uint64_t qemu_addr)
{
	unsigned int i;

	/* Find matching memory region.  */
	for (i = 0; i < dev->nregions; i++) {
		const struct vu_dev_region *r = &dev->regions[i];

		if ((qemu_addr >= r->qva) && (qemu_addr < (r->qva + r->size))) {
			/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
			return (void *)(uintptr_t)(qemu_addr - r->qva +
						   r->mmap_addr +
						   r->mmap_offset);
		}
	}

	return NULL;
}

/**
 * vmsg_close_fds() - Close all file descriptors of a given message
 * @vmsg:	vhost-user message with the list of the file descriptors
 */
static void vmsg_close_fds(const struct vhost_user_msg *vmsg)
{
	int i;

	for (i = 0; i < vmsg->fd_num; i++)
		close(vmsg->fds[i]);
}

/**
 * vu_remove_watch() - Remove a file descriptor from our passt epoll
 * 		       file descriptor
 * @vdev:	vhost-user device
 * @fd:		file descriptor to remove
 */
static void vu_remove_watch(const struct vu_dev *vdev, int fd)
{
	epoll_ctl(vdev->context->epollfd, EPOLL_CTL_DEL, fd, NULL);
}

/**
 * vmsg_set_reply_u64() - Set reply payload.u64 and clear request flags
 * 			  and fd_num
 * @vmsg:	vhost-user message
 * @val:	64-bit value to reply
 */
static void vmsg_set_reply_u64(struct vhost_user_msg *vmsg, uint64_t val)
{
	vmsg->hdr.flags = 0; /* defaults will be set by vu_send_reply() */
	vmsg->hdr.size = sizeof(vmsg->payload.u64);
	vmsg->payload.u64 = val;
	vmsg->fd_num = 0;
}

/**
 * vu_message_read_default() - Read incoming vhost-user message from the
 * 			       front-end
 * @conn_fd:	vhost-user command socket
 * @vmsg:	vhost-user message
 *
 * Return:  0 if recvmsg() has been interrupted or if there's no data to read,
 *          1 if a message has been received
 */
static int vu_message_read_default(int conn_fd, struct vhost_user_msg *vmsg)
{
	char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS *
		     sizeof(int))] = { 0 };
	struct iovec iov = {
		.iov_base = (char *)vmsg,
		.iov_len = VHOST_USER_HDR_SIZE,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	ssize_t ret, sz_payload;
	struct cmsghdr *cmsg;

	ret = recvmsg(conn_fd, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		die_perror("vhost-user message receive (recvmsg)");
	}

	vmsg->fd_num = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			size_t fd_size;

			ASSERT(cmsg->cmsg_len >= CMSG_LEN(0));
			fd_size = cmsg->cmsg_len - CMSG_LEN(0);
			ASSERT(fd_size <= sizeof(vmsg->fds));
			vmsg->fd_num = fd_size / sizeof(int);
			memcpy(vmsg->fds, CMSG_DATA(cmsg), fd_size);
			break;
		}
	}

	sz_payload = vmsg->hdr.size;
	if ((size_t)sz_payload > sizeof(vmsg->payload)) {
		die("vhost-user message request too big: %d,"
			 " size: vmsg->size: %zd, "
			 "while sizeof(vmsg->payload) = %zu",
			 vmsg->hdr.request, sz_payload, sizeof(vmsg->payload));
	}

	if (sz_payload) {
		do
			ret = recv(conn_fd, &vmsg->payload, sz_payload, 0);
		while (ret < 0 && errno == EINTR);

		if (ret < 0)
			die_perror("vhost-user message receive");

		if (ret == 0)
			die("EOF on vhost-user message receive");

		if (ret < sz_payload)
			die("Short-read on vhost-user message receive");
	}

	return 1;
}

/**
 * vu_message_write() - Send a message to the front-end
 * @conn_fd:	vhost-user command socket
 * @vmsg:	vhost-user message
 *
 * #syscalls:vu sendmsg
 */
static void vu_message_write(int conn_fd, struct vhost_user_msg *vmsg)
{
	char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))] = { 0 };
	struct iovec iov = {
		.iov_base = (char *)vmsg,
		.iov_len = VHOST_USER_HDR_SIZE + vmsg->hdr.size,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
	};
	int rc;

	ASSERT(vmsg->fd_num <= VHOST_MEMORY_BASELINE_NREGIONS);
	if (vmsg->fd_num > 0) {
		size_t fdsize = vmsg->fd_num * sizeof(int);
		struct cmsghdr *cmsg;

		msg.msg_controllen = CMSG_SPACE(fdsize);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(fdsize);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), vmsg->fds, fdsize);
	}

	do
		rc = sendmsg(conn_fd, &msg, 0);
	while (rc < 0 && errno == EINTR);

	if (rc < 0)
		die_perror("vhost-user message send");

	if ((uint32_t)rc < VHOST_USER_HDR_SIZE + vmsg->hdr.size)
		die("EOF on vhost-user message send");
}

/**
 * vu_send_reply() - Update message flags and send it to front-end
 * @conn_fd:	vhost-user command socket
 * @vmsg:	vhost-user message
 */
static void vu_send_reply(int conn_fd, struct vhost_user_msg *msg)
{
	msg->hdr.flags &= ~VHOST_USER_VERSION_MASK;
	msg->hdr.flags |= VHOST_USER_VERSION;
	msg->hdr.flags |= VHOST_USER_REPLY_MASK;

	vu_message_write(conn_fd, msg);
}

/**
 * vu_get_features_exec() - Provide back-end features bitmask to front-end
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: True as a reply is requested
 */
static bool vu_get_features_exec(struct vu_dev *vdev,
				 struct vhost_user_msg *msg)
{
	uint64_t features =
		1ULL << VIRTIO_F_VERSION_1 |
		1ULL << VIRTIO_NET_F_MRG_RXBUF |
		1ULL << VHOST_USER_F_PROTOCOL_FEATURES;

	(void)vdev;

	vmsg_set_reply_u64(msg, features);

	debug("Sending back to guest u64: 0x%016"PRIx64, msg->payload.u64);

	return true;
}

/**
 * vu_set_enable_all_rings() - Enable/disable all the virtqueues
 * @vdev:	vhost-user device
 * @enable:	New virtqueues state
 */
static void vu_set_enable_all_rings(struct vu_dev *vdev, bool enable)
{
	uint16_t i;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++)
		vdev->vq[i].enable = enable;
}

/**
 * vu_set_features_exec() - Enable features of the back-end
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_features_exec(struct vu_dev *vdev,
				 struct vhost_user_msg *msg)
{
	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	vdev->features = msg->payload.u64;
	/* We only support devices conforming to VIRTIO 1.0 or
	 * later
	 */
	if (!vu_has_feature(vdev, VIRTIO_F_VERSION_1))
		die("virtio legacy devices aren't supported by passt");

	if (!vu_has_feature(vdev, VHOST_USER_F_PROTOCOL_FEATURES))
		vu_set_enable_all_rings(vdev, true);

	return false;
}

/**
 * vu_set_owner_exec() - Session start flag, do nothing in our case
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_owner_exec(struct vu_dev *vdev,
			      struct vhost_user_msg *msg)
{
	(void)vdev;
	(void)msg;

	return false;
}

/**
 * map_ring() - Convert ring front-end (QEMU) addresses to our process
 * 		virtual address space.
 * @vdev:	vhost-user device
 * @vq:		Virtqueue
 *
 * Return: True if ring cannot be mapped to our address space
 */
static bool map_ring(struct vu_dev *vdev, struct vu_virtq *vq)
{
	vq->vring.desc = qva_to_va(vdev, vq->vra.desc_user_addr);
	vq->vring.used = qva_to_va(vdev, vq->vra.used_user_addr);
	vq->vring.avail = qva_to_va(vdev, vq->vra.avail_user_addr);

	debug("Setting virtq addresses:");
	debug("    vring_desc  at %p", (void *)vq->vring.desc);
	debug("    vring_used  at %p", (void *)vq->vring.used);
	debug("    vring_avail at %p", (void *)vq->vring.avail);

	return !(vq->vring.desc && vq->vring.used && vq->vring.avail);
}

/**
 * vu_set_mem_table_exec() - Sets the memory map regions to be able to
 * 			     translate the vring addresses.
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 *
 * #syscalls:vu mmap munmap
 */
static bool vu_set_mem_table_exec(struct vu_dev *vdev,
				  struct vhost_user_msg *msg)
{
	struct vhost_user_memory m = msg->payload.memory, *memory = &m;
	unsigned int i;

	for (i = 0; i < vdev->nregions; i++) {
		const struct vu_dev_region *r = &vdev->regions[i];

		if (r->mmap_addr) {
			/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
			munmap((void *)(uintptr_t)r->mmap_addr,
			       r->size + r->mmap_offset);
		}
	}
	vdev->nregions = memory->nregions;

	debug("vhost-user nregions: %u", memory->nregions);
	for (i = 0; i < vdev->nregions; i++) {
		struct vhost_user_memory_region *msg_region = &memory->regions[i];
		struct vu_dev_region *dev_region = &vdev->regions[i];
		void *mmap_addr;

		debug("vhost-user region %d", i);
		debug("    guest_phys_addr: 0x%016"PRIx64,
		      msg_region->guest_phys_addr);
		debug("    memory_size:     0x%016"PRIx64,
		      msg_region->memory_size);
		debug("    userspace_addr   0x%016"PRIx64,
		      msg_region->userspace_addr);
		debug("    mmap_offset      0x%016"PRIx64,
		      msg_region->mmap_offset);

		dev_region->gpa = msg_region->guest_phys_addr;
		dev_region->size = msg_region->memory_size;
		dev_region->qva = msg_region->userspace_addr;
		dev_region->mmap_offset = msg_region->mmap_offset;

		/* We don't use offset argument of mmap() since the
		 * mapped address has to be page aligned.
		 */
		mmap_addr = mmap(0, dev_region->size + dev_region->mmap_offset,
				 PROT_READ | PROT_WRITE, MAP_SHARED |
				 MAP_NORESERVE, msg->fds[i], 0);

		if (mmap_addr == MAP_FAILED)
			die_perror("vhost-user region mmap error");

		dev_region->mmap_addr = (uint64_t)(uintptr_t)mmap_addr;
		debug("    mmap_addr:       0x%016"PRIx64,
		      dev_region->mmap_addr);

		close(msg->fds[i]);
	}

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		if (vdev->vq[i].vring.desc) {
			if (map_ring(vdev, &vdev->vq[i]))
				die("remapping queue %d during setmemtable", i);
		}
	}

	/* As vu_packet_check_range() has no access to the number of
	 * memory regions, mark the end of the array with mmap_addr = 0
	 */
	ASSERT(vdev->nregions < VHOST_USER_MAX_RAM_SLOTS - 1);
	vdev->regions[vdev->nregions].mmap_addr = 0;

	tap_sock_update_pool(vdev->regions, 0);

	return false;
}

/**
 * vu_set_vring_num_exec() - Set the size of the queue (vring size)
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_num_exec(struct vu_dev *vdev,
				  struct vhost_user_msg *msg)
{
	unsigned int idx = msg->payload.state.index;
	unsigned int num = msg->payload.state.num;

	debug("State.index: %u", idx);
	debug("State.num:   %u", num);
	vdev->vq[idx].vring.num = num;

	return false;
}

/**
 * vu_set_vring_addr_exec() - Set the addresses of the vring
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_addr_exec(struct vu_dev *vdev,
				   struct vhost_user_msg *msg)
{
	/* We need to copy the payload to vhost_vring_addr structure
         * to access index because address of msg->payload.addr
         * can be unaligned as it is packed.
         */
	struct vhost_vring_addr addr = msg->payload.addr;
	struct vu_virtq *vq = &vdev->vq[addr.index];

	debug("vhost_vring_addr:");
	debug("    index:  %d", addr.index);
	debug("    flags:  %d", addr.flags);
	debug("    desc_user_addr:   0x%016" PRIx64,
	      (uint64_t)addr.desc_user_addr);
	debug("    used_user_addr:   0x%016" PRIx64,
	      (uint64_t)addr.used_user_addr);
	debug("    avail_user_addr:  0x%016" PRIx64,
	      (uint64_t)addr.avail_user_addr);
	debug("    log_guest_addr:   0x%016" PRIx64,
	      (uint64_t)addr.log_guest_addr);

	vq->vra = msg->payload.addr;
	vq->vring.flags = addr.flags;
	vq->vring.log_guest_addr = addr.log_guest_addr;

	if (map_ring(vdev, vq))
		die("Invalid vring_addr message");

	vq->used_idx = le16toh(vq->vring.used->idx);

	if (vq->last_avail_idx != vq->used_idx) {
		debug("Last avail index != used index: %u != %u",
		      vq->last_avail_idx, vq->used_idx);
	}

	return false;
}
/**
 * vu_set_vring_base_exec() - Sets the next index to use for descriptors
 * 			      in this vring
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_base_exec(struct vu_dev *vdev,
				   struct vhost_user_msg *msg)
{
	unsigned int idx = msg->payload.state.index;
	unsigned int num = msg->payload.state.num;

	debug("State.index: %u", idx);
	debug("State.num:   %u", num);
	vdev->vq[idx].shadow_avail_idx = vdev->vq[idx].last_avail_idx = num;

	return false;
}

/**
 * vu_get_vring_base_exec() - Stops the vring and returns the current
 * 			      descriptor index or indices
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: True as a reply is requested
 */
static bool vu_get_vring_base_exec(struct vu_dev *vdev,
				   struct vhost_user_msg *msg)
{
	unsigned int idx = msg->payload.state.index;

	debug("State.index: %u", idx);
	msg->payload.state.num = vdev->vq[idx].last_avail_idx;
	msg->hdr.size = sizeof(msg->payload.state);

	vdev->vq[idx].started = false;

	if (vdev->vq[idx].call_fd != -1) {
		close(vdev->vq[idx].call_fd);
		vdev->vq[idx].call_fd = -1;
	}
	if (vdev->vq[idx].kick_fd != -1) {
		vu_remove_watch(vdev, vdev->vq[idx].kick_fd);
		close(vdev->vq[idx].kick_fd);
		vdev->vq[idx].kick_fd = -1;
	}

	return true;
}

/**
 * vu_set_watch() - Add a file descriptor to the passt epoll file descriptor
 * @vdev:	vhost-user device
 * @idx:	queue index of the file descriptor to add
 */
static void vu_set_watch(const struct vu_dev *vdev, int idx)
{
	union epoll_ref ref = {
		.type = EPOLL_TYPE_VHOST_KICK,
		.fd = vdev->vq[idx].kick_fd,
		.queue = idx
	 };
	struct epoll_event ev = { 0 };

	ev.data.u64 = ref.u64;
	ev.events = EPOLLIN;
	epoll_ctl(vdev->context->epollfd, EPOLL_CTL_ADD, ref.fd, &ev);
}

/**
 * vu_check_queue_msg_file() - Check if a message is valid,
 * 			       close fds if NOFD bit is set
 * @vmsg:	vhost-user message
 */
static void vu_check_queue_msg_file(struct vhost_user_msg *msg)
{
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;
	int idx = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;

	if (idx >= VHOST_USER_MAX_QUEUES)
		die("Invalid vhost-user queue index: %u", idx);

	if (nofd) {
		vmsg_close_fds(msg);
		return;
	}

	if (msg->fd_num != 1)
		die("Invalid fds in vhost-user request: %d", msg->hdr.request);
}

/**
 * vu_set_vring_kick_exec() - Set the event file descriptor for adding buffers
 * 			      to the vring
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_kick_exec(struct vu_dev *vdev,
				   struct vhost_user_msg *msg)
{
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;
	int idx = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	vu_check_queue_msg_file(msg);

	if (vdev->vq[idx].kick_fd != -1) {
		vu_remove_watch(vdev, vdev->vq[idx].kick_fd);
		close(vdev->vq[idx].kick_fd);
		vdev->vq[idx].kick_fd = -1;
	}

	if (!nofd)
		vdev->vq[idx].kick_fd = msg->fds[0];

	debug("Got kick_fd: %d for vq: %d", vdev->vq[idx].kick_fd, idx);

	vdev->vq[idx].started = true;

	if (vdev->vq[idx].kick_fd != -1 && VHOST_USER_IS_QUEUE_TX(idx)) {
		vu_set_watch(vdev, idx);
		debug("Waiting for kicks on fd: %d for vq: %d",
		      vdev->vq[idx].kick_fd, idx);
	}

	return false;
}

/**
 * vu_set_vring_call_exec() - Set the event file descriptor to signal when
 * 			      buffers are used
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_call_exec(struct vu_dev *vdev,
				   struct vhost_user_msg *msg)
{
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;
	int idx = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	vu_check_queue_msg_file(msg);

	if (vdev->vq[idx].call_fd != -1) {
		close(vdev->vq[idx].call_fd);
		vdev->vq[idx].call_fd = -1;
	}

	if (!nofd)
		vdev->vq[idx].call_fd = msg->fds[0];

	/* in case of I/O hang after reconnecting */
	if (vdev->vq[idx].call_fd != -1)
		eventfd_write(msg->fds[0], 1);

	debug("Got call_fd: %d for vq: %d", vdev->vq[idx].call_fd, idx);

	return false;
}

/**
 * vu_set_vring_err_exec() - Set the event file descriptor to signal when
 * 			     error occurs
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_err_exec(struct vu_dev *vdev,
				  struct vhost_user_msg *msg)
{
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;
	int idx = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	vu_check_queue_msg_file(msg);

	if (vdev->vq[idx].err_fd != -1) {
		close(vdev->vq[idx].err_fd);
		vdev->vq[idx].err_fd = -1;
	}

	if (!nofd)
		vdev->vq[idx].err_fd = msg->fds[0];

	return false;
}

/**
 * vu_get_protocol_features_exec() - Provide the protocol (vhost-user) features
 * 				     to the front-end
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: True as a reply is requested
 */
static bool vu_get_protocol_features_exec(struct vu_dev *vdev,
					  struct vhost_user_msg *msg)
{
	uint64_t features = 1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK;

	(void)vdev;
	vmsg_set_reply_u64(msg, features);

	return true;
}

/**
 * vu_set_protocol_features_exec() - Enable protocol (vhost-user) features
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_protocol_features_exec(struct vu_dev *vdev,
					  struct vhost_user_msg *msg)
{
	uint64_t features = msg->payload.u64;

	debug("u64: 0x%016"PRIx64, features);

	vdev->protocol_features = msg->payload.u64;

	return false;
}

/**
 * vu_get_queue_num_exec() - Tell how many queues we support
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: True as a reply is requested
 */
static bool vu_get_queue_num_exec(struct vu_dev *vdev,
				  struct vhost_user_msg *msg)
{
	(void)vdev;

	vmsg_set_reply_u64(msg, VHOST_USER_MAX_QUEUES);

	return true;
}

/**
 * vu_set_vring_enable_exec() - Enable or disable corresponding vring
 * @vdev:	vhost-user device
 * @vmsg:	vhost-user message
 *
 * Return: False as no reply is requested
 */
static bool vu_set_vring_enable_exec(struct vu_dev *vdev,
				     struct vhost_user_msg *msg)
{
	unsigned int enable = msg->payload.state.num;
	unsigned int idx = msg->payload.state.index;

	debug("State.index:  %u", idx);
	debug("State.enable: %u", enable);

	if (idx >= VHOST_USER_MAX_QUEUES)
		die("Invalid vring_enable index: %u", idx);

	vdev->vq[idx].enable = enable;
	return false;
}

/**
 * vu_init() - Initialize vhost-user device structure
 * @c:		execution context
 * @vdev:	vhost-user device
 */
void vu_init(struct ctx *c)
{
	int i;

	c->vdev = &vdev_storage;
	c->vdev->context = c;
	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		c->vdev->vq[i] = (struct vu_virtq){
			.call_fd = -1,
			.kick_fd = -1,
			.err_fd = -1,
			.notification = true,
		};
	}
}

/**
 * vu_cleanup() - Reset vhost-user device
 * @vdev:	vhost-user device
 */
void vu_cleanup(struct vu_dev *vdev)
{
	unsigned int i;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		struct vu_virtq *vq = &vdev->vq[i];

		vq->started = false;
		vq->notification = true;

		if (vq->call_fd != -1) {
			close(vq->call_fd);
			vq->call_fd = -1;
		}
		if (vq->err_fd != -1) {
			close(vq->err_fd);
			vq->err_fd = -1;
		}
		if (vq->kick_fd != -1) {
			vu_remove_watch(vdev, vq->kick_fd);
			close(vq->kick_fd);
			vq->kick_fd = -1;
		}

		vq->vring.desc = 0;
		vq->vring.used = 0;
		vq->vring.avail = 0;
	}

	for (i = 0; i < vdev->nregions; i++) {
		const struct vu_dev_region *r = &vdev->regions[i];

		if (r->mmap_addr) {
			/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
			munmap((void *)(uintptr_t)r->mmap_addr,
			       r->size + r->mmap_offset);
		}
	}
	vdev->nregions = 0;
}

/**
 * vu_sock_reset() - Reset connection socket
 * @vdev:	vhost-user device
 */
static void vu_sock_reset(struct vu_dev *vdev)
{
	tap_sock_reset(vdev->context);
}

static bool (*vu_handle[VHOST_USER_MAX])(struct vu_dev *vdev,
					struct vhost_user_msg *msg) = {
	[VHOST_USER_GET_FEATURES]	   = vu_get_features_exec,
	[VHOST_USER_SET_FEATURES]	   = vu_set_features_exec,
	[VHOST_USER_GET_PROTOCOL_FEATURES] = vu_get_protocol_features_exec,
	[VHOST_USER_SET_PROTOCOL_FEATURES] = vu_set_protocol_features_exec,
	[VHOST_USER_GET_QUEUE_NUM]	   = vu_get_queue_num_exec,
	[VHOST_USER_SET_OWNER]		   = vu_set_owner_exec,
	[VHOST_USER_SET_MEM_TABLE]	   = vu_set_mem_table_exec,
	[VHOST_USER_SET_VRING_NUM]	   = vu_set_vring_num_exec,
	[VHOST_USER_SET_VRING_ADDR]	   = vu_set_vring_addr_exec,
	[VHOST_USER_SET_VRING_BASE]	   = vu_set_vring_base_exec,
	[VHOST_USER_GET_VRING_BASE]	   = vu_get_vring_base_exec,
	[VHOST_USER_SET_VRING_KICK]	   = vu_set_vring_kick_exec,
	[VHOST_USER_SET_VRING_CALL]	   = vu_set_vring_call_exec,
	[VHOST_USER_SET_VRING_ERR]	   = vu_set_vring_err_exec,
	[VHOST_USER_SET_VRING_ENABLE]	   = vu_set_vring_enable_exec,
};

/**
 * vu_control_handler() - Handle control commands for vhost-user
 * @vdev:	vhost-user device
 * @fd:		vhost-user message socket
 * @events:	epoll events
 */
void vu_control_handler(struct vu_dev *vdev, int fd, uint32_t events)
{
	struct vhost_user_msg msg = { 0 };
	bool need_reply, reply_requested;
	int ret;

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
		vu_sock_reset(vdev);
		return;
	}

	ret = vu_message_read_default(fd, &msg);
	if (ret == 0) {
		vu_sock_reset(vdev);
		return;
	}
	debug("================ Vhost user message ================");
	debug("Request: %s (%d)", vu_request_to_string(msg.hdr.request),
		msg.hdr.request);
	debug("Flags:   0x%x", msg.hdr.flags);
	debug("Size:    %u", msg.hdr.size);

	need_reply = msg.hdr.flags & VHOST_USER_NEED_REPLY_MASK;

	if (msg.hdr.request >= 0 && msg.hdr.request < VHOST_USER_MAX &&
	    vu_handle[msg.hdr.request])
		reply_requested = vu_handle[msg.hdr.request](vdev, &msg);
	else
		die("Unhandled request: %d", msg.hdr.request);

	/* cppcheck-suppress legacyUninitvar */
	if (!reply_requested && need_reply) {
		msg.payload.u64 = 0;
		msg.hdr.flags = 0;
		msg.hdr.size = sizeof(msg.payload.u64);
		msg.fd_num = 0;
		reply_requested = true;
	}

	if (reply_requested)
		vu_send_reply(fd, &msg);
}
