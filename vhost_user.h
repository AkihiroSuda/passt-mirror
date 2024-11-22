// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * vhost-user API, command management and virtio interface
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

/* some parts from subprojects/libvhost-user/libvhost-user.h */

#ifndef VHOST_USER_H
#define VHOST_USER_H

#include "virtio.h"
#include "iov.h"

#define VHOST_USER_F_PROTOCOL_FEATURES 30

#define VHOST_MEMORY_BASELINE_NREGIONS 8

/**
 * enum vhost_user_protocol_feature - List of available vhost-user features
 */
enum vhost_user_protocol_feature {
	VHOST_USER_PROTOCOL_F_MQ = 0,
	VHOST_USER_PROTOCOL_F_LOG_SHMFD = 1,
	VHOST_USER_PROTOCOL_F_RARP = 2,
	VHOST_USER_PROTOCOL_F_REPLY_ACK = 3,
	VHOST_USER_PROTOCOL_F_NET_MTU = 4,
	VHOST_USER_PROTOCOL_F_BACKEND_REQ = 5,
	VHOST_USER_PROTOCOL_F_CROSS_ENDIAN = 6,
	VHOST_USER_PROTOCOL_F_CRYPTO_SESSION = 7,
	VHOST_USER_PROTOCOL_F_PAGEFAULT = 8,
	VHOST_USER_PROTOCOL_F_CONFIG = 9,
	VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD = 10,
	VHOST_USER_PROTOCOL_F_HOST_NOTIFIER = 11,
	VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD = 12,
	VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS = 14,
	VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS = 15,

	VHOST_USER_PROTOCOL_F_MAX
};

/**
 * enum vhost_user_request - List of available vhost-user requests
 */
enum vhost_user_request {
	VHOST_USER_NONE = 0,
	VHOST_USER_GET_FEATURES = 1,
	VHOST_USER_SET_FEATURES = 2,
	VHOST_USER_SET_OWNER = 3,
	VHOST_USER_RESET_OWNER = 4,
	VHOST_USER_SET_MEM_TABLE = 5,
	VHOST_USER_SET_LOG_BASE = 6,
	VHOST_USER_SET_LOG_FD = 7,
	VHOST_USER_SET_VRING_NUM = 8,
	VHOST_USER_SET_VRING_ADDR = 9,
	VHOST_USER_SET_VRING_BASE = 10,
	VHOST_USER_GET_VRING_BASE = 11,
	VHOST_USER_SET_VRING_KICK = 12,
	VHOST_USER_SET_VRING_CALL = 13,
	VHOST_USER_SET_VRING_ERR = 14,
	VHOST_USER_GET_PROTOCOL_FEATURES = 15,
	VHOST_USER_SET_PROTOCOL_FEATURES = 16,
	VHOST_USER_GET_QUEUE_NUM = 17,
	VHOST_USER_SET_VRING_ENABLE = 18,
	VHOST_USER_SEND_RARP = 19,
	VHOST_USER_NET_SET_MTU = 20,
	VHOST_USER_SET_BACKEND_REQ_FD = 21,
	VHOST_USER_IOTLB_MSG = 22,
	VHOST_USER_SET_VRING_ENDIAN = 23,
	VHOST_USER_GET_CONFIG = 24,
	VHOST_USER_SET_CONFIG = 25,
	VHOST_USER_CREATE_CRYPTO_SESSION = 26,
	VHOST_USER_CLOSE_CRYPTO_SESSION = 27,
	VHOST_USER_POSTCOPY_ADVISE  = 28,
	VHOST_USER_POSTCOPY_LISTEN  = 29,
	VHOST_USER_POSTCOPY_END     = 30,
	VHOST_USER_GET_INFLIGHT_FD = 31,
	VHOST_USER_SET_INFLIGHT_FD = 32,
	VHOST_USER_GPU_SET_SOCKET = 33,
	VHOST_USER_VRING_KICK = 35,
	VHOST_USER_GET_MAX_MEM_SLOTS = 36,
	VHOST_USER_ADD_MEM_REG = 37,
	VHOST_USER_REM_MEM_REG = 38,
	VHOST_USER_MAX
};

/**
 * struct vhost_user_header - vhost-user message header
 * @request:	Request type of the message
 * @flags:	Request flags
 * @size:	The following payload size
 */
struct vhost_user_header {
	enum vhost_user_request request;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
#define VHOST_USER_NEED_REPLY_MASK  (0x1 << 3)
	uint32_t flags;
	uint32_t size;
} __attribute__ ((__packed__));

/**
 * struct vhost_user_memory_region - Front-end shared memory region information
 * @guest_phys_addr:	Guest physical address of the region
 * @memory_size:	Memory size
 * @userspace_addr:	front-end (QEMU) userspace address
 * @mmap_offset:	region offset in the shared memory area
 */
struct vhost_user_memory_region {
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;
	uint64_t mmap_offset;
};

/**
 * struct vhost_user_memory - List of all the shared memory regions
 * @nregions:	Number of memory regions
 * @padding:	Padding
 * @regions:	Memory regions list
 */
struct vhost_user_memory {
	uint32_t nregions;
	uint32_t padding;
	struct vhost_user_memory_region regions[VHOST_MEMORY_BASELINE_NREGIONS];
};

/**
 * union vhost_user_payload - vhost-user message payload
 * @u64:		64-bit payload
 * @state:		vring state payload
 * @addr:		vring addresses payload
 * vhost_user_memory:	Memory regions information payload
 */
union vhost_user_payload {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
	uint64_t u64;
	struct vhost_vring_state state;
	struct vhost_vring_addr addr;
	struct vhost_user_memory memory;
};

/**
 * struct vhost_user_msg - vhost-use message
 * @hdr:		Message header
 * @payload:		Message payload
 * @fds:		File descriptors associated with the message
 * 			in the ancillary data.
 * 			(shared memory or event file descriptors)
 * @fd_num:		Number of file descriptors
 */
struct vhost_user_msg {
	struct vhost_user_header hdr;
	union vhost_user_payload payload;

	int fds[VHOST_MEMORY_BASELINE_NREGIONS];
	int fd_num;
} __attribute__ ((__packed__));
#define VHOST_USER_HDR_SIZE sizeof(struct vhost_user_header)

/* index of the RX virtqueue */
#define VHOST_USER_RX_QUEUE 0
/* index of the TX virtqueue */
#define VHOST_USER_TX_QUEUE 1

/* in case of multiqueue, the RX and TX queues are interleaved */
#define VHOST_USER_IS_QUEUE_TX(n)	(n % 2)
#define VHOST_USER_IS_QUEUE_RX(n)	(!(n % 2))

/* Default virtio-net header for passt */
#define VU_HEADER ((struct virtio_net_hdr){	\
	.flags = VIRTIO_NET_HDR_F_DATA_VALID,	\
	.gso_type = VIRTIO_NET_HDR_GSO_NONE,	\
})

/**
 * vu_queue_enabled - Return state of a virtqueue
 * @vq:		virtqueue to check
 *
 * Return: true if the virqueue is enabled, false otherwise
 */
/* cppcheck-suppress unusedFunction */
static inline bool vu_queue_enabled(const struct vu_virtq *vq)
{
	return vq->enable;
}

/**
 * vu_queue_started - Return state of a virtqueue
 * @vq:		virtqueue to check
 *
 * Return: true if the virqueue is started, false otherwise
 */
/* cppcheck-suppress unusedFunction */
static inline bool vu_queue_started(const struct vu_virtq *vq)
{
	return vq->started;
}

void vu_print_capabilities(void);
void vu_init(struct ctx *c, struct vu_dev *vdev);
void vu_cleanup(struct vu_dev *vdev);
void vu_control_handler(struct vu_dev *vdev, int fd, uint32_t events);
#endif /* VHOST_USER_H */
