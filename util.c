// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * util.c - Convenience helpers
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <linux/errqueue.h>
#include <getopt.h>

#include "linux_dep.h"
#include "util.h"
#include "iov.h"
#include "passt.h"
#include "packet.h"
#include "log.h"
#ifdef HAS_GETRANDOM
#include <sys/random.h>
#endif

/**
 * sock_l4_sa() - Create and bind socket to socket address, add to epoll list
 * @c:		Execution context
 * @type:	epoll type
 * @sa:		Socket address to bind to
 * @sl:		Length of @sa
 * @ifname:	Interface for binding, NULL for any
 * @v6only:	Set IPV6_V6ONLY socket option
 * @data:	epoll reference portion for protocol handlers
 *
 * Return: newly created socket, negative error code on failure
 */
int sock_l4_sa(const struct ctx *c, enum epoll_type type,
	       const void *sa, socklen_t sl,
	       const char *ifname, bool v6only, uint32_t data)
{
	sa_family_t af = ((const struct sockaddr *)sa)->sa_family;
	union epoll_ref ref = { .type = type, .data = data };
	bool freebind = false;
	struct epoll_event ev;
	int fd, y = 1, ret;
	uint8_t proto;
	int socktype;

	switch (type) {
	case EPOLL_TYPE_TCP_LISTEN:
		proto = IPPROTO_TCP;
		socktype = SOCK_STREAM | SOCK_NONBLOCK;
		freebind = c->freebind;
		break;
	case EPOLL_TYPE_UDP_LISTEN:
		freebind = c->freebind;
		/* fallthrough */
	case EPOLL_TYPE_UDP_REPLY:
		proto = IPPROTO_UDP;
		socktype = SOCK_DGRAM | SOCK_NONBLOCK;
		break;
	case EPOLL_TYPE_PING:
		if (af == AF_INET)
			proto = IPPROTO_ICMP;
		else
			proto = IPPROTO_ICMPV6;
		socktype = SOCK_DGRAM | SOCK_NONBLOCK;
		break;
	default:
		ASSERT(0);
	}

	fd = socket(af, socktype, proto);

	ret = -errno;
	if (fd < 0) {
		warn("L4 socket: %s", strerror(-ret));
		return ret;
	}

	if (fd > FD_REF_MAX) {
		close(fd);
		return -EBADF;
	}

	ref.fd = fd;

	if (v6only)
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &y, sizeof(y)))
			debug("Failed to set IPV6_V6ONLY on socket %i", fd);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)))
		debug("Failed to set SO_REUSEADDR on socket %i", fd);

	if (proto == IPPROTO_UDP) {
		int level = af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
		int opt = af == AF_INET ? IP_RECVERR : IPV6_RECVERR;

		if (setsockopt(fd, level, opt, &y, sizeof(y)))
			die_perror("Failed to set RECVERR on socket %i", fd);
	}

	if (ifname && *ifname) {
		/* Supported since kernel version 5.7, commit c427bfec18f2
		 * ("net: core: enable SO_BINDTODEVICE for non-root users"). If
		 * it's unsupported, don't bind the socket at all, because the
		 * user might rely on this to filter incoming connections.
		 */
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       ifname, strlen(ifname))) {
			char str[SOCKADDR_STRLEN];

			ret = -errno;
			warn("Can't bind %s socket for %s to %s, closing",
			     EPOLL_TYPE_STR(proto),
			     sockaddr_ntop(sa, str, sizeof(str)), ifname);
			close(fd);
			return ret;
		}
	}

	if (freebind) {
		int level = af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
		int opt = af == AF_INET ? IP_FREEBIND : IPV6_FREEBIND;

		if (setsockopt(fd, level, opt, &y, sizeof(y))) {
			err_perror("Failed to set %s on socket %i",
				   af == AF_INET ? "IP_FREEBIND"
				                 : "IPV6_FREEBIND",
				   fd);
		}
	}

	if (bind(fd, sa, sl) < 0) {
		/* We'll fail to bind to low ports if we don't have enough
		 * capabilities, and we'll fail to bind on already bound ports,
		 * this is fine. This might also fail for ICMP because of a
		 * broken SELinux policy, see icmp_tap_handler().
		 */
		if (type != EPOLL_TYPE_PING) {
			ret = -errno;
			close(fd);
			return ret;
		}
	}

	if (type == EPOLL_TYPE_TCP_LISTEN && listen(fd, 128) < 0) {
		ret = -errno;
		warn("TCP socket listen: %s", strerror(-ret));
		close(fd);
		return ret;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = ref.u64;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		ret = -errno;
		warn("L4 epoll_ctl: %s", strerror(-ret));
		return ret;
	}

	return fd;
}

/**
 * sock_probe_mem() - Check if setting high SO_SNDBUF and SO_RCVBUF is allowed
 * @c:		Execution context
 */
void sock_probe_mem(struct ctx *c)
{
	int v = INT_MAX / 2, s;
	socklen_t sl;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (s < 0) {
		c->low_wmem = c->low_rmem = 1;
		return;
	}

	sl = sizeof(v);
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &sl) ||
	    (size_t)v < SNDBUF_BIG)
		c->low_wmem = 1;

	v = INT_MAX / 2;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v))	||
	    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &sl) ||
	    (size_t)v < RCVBUF_BIG)
		c->low_rmem = 1;

	close(s);
}

/**
 * timespec_diff_us() - Report difference in microseconds between two timestamps
 * @a:		Minuend timestamp
 * @b:		Subtrahend timestamp
 *
 * Return: difference in microseconds (wraps after 2^63 / 10^6s ~= 292k years)
 */
int64_t timespec_diff_us(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_nsec < b->tv_nsec) {
		return (a->tv_nsec + 1000000000 - b->tv_nsec) / 1000 +
		       (a->tv_sec - b->tv_sec - 1) * 1000000;
	}

	return (a->tv_nsec - b->tv_nsec) / 1000 +
	       (a->tv_sec - b->tv_sec) * 1000000;
}

/**
 * timespec_diff_ms() - Report difference in milliseconds between two timestamps
 * @a:		Minuend timestamp
 * @b:		Subtrahend timestamp
 *
 * Return: difference in milliseconds
 */
long timespec_diff_ms(const struct timespec *a, const struct timespec *b)
{
	return timespec_diff_us(a, b) / 1000;
}

/**
 * bitmap_set() - Set single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to set
 */
void bitmap_set(uint8_t *map, unsigned bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word |= BITMAP_BIT(bit);
}

/**
 * bitmap_clear() - Clear single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to clear
 */
void bitmap_clear(uint8_t *map, unsigned bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word &= ~BITMAP_BIT(bit);
}

/**
 * bitmap_isset() - Check for set bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to check
 *
 * Return: true if given bit is set, false if it's not
 */
bool bitmap_isset(const uint8_t *map, unsigned bit)
{
	const unsigned long *word
		= (const unsigned long *)map + BITMAP_WORD(bit);

	return !!(*word & BITMAP_BIT(bit));
}

/**
 * bitmap_or() - Logical disjunction (OR) of two bitmaps
 * @dst:	Pointer to result bitmap
 * @size:	Size of bitmaps, in bytes
 * @a:		First operand
 * @b:		Second operand
 */
void bitmap_or(uint8_t *dst, size_t size, const uint8_t *a, const uint8_t *b)
{
	unsigned long *dw = (unsigned long *)dst;
	unsigned long *aw = (unsigned long *)a;
	unsigned long *bw = (unsigned long *)b;
	size_t i;

	for (i = 0; i < size / sizeof(long); i++, dw++, aw++, bw++)
		*dw = *aw | *bw;

	for (i = size / sizeof(long) * sizeof(long); i < size; i++)
		dst[i] = a[i] | b[i];
}

/*
 * ns_enter() - Enter configured user (unless already joined) and network ns
 * @c:		Execution context
 *
 * Won't return on failure
 *
 * #syscalls:pasta setns
 */
void ns_enter(const struct ctx *c)
{
	if (setns(c->pasta_netns_fd, CLONE_NEWNET))
		die_perror("setns() failed entering netns");
}

/**
 * ns_is_init() - Is the caller running in the "init" user namespace?
 *
 * Return: true if caller is in init, false otherwise, won't return on failure
 */
bool ns_is_init(void)
{
	const char root_uid_map[] = "         0          0 4294967295\n";
	char buf[sizeof(root_uid_map)] = { 0 };
	bool ret = true;
	int fd;

	if ((fd = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC)) < 0)
		die_perror("Can't determine if we're in init namespace");

	if (read(fd, buf, sizeof(root_uid_map)) != sizeof(root_uid_map) - 1 ||
	    strncmp(buf, root_uid_map, sizeof(root_uid_map)))
		ret = false;

	close(fd);
	return ret;
}

/**
 * struct open_in_ns_args - Parameters for do_open_in_ns()
 * @c:		Execution context
 * @fd:		Filled in with return value from open()
 * @err:	Filled in with errno if open() failed
 * @path:	Path to open
 * @flags:	open() flags
 */
struct open_in_ns_args {
	const struct ctx *c;
	int fd;
	int err;
	const char *path;
	int flags;
};

/**
 * do_open_in_ns() - Enter namespace and open a file
 * @arg:	See struct open_in_ns_args
 *
 * Must be called via NS_CALL()
 */
static int do_open_in_ns(void *arg)
{
	struct open_in_ns_args *a = (struct open_in_ns_args *)arg;

	ns_enter(a->c);

	a->fd = open(a->path, a->flags);
	a->err = errno;

	return 0;
}

/**
 * open_in_ns() - open() within the pasta namespace
 * @c:		Execution context
 * @path:	Path to open
 * @flags:	open() flags
 *
 * Return: fd of open()ed file or -1 on error, errno is set to indicate error
 */
int open_in_ns(const struct ctx *c, const char *path, int flags)
{
	struct open_in_ns_args arg = {
		.c = c, .path = path, .flags = flags,
	};

	NS_CALL(do_open_in_ns, &arg);
	errno = arg.err;
	return arg.fd;
}

/**
 * pidfile_write() - Write PID to file, if requested to do so, and close it
 * @fd:		Open PID file descriptor, closed on exit, -1 to skip writing it
 * @pid:	PID value to write
 */
void pidfile_write(int fd, pid_t pid)
{
	char pid_buf[12];
	int n;

	if (fd == -1)
		return;

	n = snprintf(pid_buf, sizeof(pid_buf), "%i\n", pid);

	if (write(fd, pid_buf, n) < 0) {
		perror("PID file write");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

/**
 * output_file_open() - Open file for output, if needed
 * @path:	Path for output file
 * @flags:	Flags for open() other than O_CREAT, O_TRUNC, O_CLOEXEC
 *
 * Return: file descriptor on success, -1 on failure with errno set by open()
 */
int output_file_open(const char *path, int flags)
{
	/* We use O_CLOEXEC here, but clang-tidy as of LLVM 16 to 19 looks for
	 * it in the 'mode' argument if we have one
	 */
	return open(path, O_CREAT | O_TRUNC | O_CLOEXEC | flags,
		    /* NOLINTNEXTLINE(android-cloexec-open) */
		    S_IRUSR | S_IWUSR);
}

/**
 * __daemon() - daemon()-like function writing PID file before parent exits
 * @pidfile_fd:	Open PID file descriptor
 * @devnull_fd:	Open file descriptor for /dev/null
 *
 * Return: child PID on success, won't return on failure
 */
int __daemon(int pidfile_fd, int devnull_fd)
{
	pid_t pid = fork();

	if (pid == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (pid) {
		pidfile_write(pidfile_fd, pid);
		exit(EXIT_SUCCESS);
	}

	if (setsid()				< 0 ||
	    dup2(devnull_fd, STDIN_FILENO)	< 0 ||
	    dup2(devnull_fd, STDOUT_FILENO)	< 0 ||
	    dup2(devnull_fd, STDERR_FILENO)	< 0 ||
	    close(devnull_fd))
		exit(EXIT_FAILURE);

	return 0;
}

/**
 * fls() - Find last (most significant) bit set in word
 * @x:		Word
 *
 * Return: position of most significant bit set, starting from 0, -1 if none
 */
int fls(unsigned long x)
{
	int y = 0;

	if (!x)
		return -1;

	while (x >>= 1)
		y++;

	return y;
}

/**
 * write_file() - Replace contents of file with a string
 * @path:	File to write
 * @buf:	String to write
 *
 * Return: 0 on success, -1 on any error
 */
int write_file(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	size_t len = strlen(buf);

	if (fd < 0) {
		warn_perror("Could not open %s", path);
		return -1;
	}

	while (len) {
		ssize_t rc = write(fd, buf, len);

		if (rc <= 0) {
			warn_perror("Couldn't write to %s", path);
			break;
		}

		buf += rc;
		len -= rc;
	}

	close(fd);
	return len == 0 ? 0 : -1;
}

#ifdef __ia64__
/* Needed by do_clone() below: glibc doesn't export the prototype of __clone2(),
 * use the description from clone(2).
 */
int __clone2(int (*fn)(void *), void *stack_base, size_t stack_size, int flags,
	     void *arg, ... /* pid_t *parent_tid, struct user_desc *tls,
	     pid_t *child_tid */ );
#endif

/**
 * do_clone() - Wrapper of __clone2() for ia64, clone() for other architectures
 * @fn:		Entry point for child
 * @stack_area:	Stack area for child: we'll point callees to the middle of it
 * @stack_size:	Total size of stack area, passed to callee divided by two
 * @flags:	clone() system call flags
 * @arg:	Argument to @fn
 *
 * Return: thread ID of child, -1 on failure
 */
int do_clone(int (*fn)(void *), char *stack_area, size_t stack_size, int flags,
	     void *arg)
{
#ifdef __ia64__
	return __clone2(fn, stack_area + stack_size / 2, stack_size / 2,
			flags, arg);
#else
	return clone(fn, stack_area + stack_size / 2, flags, arg);
#endif
}

/* write_all_buf() - write all of a buffer to an fd
 * @fd:		File descriptor
 * @buf:	Pointer to base of buffer
 * @len:	Length of buffer
 *
 * Return: 0 on success, -1 on error (with errno set)
 *
 * #syscalls write
 */
int write_all_buf(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t left = len;

	while (left) {
		ssize_t rc;

		do
			rc = write(fd, p, left);
		while ((rc < 0) && errno == EINTR);

		if (rc < 0)
			return -1;

		p += rc;
		left -= rc;
	}
	return 0;
}

/* write_remainder() - write the tail of an IO vector to an fd
 * @fd:		File descriptor
 * @iov:	IO vector
 * @iovcnt:	Number of entries in @iov
 * @skip:	Number of bytes of the vector to skip writing
 *
 * Return: 0 on success, -1 on error (with errno set)
 *
 * #syscalls writev
 */
int write_remainder(int fd, const struct iovec *iov, size_t iovcnt, size_t skip)
{
	size_t i = 0, offset;

	while ((i += iov_skip_bytes(iov + i, iovcnt - i, skip, &offset)) < iovcnt) {
		ssize_t rc;

		if (offset) {
			/* Write the remainder of the partially written buffer */
			if (write_all_buf(fd, (char *)iov[i].iov_base + offset,
					  iov[i].iov_len - offset) < 0)
				return -1;
			i++;
		}

		/* Write as much of the remaining whole buffers as we can */
		rc = writev(fd, &iov[i], iovcnt - i);
		if (rc < 0)
			return -1;

		skip = rc;
	}
	return 0;
}

/** sockaddr_ntop() - Convert a socket address to text format
 * @sa:		Socket address
 * @dst:	output buffer, minimum SOCKADDR_STRLEN bytes
 * @size:	size of buffer at @dst
 *
 * Return: On success, a non-null pointer to @dst, NULL on failure
 */
const char *sockaddr_ntop(const void *sa, char *dst, socklen_t size)
{
	sa_family_t family = ((const struct sockaddr *)sa)->sa_family;
	socklen_t off = 0;

#define IPRINTF(...)							\
	do {								\
		off += snprintf(dst + off, size - off, __VA_ARGS__);	\
		if (off >= size)					\
			return NULL;					\
	} while (0)

#define INTOP(af, addr)							\
	do {								\
		if (!inet_ntop((af), (addr), dst + off, size - off))	\
			return NULL;					\
		off += strlen(dst + off);				\
	} while (0)

	switch (family) {
	case AF_UNSPEC:
		IPRINTF("<unspecified>");
		break;

	case AF_INET: {
		const struct sockaddr_in *sa4 = sa;

		INTOP(AF_INET, &sa4->sin_addr);
		IPRINTF(":%hu", ntohs(sa4->sin_port));
		break;
	}

	case AF_INET6: {
		const struct sockaddr_in6 *sa6 = sa;

		IPRINTF("[");
		INTOP(AF_INET6, &sa6->sin6_addr);
		IPRINTF("]:%hu", ntohs(sa6->sin6_port));
		break;
	}

		/* FIXME: Implement AF_UNIX */
	default:
		errno = EAFNOSUPPORT;
		return NULL;
	}

#undef IPRINTF
#undef INTOP

	return dst;
}

/** eth_ntop() - Convert an Ethernet MAC address to text format
 * @mac:	MAC address
 * @dst:	Output buffer, minimum ETH_ADDRSTRLEN bytes
 * @size:	Size of buffer at @dst
 *
 * Return: On success, a non-null pointer to @dst, NULL on failure
 */
const char *eth_ntop(const unsigned char *mac, char *dst, size_t size)
{
	int len;

	len = snprintf(dst, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	if (len < 0 || (size_t)len >= size)
		return NULL;

	return dst;
}

/** str_ee_origin() - Convert socket extended error origin to a string
 * @ee:		Socket extended error structure
 *
 * Return: Static string describing error origin
 */
const char *str_ee_origin(const struct sock_extended_err *ee)
{
	const char *const desc[] = {
		[SO_EE_ORIGIN_NONE]  = "<no origin>",
		[SO_EE_ORIGIN_LOCAL] = "Local",
		[SO_EE_ORIGIN_ICMP]  = "ICMP",
		[SO_EE_ORIGIN_ICMP6] = "ICMPv6",
	};

	if (ee->ee_origin < ARRAY_SIZE(desc))
		return desc[ee->ee_origin];

	return "<invalid>";
}

/**
 * close_open_files() - Close leaked files, but not --fd, stdin, stdout, stderr
 * @argc:	Argument count
 * @argv:	Command line options, as we need to skip any file given via --fd
 */
void close_open_files(int argc, char **argv)
{
	const struct option optfd[] = { { "fd", required_argument, NULL, 'F' },
					{ 0 },
				      };
	long fd = -1;
	int name, rc;

	do {
		name = getopt_long(argc, argv, "-:F:", optfd, NULL);

		if (name == 'F') {
			errno = 0;
			fd = strtol(optarg, NULL, 0);

			if (errno || fd <= STDERR_FILENO || fd > INT_MAX)
				die("Invalid --fd: %s", optarg);
		}
	} while (name != -1);

	if (fd == -1) {
		rc = close_range(STDERR_FILENO + 1, ~0U, CLOSE_RANGE_UNSHARE);
	} else if (fd == STDERR_FILENO + 1) { /* Still a single range */
		rc = close_range(STDERR_FILENO + 2, ~0U, CLOSE_RANGE_UNSHARE);
	} else {
		rc = close_range(STDERR_FILENO + 1, fd - 1,
				 CLOSE_RANGE_UNSHARE);
		if (!rc)
			rc = close_range(fd + 1, ~0U, CLOSE_RANGE_UNSHARE);
	}

	if (rc) {
		if (errno == ENOSYS || errno == EINVAL) {
			/* This probably means close_range() or the
			 * CLOSE_RANGE_UNSHARE flag is not supported by the
			 * kernel.  Not much we can do here except carry on and
			 * hope for the best.
			 */
			warn(
"Can't use close_range() to ensure no files leaked by parent");
		} else {
			die_perror("Failed to close files leaked by parent");
		}
	}

}

/**
 * snprintf_check() - snprintf() wrapper, checking for truncation and errors
 * @str:	Output buffer
 * @size:	Maximum size to write to @str
 * @format:	Message
 *
 * Return: false on success, true on truncation or error, sets errno on failure
 */
bool snprintf_check(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	int rc;

	va_start(ap, format);
	rc = vsnprintf(str, size, format, ap);
	va_end(ap);

	if (rc < 0) {
		errno = EIO;
		return true;
	}

	if ((size_t)rc >= size) {
		errno = ENOBUFS;
		return true;
	}

	return false;
}

#define DEV_RANDOM	"/dev/random"

/**
 * raw_random() - Get high quality random bytes
 * @buf:	Buffer to fill with random bytes
 * @buflen:	Number of bytes of random data to put in @buf
 *
 * Assumes that the random data is essential, and will die() if unable to obtain
 * it.
 */
void raw_random(void *buf, size_t buflen)
{
	size_t random_read = 0;
#ifndef HAS_GETRANDOM
	int fd = open(DEV_RANDOM, O_RDONLY);

	if (fd < 0)
		die_perror("Couldn't open %s", DEV_RANDOM);
#endif

	while (random_read < buflen) {
		ssize_t ret;

#ifdef HAS_GETRANDOM
		ret = getrandom((char *)buf + random_read,
				buflen - random_read, GRND_RANDOM);
#else
		ret = read(dev_random, (char *)buf + random_read,
			   buflen - random_read);
#endif

		if (ret == -1 && errno == EINTR)
			continue;

		if (ret < 0)
			die_perror("Error on random data source");

		if (ret == 0)
			break;

		random_read += ret;
	}

#ifndef HAS_GETRANDOM
	close(dev_random);
#endif

	if (random_read < buflen)
		die("Unexpected EOF on random data source");
}
