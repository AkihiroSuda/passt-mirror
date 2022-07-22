// SPDX-License-Identifier: AGPL-3.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * conf.c - Configuration settings and option parsing
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "util.h"
#include "passt.h"
#include "netlink.h"
#include "udp.h"
#include "tcp.h"
#include "pasta.h"
#include "lineread.h"

/**
 * get_bound_ports() - Get maps of ports with bound sockets
 * @c:		Execution context
 * @ns:		If set, set bitmaps for ports to tap/ns -- to init otherwise
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
void get_bound_ports(struct ctx *c, int ns, uint8_t proto)
{
	uint8_t *udp_map, *udp_excl, *tcp_map, *tcp_excl;

	if (ns) {
		udp_map = c->udp.port_to_tap;
		udp_excl = c->udp.port_to_init;
		tcp_map = c->tcp.port_to_tap;
		tcp_excl = c->tcp.port_to_init;
	} else {
		udp_map = c->udp.port_to_init;
		udp_excl = c->udp.port_to_tap;
		tcp_map = c->tcp.port_to_init;
		tcp_excl = c->tcp.port_to_tap;
	}

	if (proto == IPPROTO_UDP) {
		memset(udp_map, 0, USHRT_MAX / 8);
		procfs_scan_listen(c, IPPROTO_UDP, V4, ns, udp_map, udp_excl);
		procfs_scan_listen(c, IPPROTO_UDP, V6, ns, udp_map, udp_excl);

		procfs_scan_listen(c, IPPROTO_TCP, V4, ns, udp_map, udp_excl);
		procfs_scan_listen(c, IPPROTO_TCP, V6, ns, udp_map, udp_excl);
	} else if (proto == IPPROTO_TCP) {
		memset(tcp_map, 0, USHRT_MAX / 8);
		procfs_scan_listen(c, IPPROTO_TCP, V4, ns, tcp_map, tcp_excl);
		procfs_scan_listen(c, IPPROTO_TCP, V6, ns, tcp_map, tcp_excl);
	}
}

/**
 * struct get_bound_ports_ns_arg - Arguments for get_bound_ports_ns()
 * @c:		Execution context
 * @proto:	Protocol number (IPPROTO_TCP or IPPROTO_UDP)
 */
struct get_bound_ports_ns_arg {
	struct ctx *c;
	uint8_t proto;
};

/**
 * get_bound_ports_ns() - Get maps of ports in namespace with bound sockets
 * @arg:	See struct get_bound_ports_ns_arg
 *
 * Return: 0
 */
static int get_bound_ports_ns(void *arg)
{
	struct get_bound_ports_ns_arg *a = (struct get_bound_ports_ns_arg *)arg;
	struct ctx *c = a->c;

	if (!c->pasta_netns_fd || ns_enter(c))
		return 0;

	get_bound_ports(c, 1, a->proto);

	return 0;
}

enum conf_port_type {
	PORT_SPEC = 1,
	PORT_NONE,
	PORT_AUTO,
	PORT_ALL,
};

/**
 * conf_ports() - Parse port configuration options, initialise UDP/TCP sockets
 * @c:		Execution context
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @set:	Pointer to @conf_port_type to be set (port binding type)
 *
 * Return: -EINVAL on parsing error, 0 otherwise
 */
static int conf_ports(struct ctx *c, char optname, const char *optarg,
		      enum conf_port_type *set)
{
	int start_src, end_src, start_dst, end_dst, exclude_only = 1, i, port;
	char addr_buf[sizeof(struct in6_addr)] = { 0 }, *addr = addr_buf;
	void (*remap)(in_port_t port, in_port_t delta);
	uint8_t *map, exclude[USHRT_MAX / 8] = { 0 };
	char buf[BUFSIZ], *sep, *spec, *p;
	sa_family_t af = AF_UNSPEC;

	if (optname == 't') {
		map = c->tcp.port_to_tap;
		remap = tcp_remap_to_tap;
	} else if (optname == 'T') {
		map = c->tcp.port_to_init;
		remap = tcp_remap_to_init;
	} else if (optname == 'u') {
		map = c->udp.port_to_tap;
		remap = udp_remap_to_tap;
	} else if (optname == 'U') {
		map = c->udp.port_to_init;
		remap = udp_remap_to_init;
	} else {	/* For gcc -O3 */
		return 0;
	}

	if (!strcmp(optarg, "none")) {
		if (*set)
			return -EINVAL;
		*set = PORT_NONE;
		return 0;
	}

	if (!strcmp(optarg, "auto")) {
		if (*set || c->mode != MODE_PASTA)
			return -EINVAL;
		*set = PORT_AUTO;
		return 0;
	}

	if (!strcmp(optarg, "all")) {
		int i;

		if (*set || c->mode != MODE_PASST)
			return -EINVAL;
		*set = PORT_ALL;
		memset(map, 0xff, PORT_EPHEMERAL_MIN / 8);

		for (i = 0; i < PORT_EPHEMERAL_MIN; i++) {
			if (optname == 't')
				tcp_sock_init(c, 0, AF_UNSPEC, NULL, i);
			else if (optname == 'u')
				udp_sock_init(c, 0, AF_UNSPEC, NULL, i);
		}

		return 0;
	}

	if (*set > PORT_SPEC)
		return -EINVAL;

	*set = PORT_SPEC;

	strncpy(buf, optarg, sizeof(buf) - 1);

	if ((spec = strchr(buf, '/'))) {
		*spec = 0;
		spec++;

		if (optname != 't' && optname != 'u')
			goto bad;

		if (inet_pton(AF_INET, buf, addr))
			af = AF_INET;
		else if (inet_pton(AF_INET6, buf, addr))
			af = AF_INET6;
		else
			goto bad;
	} else {
		spec = buf;

		addr = NULL;
	}

	if (strspn(spec, "0123456789-,:~") != strlen(spec))
		goto bad;

	/* Mark all exclusions first, they might be given after base ranges */
	p = spec;
	start_src = end_src = -1;
	do {
		while (*p != '~' && start_src == -1) {
			exclude_only = 0;

			if (!(p = strchr(p, ',')))
				break;

			p++;
		}
		if (!p || !*p)
			break;

		if (*p == '~')
			p++;

		errno = 0;
		port = strtol(p, &sep, 10);
		if (sep == p)
			break;

		if (port < 0 || port > USHRT_MAX || errno)
			goto bad;

		switch (*sep) {
		case '-':
			if (start_src == -1)		/* ~22-... */
				start_src = port;
			break;
		case ',':
		case 0:
			if (start_src == -1)		/* ~80 */
				start_src = end_src = port;
			else if (end_src == -1)		/* ~22-25 */
				end_src = port;
			else
				goto bad;

			if (start_src > end_src)	/* ~80-22 */
				goto bad;

			for (i = start_src; i <= end_src; i++) {
				if (bitmap_isset(exclude, i))
					goto overlap;

				bitmap_set(exclude, i);
			}
			start_src = end_src = -1;
			break;
		default:
			goto bad;
		}
		p = sep + 1;
	} while (*sep);

	if (exclude_only) {
		for (i = 0; i < PORT_EPHEMERAL_MIN; i++) {
			if (bitmap_isset(exclude, i))
				continue;

			bitmap_set(map, i);

			if (optname == 't')
				tcp_sock_init(c, 0, af, addr, i);
			else if (optname == 'u')
				udp_sock_init(c, 0, af, addr, i);
		}

		return 0;
	}

	/* Now process base ranges, skipping exclusions */
	start_src = end_src = start_dst = end_dst = -1;
	p = spec;
	do {
		while (*p == '~') {
			if (!(p = strchr(p, ',')))
				break;
			p++;
		}
		if (!p || !*p)
			break;

		errno = 0;
		port = strtol(p, &sep, 10);
		if (sep == p)
			break;

		if (port < 0 || port > USHRT_MAX || errno)
			goto bad;

		/* -p 22
		 *    ^ start_src	end_src == start_dst == end_dst == -1
		 *
		 * -p 22-25
		 *    |  ^ end_src
		 *     ` start_src	start_dst == end_dst == -1
		 *
		 * -p 80:8080
		 *    |  ^ start_dst
		 *     ` start_src	end_src == end_dst == -1
		 *
		 * -p 22-80:8022-8080
		 *    |  |  |    ^ end_dst
		 *    |  |   ` start_dst
		 *    |   ` end_dst
		 *     ` start_src
		 */
		switch (*sep) {
		case '-':
			if (start_src == -1) {		/* 22-... */
				start_src = port;
			} else {
				if (!end_src)		/* 22:8022-8080 */
					goto bad;
				start_dst = port;	/* 22-80:8022-... */
			}
			break;
		case ':':
			if (start_src == -1)		/* 80:... */
				start_src = end_src = port;
			else if (end_src == -1)		/* 22-80:... */
				end_src = port;
			else				/* 22-80:8022:... */
				goto bad;
			break;
		case ',':
		case 0:
			if (start_src == -1)		/* 80 */
				start_src = end_src = port;
			else if (end_src == -1)		/* 22-25 */
				end_src = port;
			else if (start_dst == -1)	/* 80:8080 */
				start_dst = end_dst = port;
			else if (end_dst == -1)		/* 22-80:8022-8080 */
				end_dst = port;
			else
				goto bad;

			if (start_src > end_src)	/* 80-22 */
				goto bad;

			if (start_dst > end_dst)	/* 22-80:8080:8022 */
				goto bad;

			if (end_dst != -1 &&
			    end_dst - start_dst != end_src - start_src)
				goto bad;		/* 22-81:8022:8080 */

			for (i = start_src; i <= end_src; i++) {
				if (bitmap_isset(map, i))
					goto overlap;

				if (bitmap_isset(exclude, i))
					continue;

				bitmap_set(map, i);

				if (start_dst != -1) {
					/* 80:8080 or 22-80:8080:8080 */
					remap(i, (in_port_t)(start_dst -
							     start_src));
				}

				if (optname == 't')
					tcp_sock_init(c, 0, af, addr, i);
				else if (optname == 'u')
					udp_sock_init(c, 0, af, addr, i);
			}

			start_src = end_src = start_dst = end_dst = -1;
			break;
		}
		p = sep + 1;
	} while (*sep);

	return 0;
bad:
	err("Invalid port specifier %s", optarg);
	return -EINVAL;

overlap:
	err("Overlapping port specifier %s", optarg);
	return -EINVAL;
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	int dns4_set, dns6_set, dnss_set, dns_set, fd;
	struct in6_addr *dns6 = &c->dns6[0];
	struct fqdn *s = c->dns_search;
	uint32_t *dns4 = &c->dns4[0];
	struct lineread resolvconf;
	int line_len;
	char *line, *p, *end;

	dns4_set = !c->v4  || !!*dns4;
	dns6_set = !c->v6  || !IN6_IS_ADDR_UNSPECIFIED(dns6);
	dnss_set = !!*s->n || c->no_dns_search;
	dns_set = (dns4_set && dns6_set) || c->no_dns;

	if (dns_set && dnss_set)
		return;

	if ((fd = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC)) < 0)
		goto out;

	lineread_init(&resolvconf, fd);
	while ((line_len = lineread_get(&resolvconf, &line)) > 0) {
		if (!dns_set && strstr(line, "nameserver ") == line) {
			p = strrchr(line, ' ');
			if (!p)
				continue;

			end = strpbrk(line, "%\n");
			if (end)
				*end = 0;

			if (!dns4_set &&
			    dns4 - &c->dns4[0] < ARRAY_SIZE(c->dns4) - 1 &&
			    inet_pton(AF_INET, p + 1, dns4)) {
				/* We can only access local addresses via the gw redirect */
				if (ntohl(*dns4) >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET) {
					if (c->no_map_gw) {
						*dns4 = 0;
						continue;
					}
					*dns4 = c->gw4;
				}
				dns4++;
				*dns4 = 0;
			}

			if (!dns6_set &&
			    dns6 - &c->dns6[0] < ARRAY_SIZE(c->dns6) - 1 &&
			    inet_pton(AF_INET6, p + 1, dns6)) {
				/* We can only access local addresses via the gw redirect */
				if (IN6_IS_ADDR_LOOPBACK(dns6)) {
					if (c->no_map_gw) {
						memset(dns6, 0, sizeof(*dns6));
						continue;
					}
					memcpy(dns6, &c->gw6, sizeof(*dns6));
				}
				dns6++;
				memset(dns6, 0, sizeof(*dns6));
			}
		} else if (!dnss_set && strstr(line, "search ") == line &&
			   s == c->dns_search) {
			end = strpbrk(line, "\n");
			if (end)
				*end = 0;

			if (!strtok(line, " \t"))
				continue;

			while (s - c->dns_search < ARRAY_SIZE(c->dns_search) - 1
			       && (p = strtok(NULL, " \t"))) {
				strncpy(s->n, p, sizeof(c->dns_search[0]));
				s++;
				*s->n = 0;
			}
		}
	}

	if (line_len < 0)
		warn("Error reading /etc/resolv.conf: %s", strerror(errno));
	close(fd);

out:
	if (!dns_set && dns4 == c->dns4 && dns6 == c->dns6)
		warn("Couldn't get any nameserver address");
}

/**
 * conf_ns_check() - Check if we can enter configured namespaces
 * @arg:	Execution context
 *
 * Return: 0
 */
static int conf_ns_check(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	if ((!c->netns_only && setns(c->pasta_userns_fd, CLONE_NEWUSER)) ||
	    setns(c->pasta_netns_fd, CLONE_NEWNET))
		c->pasta_userns_fd = c->pasta_netns_fd = -1;

	return 0;

}

/**
 * conf_ns_opt() - Open network, user namespaces descriptors from configuration
 * @c:			Execution context
 * @nsdir:		--nsrun-dir argument, can be an empty string
 * @conf_userns:	--userns argument, can be an empty string
 * @optarg:		PID, path or name of namespace
 *
 * Return: 0 on success, negative error code otherwise
 */
static int conf_ns_opt(struct ctx *c,
		       char *nsdir, const char *conf_userns, const char *optarg)
{
	int ufd = -1, nfd = -1, try, ret, netns_only_reset = c->netns_only;
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX];
	char *endptr;
	long pid_arg;
	pid_t pid;

	if (c->netns_only && *conf_userns) {
		err("Both --userns and --netns-only given");
		return -EINVAL;
	}

	/* It might be a PID, a netns path, or a netns name */
	for (try = 0; try < 3; try++) {
		if (try == 0) {
			pid_arg = strtol(optarg, &endptr, 10);
			if (*endptr || pid_arg < 0 || pid_arg > INT_MAX)
				continue;

			pid = pid_arg;

			if (!*conf_userns && !c->netns_only) {
				ret = snprintf(userns, PATH_MAX,
					       "/proc/%i/ns/user", pid);
				if (ret <= 0 || ret > (int)sizeof(userns))
					continue;
			}
			ret = snprintf(netns, PATH_MAX, "/proc/%i/ns/net", pid);
			if (ret <= 0 || ret > (int)sizeof(netns))
				continue;
		} else if (try == 1) {
			if (!*conf_userns)
				c->netns_only = 1;

			ret = snprintf(netns, PATH_MAX, "%s", optarg);
			if (ret <= 0 || ret > (int)sizeof(userns))
				continue;
		} else if (try == 2) {
			ret = snprintf(netns, PATH_MAX, "%s/%s",
				 *nsdir ? nsdir : NETNS_RUN_DIR, optarg);
			if (ret <= 0 || ret > (int)sizeof(netns))
				continue;
		}

		/* Don't pass O_CLOEXEC here: ns_enter() needs those files */
		if (!c->netns_only) {
			if (*conf_userns)
				/* NOLINTNEXTLINE(android-cloexec-open) */
				ufd = open(conf_userns, O_RDONLY);
			else if (*userns)
				/* NOLINTNEXTLINE(android-cloexec-open) */
				ufd = open(userns, O_RDONLY);
		}

		/* NOLINTNEXTLINE(android-cloexec-open) */
		nfd = open(netns, O_RDONLY);

		if (nfd == -1 || (ufd == -1 && !c->netns_only)) {
			if (nfd >= 0)
				close(nfd);

			if (ufd >= 0)
				close(ufd);

			continue;
		}

		c->pasta_netns_fd = nfd;
		c->pasta_userns_fd = ufd;

		NS_CALL(conf_ns_check, c);

		if (c->pasta_netns_fd >= 0) {
			char buf[PATH_MAX];

			if (try == 0 || c->no_netns_quit)
				return 0;

			strncpy(buf, netns, PATH_MAX);
			strncpy(c->netns_base, basename(buf), PATH_MAX - 1);
			strncpy(buf, netns, PATH_MAX);
			strncpy(c->netns_dir, dirname(buf), PATH_MAX - 1);

			return 0;
		}
	}

	c->netns_only = netns_only_reset;

	return -ENOENT;
}

/**
 * conf_ip() - Verify or detect IPv4/IPv6 support, get relevant addresses
 * @c:		Execution context
 */
static void conf_ip(struct ctx *c)
{
	int v4, v6;

	if (c->v4) {
		c->v4		= IP_VERSION_ENABLED;
		v4		= IP_VERSION_PROBE;
		v6 = c->v6	= IP_VERSION_DISABLED;
	} else if (c->v6) {
		c->v6		= IP_VERSION_ENABLED;
		v6		= IP_VERSION_PROBE;
		v4 = c->v4	= IP_VERSION_DISABLED;
	} else {
		c->v4 = c->v6	= IP_VERSION_ENABLED;
		v4 = v6		= IP_VERSION_PROBE;
	}

	if (v4 != IP_VERSION_DISABLED) {
		if (!c->ifi4)
			c->ifi4 = nl_get_ext_if(AF_INET);
		if (!c->ifi4) {
			warn("No external routable interface for IPv4");
			v4 = IP_VERSION_DISABLED;
		}
	}

	if (v6 != IP_VERSION_DISABLED) {
		if (!c->ifi6)
			c->ifi6 = nl_get_ext_if(AF_INET6);
		if (!c->ifi6) {
			warn("No external routable interface for IPv6");
			v6 = IP_VERSION_DISABLED;
		}
	}

	if (v4 != IP_VERSION_DISABLED) {
		if (!c->gw4)
			nl_route(0, c->ifi4, AF_INET, &c->gw4);

		if (!c->addr4) {
			int mask_len = 0;

			nl_addr(0, c->ifi4, AF_INET, &c->addr4, &mask_len, NULL);
			c->mask4 = htonl(0xffffffff << (32 - mask_len));
		}

		if (!c->mask4) {
			if (IN_CLASSA(ntohl(c->addr4)))
				c->mask4 = htonl(IN_CLASSA_NET);
			else if (IN_CLASSB(ntohl(c->addr4)))
				c->mask4 = htonl(IN_CLASSB_NET);
			else if (IN_CLASSC(ntohl(c->addr4)))
				c->mask4 = htonl(IN_CLASSC_NET);
			else
				c->mask4 = 0xffffffff;
		}

		memcpy(&c->addr4_seen, &c->addr4, sizeof(c->addr4_seen));

		if (MAC_IS_ZERO(c->mac))
			nl_link(0, c->ifi4, c->mac, 0, 0);
	}

	if (c->mode == MODE_PASST)
		memset(&c->mac_guest, 0xff, sizeof(c->mac_guest));

	if (v6 != IP_VERSION_DISABLED) {
		int prefix_len = 0;

		if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6))
			nl_route(0, c->ifi6, AF_INET6, &c->gw6);

		nl_addr(0, c->ifi6, AF_INET6,
			IN6_IS_ADDR_UNSPECIFIED(&c->addr6) ? &c->addr6 : NULL,
			&prefix_len, &c->addr6_ll);

		memcpy(&c->addr6_seen, &c->addr6, sizeof(c->addr6));
		memcpy(&c->addr6_ll_seen, &c->addr6_ll, sizeof(c->addr6_ll));

		if (MAC_IS_ZERO(c->mac))
			nl_link(0, c->ifi6, c->mac, 0, 0);
	}

	if (!c->gw4 || !c->addr4 || MAC_IS_ZERO(c->mac))
		v4 = IP_VERSION_DISABLED;
	else
		v4 = IP_VERSION_ENABLED;

	if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6) ||
	    IN6_IS_ADDR_UNSPECIFIED(&c->addr6) ||
	    IN6_IS_ADDR_UNSPECIFIED(&c->addr6_ll) ||
	    MAC_IS_ZERO(c->mac))
		v6 = IP_VERSION_DISABLED;
	else
		v6 = IP_VERSION_ENABLED;

	if ((v4 == IP_VERSION_DISABLED) && (v6 == IP_VERSION_DISABLED)) {
		err("External interface not usable");
		exit(EXIT_FAILURE);
	}

	c->v4 = v4;
	c->v6 = v6;
}

/**
 * usage() - Print usage and exit
 * @name:	Executable name
 */
static void usage(const char *name)
{
	if (strstr(name, "pasta")) {
		info("Usage: %s [OPTION]... [PID|PATH|NAME]", name);
		info("");
		info("Without PID|PATH|NAME, run the default shell in a new");
		info("network and user namespace, and connect it via pasta.");
	} else {
		info("Usage: %s [OPTION]...", name);
	}
	info("");

	info(   "  -d, --debug		Be verbose, don't run in background");
	info(   "      --trace		Be extra verbose, implies --debug");
	info(   "  -q, --quiet		Don't print informational messages");
	info(   "  -f, --foreground	Don't run in background");
	info(   "    default: run in background if started from a TTY");
	info(   "  -e, --stderr		Log to stderr too");
	info(   "    default: log to system logger only if started from a TTY");
	info(   "  --runas UID|UID:GID 	Use given UID, GID if started as root");
	info(   "    UID and GID can be numeric, or login and group names");
	info(   "    default: drop to user \"nobody\"");
	info(   "  -h, --help		Display this help message and exit");

	if (strstr(name, "pasta")) {
		info(   "  -I, --ns-ifname NAME	namespace interface name");
		info(   "    default: same interface name as external one");
	} else {
		info(   "  -s, --socket PATH	UNIX domain socket path");
		info(   "    default: probe free path starting from "
		     UNIX_SOCK_PATH, 1);
	}

	info(   "  -p, --pcap [FILE]	Log tap-facing traffic to pcap file");
	info(   "    if FILE is not given, log to:");

	if (strstr(name, "pasta"))
		info("      /tmp/pasta_ISO8601-TIMESTAMP_PID.pcap");
	else
		info("      /tmp/passt_ISO8601-TIMESTAMP_PID.pcap");

	info(   "  -P, --pid FILE	Write own PID to the given file");
	info(   "  -m, --mtu MTU	Assign MTU via DHCP/NDP");
	info(   "    a zero value disables assignment");
	info(   "    default: 65520: maximum 802.3 MTU minus 802.3 header");
	info(   "                    length, rounded to 32 bits (IPv4 words)");
	info(   "  -a, --address ADDR	Assign IPv4 or IPv6 address ADDR");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: use addresses from interface with default route");
	info(   "  -n, --netmask MASK	Assign IPv4 MASK, dot-decimal or bits");
	info(   "    default: netmask from matching address on the host");
	info(   "  -M, --mac-addr ADDR	Use source MAC address ADDR");
	info(   "    default: MAC address from interface with default route");
	info(   "  -g, --gateway ADDR	Pass IPv4 or IPv6 address as gateway");
	info(   "    default: gateway from interface with default route");
	info(   "  -i, --interface NAME	Interface for addresses and routes");
	info(   "    default: interface with first default route");
	info(   "  -D, --dns ADDR	Use IPv4 or IPv6 address as DNS");
	info(   "    can be specified multiple times");
	info(   "    a single, empty option disables DNS information");
	if (strstr(name, "pasta"))
		info(   "    default: don't use any addresses");
	else
		info(   "    default: use addresses from /etc/resolv.conf");

	info(   "  -S, --search LIST	Space-separated list, search domains");
	info(   "    a single, empty option disables the DNS search list");
	if (strstr(name, "pasta"))
		info(   "    default: don't use any search list");
	else
		info(   "    default: use search list from /etc/resolv.conf");

	if (strstr(name, "pasta"))
		info("  --dhcp-dns:	\tPass DNS list via DHCP/DHCPv6/NDP");
	else
		info("  --no-dhcp-dns:	No DNS list in DHCP/DHCPv6/NDP");

	if (strstr(name, "pasta"))
		info("  --dhcp-search:	Pass list via DHCP/DHCPv6/NDP");
	else
		info("  --no-dhcp-search:	No list in DHCP/DHCPv6/NDP");

	info(   "  --dns-forward ADDR	Forward DNS queries sent to ADDR");
	info(   "    can be specified zero to two times (for IPv4 and IPv6)");
	info(   "    default: don't forward DNS queries");

	info(   "  --no-tcp		Disable TCP protocol handler");
	info(   "  --no-udp		Disable UDP protocol handler");
	info(   "  --no-icmp		Disable ICMP/ICMPv6 protocol handler");
	info(   "  --no-dhcp		Disable DHCP server");
	info(   "  --no-ndp		Disable NDP responses");
	info(   "  --no-dhcpv6		Disable DHCPv6 server");
	info(   "  --no-ra		Disable router advertisements");
	info(   "  --no-map-gw		Don't map gateway address to host");
	info(   "  -4, --ipv4-only	Enable IPv4 operation only");
	info(   "  -6, --ipv6-only	Enable IPv6 operation only");

	if (strstr(name, "pasta"))
		goto pasta_opts;

	info(   "  -t, --tcp-ports SPEC	TCP port forwarding to guest");
	info(   "    can be specified multiple times");
	info(   "    SPEC can be:");
	info(   "      'none': don't forward any ports");
	info(   "      'all': forward all unbound, non-ephemeral ports");
	info(   "      a comma-separated list, optionally ranged with '-'");
	info(   "        and optional target ports after ':', with optional");
	info(   "        address specification suffixed by '/'. Ranges can be");
	info(   "        reduced by excluding ports or ranges prefixed by '~'");
	info(   "        Examples:");
	info(   "        -t 22		Forward local port 22 to 22 on guest");
	info(   "        -t 22:23	Forward local port 22 to 23 on guest");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80  	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
	info(   "        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to guest");
	info(   "        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25");
	info(   "        -t ~25		Forward all ports except for 25");
	info(   "    default: none");
	info(   "  -u, --udp-ports SPEC	UDP port forwarding to guest");
	info(   "    SPEC is as described for TCP above");
	info(   "    default: none");

	exit(EXIT_FAILURE);

pasta_opts:
	info(   "  -t, --tcp-ports SPEC	TCP port forwarding to namespace");
	info(   "    can be specified multiple times"); 
	info(   "    SPEC can be:");
	info(   "      'none': don't forward any ports");
	info(   "      'auto': forward all ports currently bound in namespace");
	info(   "      a comma-separated list, optionally ranged with '-'");
	info(   "        and optional target ports after ':', with optional");
	info(   "        address specification suffixed by '/'. Examples:");
	info(   "        -t 22	Forward local port 22 to port 22 in netns");
	info(   "        -t 22:23	Forward local port 22 to port 23");
	info(   "        -t 22,25	Forward ports 22, 25 to ports 22, 25");
	info(   "        -t 22-80	Forward ports 22 to 80");
	info(   "        -t 22-80:32-90	Forward ports 22 to 80 to");
	info(   "			corresponding port numbers plus 10");
	info(   "        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to namespace");
	info(   "        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25");
	info(   "        -t ~25		Forward all bound ports except for 25");
	info(   "    default: auto");
	info(   "    IPv6 bound ports are also forwarded for IPv4");
	info(   "  -u, --udp-ports SPEC	UDP port forwarding to namespace");
	info(   "    SPEC is as described for TCP above");
	info(   "    default: auto");
	info(   "    IPv6 bound ports are also forwarded for IPv4");
	info(   "    unless specified, with '-t auto', UDP ports with numbers");
	info(   "    corresponding to forwarded TCP port numbers are");
	info(   "    forwarded too");
	info(   "  -T, --tcp-ns SPEC	TCP port forwarding to init namespace");
	info(   "    SPEC is as described above");
	info(   "    default: auto");
	info(   "  -U, --udp-ns SPEC	UDP port forwarding to init namespace");
	info(   "    SPEC is as described above");
	info(   "    default: auto");
	info(   "  --userns NSPATH 	Target user namespace to join");
	info(   "  --netns-only		Don't join existing user namespace");
	info(   "    implied if PATH or NAME are given without --userns");
	info(   "  --nsrun-dir		Directory for nsfs mountpoints");
	info(   "    default: " NETNS_RUN_DIR);
	info(   "  --config-net		Configure tap interface in namespace");
	info(   "  --ns-mac-addr ADDR	Set MAC address on tap interface");

	exit(EXIT_FAILURE);
}

/**
 * conf_print() - Print fundamental configuration parameters
 * @c:		Execution context
 */
static void conf_print(const struct ctx *c)
{
	char buf4[INET_ADDRSTRLEN], ifn[IFNAMSIZ];
	int i;

	if (c->ifi4)
		info("Outbound interface (IPv4): %s", if_indextoname(c->ifi4, ifn));
	if (c->ifi6)
		info("Outbound interface (IPv6): %s", if_indextoname(c->ifi6, ifn));
	if (c->mode == MODE_PASTA)
		info("Namespace interface: %s", c->pasta_ifn);

	info("MAC:");
	info("    host: %02x:%02x:%02x:%02x:%02x:%02x",
	     c->mac[0], c->mac[1], c->mac[2],
	     c->mac[3], c->mac[4], c->mac[5]);

	if (c->v4) {
		if (!c->no_dhcp) {
			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->addr4, buf4, sizeof(buf4)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &c->mask4, buf4, sizeof(buf4)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->gw4,   buf4, sizeof(buf4)));
		}

		for (i = 0; c->dns4[i]; i++) {
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET, &c->dns4[i], buf4, sizeof(buf4));
			info("    %s", buf4);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}

	if (c->v6) {
		char buf6[INET6_ADDRSTRLEN];

		if (!c->no_ndp && !c->no_dhcpv6)
			info("NDP/DHCPv6:");
		else if (!c->no_ndp)
			info("DHCPv6:");
		else if (!c->no_dhcpv6)
			info("NDP:");
		else
			goto dns6;

		info("    assign: %s",
		     inet_ntop(AF_INET6, &c->addr6, buf6, sizeof(buf6)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c->gw6,   buf6, sizeof(buf6)));
		info("    our link-local: %s",
		     inet_ntop(AF_INET6, &c->addr6_ll, buf6, sizeof(buf6)));

dns6:
		for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&c->dns6[i]); i++) {
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET6, &c->dns6[i], buf6, sizeof(buf6));
			info("    %s", buf6);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}
}

/**
 * conf_runas() - Handle --runas: look up desired UID and GID
 * @opt:	Passed option value
 * @uid:	User ID, set on return if valid
 * @gid:	Group ID, set on return if valid
 *
 * Return: 0 on success, negative error code on failure
 */
static int conf_runas(const char *opt, unsigned int *uid, unsigned int *gid)
{
	char ubuf[LOGIN_NAME_MAX], gbuf[LOGIN_NAME_MAX], *endptr;
	struct passwd *pw;
	struct group *gr;

	/* NOLINTNEXTLINE(cert-err34-c): 2 if conversion succeeds */
	if (sscanf(opt, "%u:%u", uid, gid) == 2 && *uid && *gid)
		return 0;

	*uid = strtol(opt, &endptr, 0);
	if (!*endptr && (*gid = *uid))
		return 0;

#ifdef GLIBC_NO_STATIC_NSS
	(void)ubuf;
	(void)gbuf;
	(void)pw;
	(void)gr;

	return -EINVAL;
#else
	/* NOLINTNEXTLINE(cert-err34-c): 2 if conversion succeeds */
	if (sscanf(opt, "%" STR(LOGIN_NAME_MAX) "[^:]:"
			"%" STR(LOGIN_NAME_MAX) "s", ubuf, gbuf) == 2) {
		if (!(pw = getpwnam(ubuf)) || !(*uid = pw->pw_uid))
			return -ENOENT;

		if (!(gr = getgrnam(gbuf)) || !(*gid = gr->gr_gid))
			return -ENOENT;

		return 0;
	}

	pw = getpwnam(ubuf);
	if (!pw || !(*uid = pw->pw_uid) || !(*gid = pw->pw_gid))
		return -ENOENT;

	return 0;
#endif /* !GLIBC_NO_STATIC_NSS */
}

/**
 * conf() - Process command-line arguments and set configuration
 * @c:		Execution context
 * @argc:	Argument count
 * @argv:	Options, plus target PID for pasta mode
 */
void conf(struct ctx *c, int argc, char **argv)
{
	struct option options[] = {
		{"debug",	no_argument,		NULL,		'd' },
		{"quiet",	no_argument,		NULL,		'q' },
		{"foreground",	no_argument,		NULL,		'f' },
		{"stderr",	no_argument,		NULL,		'e' },
		{"help",	no_argument,		NULL,		'h' },
		{"socket",	required_argument,	NULL,		's' },
		{"ns-ifname",	required_argument,	NULL,		'I' },
		{"pcap",	optional_argument,	NULL,		'p' },
		{"pid",		required_argument,	NULL,		'P' },
		{"mtu",		required_argument,	NULL,		'm' },
		{"address",	required_argument,	NULL,		'a' },
		{"netmask",	required_argument,	NULL,		'n' },
		{"mac-addr",	required_argument,	NULL,		'M' },
		{"gateway",	required_argument,	NULL,		'g' },
		{"interface",	required_argument,	NULL,		'i' },
		{"dns",		optional_argument,	NULL,		'D' },
		{"search",	optional_argument,	NULL,		'S' },
		{"no-tcp",	no_argument,		&c->no_tcp,	1 },
		{"no-udp",	no_argument,		&c->no_udp,	1 },
		{"no-icmp",	no_argument,		&c->no_icmp,	1 },
		{"no-dhcp",	no_argument,		&c->no_dhcp,	1 },
		{"no-dhcpv6",	no_argument,		&c->no_dhcpv6,	1 },
		{"no-ndp",	no_argument,		&c->no_ndp,	1 },
		{"no-ra",	no_argument,		&c->no_ra,	1 },
		{"no-map-gw",	no_argument,		&c->no_map_gw,	1 },
		{"ipv4-only",	no_argument,		&c->v4,		'4' },
		{"ipv6-only",	no_argument,		&c->v6,		'6' },
		{"tcp-ports",	required_argument,	NULL,		't' },
		{"udp-ports",	required_argument,	NULL,		'u' },
		{"tcp-ns",	required_argument,	NULL,		'T' },
		{"udp-ns",	required_argument,	NULL,		'U' },
		{"userns",	required_argument,	NULL,		2 },
		{"netns-only",	no_argument,		&c->netns_only,	1 },
		{"nsrun-dir",	required_argument,	NULL,		3 },
		{"config-net",	no_argument,		&c->pasta_conf_ns, 1 },
		{"ns-mac-addr",	required_argument,	NULL,		4 },
		{"dhcp-dns",	no_argument,		NULL,		5 },
		{"no-dhcp-dns",	no_argument,		NULL,		6 },
		{"dhcp-search", no_argument,		NULL,		7 },
		{"no-dhcp-search", no_argument,		NULL,		8 },
		{"dns-forward",	required_argument,	NULL,		9 },
		{"no-netns-quit", no_argument,		NULL,		10 },
		{"trace",	no_argument,		NULL,		11 },
		{"runas",	required_argument,	NULL,		12 },
		{ 0 },
	};
	struct get_bound_ports_ns_arg ns_ports_arg = { .c = c };
	char nsdir[PATH_MAX] = { 0 }, userns[PATH_MAX] = { 0 };
	enum conf_port_type tcp_tap = 0, tcp_init = 0;
	enum conf_port_type udp_tap = 0, udp_init = 0;
	struct fqdn *dnss = c->dns_search;
	struct in6_addr *dns6 = c->dns6;
	int name, ret, mask, b, i;
	uint32_t *dns4 = c->dns4;

	if (c->mode == MODE_PASTA)
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;

	do {
		const char *optstring;

		if (c->mode == MODE_PASST)
			optstring = "dqfehs:p::P:m:a:n:M:g:i:D::S::46t:u:";
		else
			optstring = "dqfehI:p::P:m:a:n:M:g:i:D::S::46t:u:T:U:";

		name = getopt_long(argc, argv, optstring, options, NULL);

		if ((name == 'p' || name == 'D' || name == 'S') && !optarg &&
		    optind < argc && *argv[optind] && *argv[optind] != '-') {
			if (c->mode == MODE_PASTA) {
				if (conf_ns_opt(c, nsdir, userns, argv[optind]))
					optarg = argv[optind++];
			} else {
				optarg = argv[optind++];
			}
		}

		switch (name) {
		case -1:
		case 0:
			break;
		case 2:
			if (c->mode != MODE_PASTA) {
				err("--userns is for pasta mode only");
				usage(argv[0]);
			}

			ret = snprintf(userns, sizeof(userns), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(userns)) {
				err("Invalid userns: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 3:
			if (c->mode != MODE_PASTA) {
				err("--nsrun-dir is for pasta mode only");
				usage(argv[0]);
			}

			ret = snprintf(nsdir, sizeof(nsdir), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(nsdir)) {
				err("Invalid nsrun-dir: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 4:
			if (c->mode != MODE_PASTA) {
				err("--ns-mac-addr is for pasta mode only");
				usage(argv[0]);
			}

			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac_guest[i] = b;
			}
			break;
		case 5:
			if (c->mode != MODE_PASTA) {
				err("--dhcp-dns is for pasta mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns = 0;
			break;
		case 6:
			if (c->mode != MODE_PASST) {
				err("--no-dhcp-dns is for passt mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns = 1;
			break;
		case 7:
			if (c->mode != MODE_PASTA) {
				err("--dhcp-search is for pasta mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns_search = 0;
			break;
		case 8:
			if (c->mode != MODE_PASST) {
				err("--no-dhcp-search is for passt mode only");
				usage(argv[0]);
			}
			c->no_dhcp_dns_search = 1;
			break;
		case 9:
			if (IN6_IS_ADDR_UNSPECIFIED(&c->dns6_fwd)	&&
			    inet_pton(AF_INET6, optarg, &c->dns6_fwd)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->dns6_fwd)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->dns6_fwd))
				break;

			if (c->dns4_fwd == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->dns4_fwd)	&&
			    c->dns4_fwd != INADDR_ANY			&&
			    c->dns4_fwd != INADDR_BROADCAST		&&
			    c->dns4_fwd != INADDR_LOOPBACK)
				break;

			err("Invalid DNS forwarding address: %s", optarg);
			usage(argv[0]);
			break;
		case 10:
			if (c->mode != MODE_PASTA) {
				err("--no-netns-quit is for pasta mode only");
				usage(argv[0]);
			}
			c->no_netns_quit = 1;
			break;
		case 11:
			if (c->trace) {
				err("Multiple --trace options given");
				usage(argv[0]);
			}

			if (c->quiet) {
				err("Either --trace or --quiet");
				usage(argv[0]);
			}

			c->trace = c->debug = c->foreground = 1;
			break;
		case 12:
			if (c->uid || c->gid) {
				err("Multiple --runas options given");
				usage(argv[0]);
			}

			if (conf_runas(optarg, &c->uid, &c->gid)) {
				err("Invalid --runas option: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'd':
			if (c->debug) {
				err("Multiple --debug options given");
				usage(argv[0]);
			}

			if (c->quiet) {
				err("Either --debug or --quiet");
				usage(argv[0]);
			}

			c->debug = 1;
			c->foreground = 1;
			break;
		case 'e':
			if (c->stderr) {
				err("Multiple --stderr options given");
				usage(argv[0]);
			}

			c->stderr = 1;
			break;
		case 'q':
			if (c->quiet) {
				err("Multiple --quiet options given");
				usage(argv[0]);
			}

			if (c->debug) {
				err("Either --debug or --quiet");
				usage(argv[0]);
			}

			c->quiet = 1;
			break;
		case 'f':
			if (c->foreground && !c->debug) {
				err("Multiple --foreground options given");
				usage(argv[0]);
			}

			c->foreground = 1;
			break;
		case 's':
			if (*c->sock_path) {
				err("Multiple --socket options given");
				usage(argv[0]);
			}

			ret = snprintf(c->sock_path, UNIX_SOCK_MAX - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap)) {
				err("Invalid socket path: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'I':
			if (*c->pasta_ifn) {
				err("Multiple --ns-ifname options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pasta_ifn, IFNAMSIZ - 1, "%s",
				       optarg);
			if (ret <= 0 || ret >= IFNAMSIZ - 1) {
				err("Invalid interface name: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'p':
			if (*c->pcap) {
				err("Multiple --pcap options given");
				usage(argv[0]);
			}

			if (!optarg) {
				*c->pcap = 1;
				break;
			}

			ret = snprintf(c->pcap, sizeof(c->pcap), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap)) {
				err("Invalid pcap path: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'P':
			if (*c->pid_file) {
				err("Multiple --pid options given");
				usage(argv[0]);
			}

			ret = snprintf(c->pid_file, sizeof(c->pid_file), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pid_file)) {
				err("Invalid PID file: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'm':
			if (c->mtu) {
				err("Multiple --mtu options given");
				usage(argv[0]);
			}

			errno = 0;
			c->mtu = strtol(optarg, NULL, 0);

			if (!c->mtu) {
				c->mtu = -1;
				break;
			}

			if (c->mtu < ETH_MIN_MTU || c->mtu > (int)ETH_MAX_MTU ||
			    errno) {
				err("Invalid MTU: %s", optarg);
				usage(argv[0]);
			}
			break;
		case 'a':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->addr6)		&&
			    inet_pton(AF_INET6, optarg, &c->addr6)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->addr6)		&&
			    !IN6_IS_ADDR_LOOPBACK(&c->addr6)		&&
			    !IN6_IS_ADDR_V4MAPPED(&c->addr6)		&&
			    !IN6_IS_ADDR_V4COMPAT(&c->addr6)		&&
			    !IN6_IS_ADDR_MULTICAST(&c->addr6))
				break;

			if (c->addr4 == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->addr4)	&&
			    c->addr4 != INADDR_ANY			&&
			    c->addr4 != INADDR_BROADCAST		&&
			    c->addr4 != INADDR_LOOPBACK			&&
			    !IN_MULTICAST(c->addr4))
				break;

			err("Invalid address: %s", optarg);
			usage(argv[0]);
			break;
		case 'n':
			if (inet_pton(AF_INET, optarg, &c->mask4))
				break;

			errno = 0;
			mask = strtol(optarg, NULL, 0);
			if (mask > 0 && mask <= 32 && !errno) {
				c->mask4 = htonl(0xffffffff << (32 - mask));
				break;
			}

			err("Invalid netmask: %s", optarg);
			usage(argv[0]);
			break;
		case 'M':
			for (i = 0; i < ETH_ALEN; i++) {
				errno = 0;
				b = strtol(optarg + (intptr_t)i * 3, NULL, 16);
				if (b < 0 || b > UCHAR_MAX || errno) {
					err("Invalid MAC address: %s", optarg);
					usage(argv[0]);
				}
				c->mac[i] = b;
			}
			break;
		case 'g':
			if (IN6_IS_ADDR_UNSPECIFIED(&c->gw6)		&&
			    inet_pton(AF_INET6, optarg, &c->gw6)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->gw6)		&&
			    !IN6_IS_ADDR_LOOPBACK(&c->gw6))
				break;

			if (c->gw4 == INADDR_ANY			&&
			    inet_pton(AF_INET, optarg, &c->gw4)		&&
			    c->gw4 != INADDR_ANY			&&
			    c->gw4 != INADDR_BROADCAST			&&
			    c->gw4 != INADDR_LOOPBACK)
				break;

			err("Invalid gateway address: %s", optarg);
			usage(argv[0]);
			break;
		case 'i':
			if (c->ifi4 || c->ifi6) {
				err("Redundant interface: %s", optarg);
				usage(argv[0]);
			}

			if (!(c->ifi4 = c->ifi6 = if_nametoindex(optarg))) {
				err("Invalid interface name %s: %s", optarg,
				    strerror(errno));
				usage(argv[0]);
			}
			break;
		case 'D':
			if (c->no_dns ||
			    (!optarg && (dns4 - c->dns4 || dns6 - c->dns6))) {
				err("Empty and non-empty DNS options given");
				usage(argv[0]);
			}

			if (!optarg) {
				c->no_dns = 1;
				break;
			}

			if (dns4 - &c->dns4[0] < ARRAY_SIZE(c->dns4) &&
			    inet_pton(AF_INET, optarg, dns4)) {
				dns4++;
				break;
			}

			if (dns6 - &c->dns6[0] < ARRAY_SIZE(c->dns6) &&
			    inet_pton(AF_INET6, optarg, dns6)) {
				dns6++;
				break;
			}

			err("Cannot use DNS address %s", optarg);
			usage(argv[0]);
			break;
		case 'S':
			if (c->no_dns_search ||
			    (!optarg && dnss != c->dns_search)) {
				err("Empty and non-empty DNS search given");
				usage(argv[0]);
			}

			if (!optarg) {
				c->no_dns_search = 1;
				break;
			}

			if (dnss - c->dns_search < ARRAY_SIZE(c->dns_search)) {
				ret = snprintf(dnss->n, sizeof(*c->dns_search),
					       "%s", optarg);
				dnss++;

				if (ret > 0 &&
				    ret < (int)sizeof(*c->dns_search))
					break;
			}

			err("Cannot use DNS search domain %s", optarg);
			usage(argv[0]);
			break;
		case '4':
			c->v4 = 1;
			break;
		case '6':
			c->v6 = 1;
			break;
		case 't':
		case 'u':
		case 'T':
		case 'U':
			/* Handle these later, once addresses are configured */
			break;
		case '?':
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	} while (name != -1);

	check_root(c);

	if (c->mode == MODE_PASTA && optind + 1 == argc) {
		ret = conf_ns_opt(c, nsdir, userns, argv[optind]);
		if (ret == -ENOENT)
			err("Namespace %s not found", argv[optind]);
		if (ret < 0)
			usage(argv[0]);
	} else if (c->mode == MODE_PASTA && *userns && optind == argc) {
		err("--userns requires PID, PATH or NAME");
		usage(argv[0]);
	} else if (optind != argc) {
		usage(argv[0]);
	}

	if (c->v4 && c->v6) {
		err("Options ipv4-only and ipv6-only are mutually exclusive");
		usage(argv[0]);
	}

	if (c->pasta_conf_ns)
		c->no_ra = 1;

	if (c->mode == MODE_PASTA && c->pasta_netns_fd == -1)
		pasta_start_ns(c);

	if (nl_sock_init(c)) {
		err("Failed to get netlink socket");
		exit(EXIT_FAILURE);
	}

	conf_ip(c);

	/* Now we can process port configuration options */
	optind = 1;
	do {
		enum conf_port_type *set = NULL;
		const char *optstring;

		if (c->mode == MODE_PASST)
			optstring = "dqfehs:p::P:m:a:n:M:g:i:D::S::46t:u:";
		else
			optstring = "dqfehI:p::P:m:a:n:M:g:i:D::S::46t:u:T:U:";

		name = getopt_long(argc, argv, optstring, options, NULL);
		switch (name) {
		case 't':
		case 'u':
		case 'T':
		case 'U':
			if (name == 't')
				set = &tcp_tap;
			else if (name == 'T')
				set = &tcp_init;
			else if (name == 'u')
				set = &udp_tap;
			else if (name == 'U')
				set = &udp_init;

			if (!optarg || conf_ports(c, name, optarg, set))
				usage(argv[0]);

			break;
		default:
			break;
		}
	} while (name != -1);

	if (!c->v4)
		c->no_dhcp = 1;

	if (!c->v6) {
		c->no_ndp = 1;
		c->no_dhcpv6 = 1;
	}

	if (!c->mtu)
		c->mtu = ROUND_DOWN(ETH_MAX_MTU - ETH_HLEN, sizeof(uint32_t));

	get_dns(c);

	if (!*c->pasta_ifn) {
		if (c->ifi4)
			if_indextoname(c->ifi4, c->pasta_ifn);
		else
			if_indextoname(c->ifi6, c->pasta_ifn);
	}

	c->tcp.ns_detect_ports   = c->udp.ns_detect_ports   = 0;
	c->tcp.init_detect_ports = c->udp.init_detect_ports = 0;

	if (c->mode == MODE_PASTA) {
		c->proc_net_tcp[V4][0] = c->proc_net_tcp[V4][1] = -1;
		c->proc_net_tcp[V6][0] = c->proc_net_tcp[V6][1] = -1;
		c->proc_net_udp[V4][0] = c->proc_net_udp[V4][1] = -1;
		c->proc_net_udp[V6][0] = c->proc_net_udp[V6][1] = -1;

		if (!tcp_tap || tcp_tap == PORT_AUTO) {
			c->tcp.ns_detect_ports = 1;
			ns_ports_arg.proto = IPPROTO_TCP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!udp_tap || udp_tap == PORT_AUTO) {
			c->udp.ns_detect_ports = 1;
			ns_ports_arg.proto = IPPROTO_UDP;
			NS_CALL(get_bound_ports_ns, &ns_ports_arg);
		}
		if (!tcp_init || tcp_init == PORT_AUTO) {
			c->tcp.init_detect_ports = 1;
			get_bound_ports(c, 0, IPPROTO_TCP);
		}
		if (!udp_init || udp_init == PORT_AUTO) {
			c->udp.init_detect_ports = 1;
			get_bound_ports(c, 0, IPPROTO_UDP);
		}
	}

	if (!c->quiet)
		conf_print(c);
}
