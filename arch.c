// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * arch.c - Architecture-specific implementations
 *
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

/**
 * arch_avx2_exec() - Switch to AVX2 build if supported
 * @argv:	Arguments from command line
 */
#ifdef __x86_64__
void arch_avx2_exec(char **argv)
{
	char exe[PATH_MAX] = { 0 };
	const char *p;

	if (readlink("/proc/self/exe", exe, PATH_MAX - 1) < 0)
		die_perror("Failed to read own /proc/self/exe link");

	p = strstr(exe, ".avx2");
	if (p && strlen(p) == strlen(".avx2"))
		return;

	if (__builtin_cpu_supports("avx2")) {
		char new_path[PATH_MAX + sizeof(".avx2")];

		if (snprintf_check(new_path, PATH_MAX + sizeof(".avx2"),
				   "%s.avx2", exe))
			die_perror("Can't build AVX2 executable path");

		execv(new_path, argv);
		warn_perror("Can't run AVX2 build, using non-AVX2 version");
	}
}
#else
void arch_avx2_exec(char **argv) { (void)argv; }
#endif
