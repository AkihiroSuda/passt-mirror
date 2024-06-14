/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <syslog.h>

#define LOGFILE_SIZE_DEFAULT		(1024 * 1024UL)
#define LOGFILE_CUT_RATIO		30	/* When full, cut ~30% size */
#define LOGFILE_SIZE_MIN		(5UL * MAX(BUFSIZ, PAGE_SIZE))

void vlogmsg(int pri, const char *format, va_list ap);
void logmsg(int pri, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#define err(...)	logmsg(LOG_ERR, __VA_ARGS__)
#define warn(...)	logmsg(LOG_WARNING, __VA_ARGS__)
#define info(...)	logmsg(LOG_INFO, __VA_ARGS__)
#define debug(...)	logmsg(LOG_DEBUG, __VA_ARGS__)

#define die(...)							\
	do {								\
		err(__VA_ARGS__);					\
		exit(EXIT_FAILURE);					\
	} while (0)

extern int log_trace;
extern bool log_conf_parsed;

void trace_init(int enable);
#define trace(...)							\
	do {								\
		if (log_trace)						\
			debug(__VA_ARGS__);				\
	} while (0)

void __openlog(const char *ident, int option, int facility);
void logfile_init(const char *name, const char *path, size_t size);
void passt_vsyslog(int pri, const char *format, va_list ap);
void logfile_write(int pri, const char *format, va_list ap);
void __setlogmask(int mask);

#endif /* LOG_H */
