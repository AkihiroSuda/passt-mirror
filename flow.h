/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */
#ifndef FLOW_H
#define FLOW_H

#define FLOW_TIMER_INTERVAL		1000	/* ms */

/**
 * enum flow_type - Different types of packet flows we track
 */
enum flow_type {
	/* Represents an invalid or unused flow */
	FLOW_TYPE_NONE = 0,
	/* A TCP connection between a socket and tap interface */
	FLOW_TCP,
	/* A TCP connection between a host socket and ns socket */
	FLOW_TCP_SPLICE,

	FLOW_NUM_TYPES,
};

extern const char *flow_type_str[];
#define FLOW_TYPE(f)							\
        ((f)->type < FLOW_NUM_TYPES ? flow_type_str[(f)->type] : "?")

/**
 * struct flow_common - Common fields for packet flows
 * @type:	Type of packet flow
 */
struct flow_common {
	uint8_t		type;
};

#define FLOW_INDEX_BITS		17	/* 128k - 1 */
#define FLOW_MAX		MAX_FROM_BITS(FLOW_INDEX_BITS)

#define FLOW_TABLE_PRESSURE		30	/* % of FLOW_MAX */
#define FLOW_FILE_PRESSURE		30	/* % of c->nofile */

/**
 * struct flow_sidx - ID for one side of a specific flow
 * @side:	Side referenced (0 or 1)
 * @flow:	Index of flow referenced
 */
typedef struct flow_sidx {
	unsigned	side :1;
	unsigned	flow :FLOW_INDEX_BITS;
} flow_sidx_t;
static_assert(sizeof(flow_sidx_t) <= sizeof(uint32_t),
	      "flow_sidx_t must fit within 32 bits");

#define FLOW_SIDX_NONE ((flow_sidx_t){ .flow = FLOW_MAX })

/**
 * flow_sidx_eq() - Test if two sidx values are equal
 * @a, @b:	sidx values
 *
 * Return: true iff @a and @b refer to the same side of the same flow
 */
static inline bool flow_sidx_eq(flow_sidx_t a, flow_sidx_t b)
{
	return (a.flow == b.flow) && (a.side == b.side);
}

union flow;

void flow_table_compact(struct ctx *c, union flow *hole);
void flow_defer_handler(struct ctx *c, const struct timespec *now);

void flow_log_(const struct flow_common *f, int pri, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

#define flow_log(f_, pri, ...)	flow_log_(&(f_)->f, (pri), __VA_ARGS__)

#define flow_dbg(f, ...)	flow_log((f), LOG_DEBUG, __VA_ARGS__)
#define flow_err(f, ...)	flow_log((f), LOG_ERR, __VA_ARGS__)

#define flow_trace(f, ...)						\
	do {								\
		if (log_trace)						\
			flow_dbg((f), __VA_ARGS__);			\
	} while (0)

#endif /* FLOW_H */
