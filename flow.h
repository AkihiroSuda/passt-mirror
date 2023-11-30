/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */
#ifndef FLOW_H
#define FLOW_H

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

union flow;

void flow_table_compact(struct ctx *c, union flow *hole);

#endif /* FLOW_H */
