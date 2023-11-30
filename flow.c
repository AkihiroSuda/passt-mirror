/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "flow.h"
#include "tcp_conn.h"
#include "flow_table.h"

const char *flow_type_str[] = {
	[FLOW_TYPE_NONE]	= "<none>",
	[FLOW_TCP]		= "TCP connection",
	[FLOW_TCP_SPLICE]	= "TCP connection (spliced)",
};
static_assert(ARRAY_SIZE(flow_type_str) == FLOW_NUM_TYPES,
	      "flow_type_str[] doesn't match enum flow_type");

/* Global Flow Table */
union flow flowtab[FLOW_MAX];

/**
 * flow_table_compact() - Perform compaction on flow table
 * @c:		Execution context
 * @hole:	Pointer to recently closed flow
 */
void flow_table_compact(struct ctx *c, union flow *hole)
{
	union flow *from;

	if (FLOW_IDX(hole) == --c->flow_count) {
		debug("flow: table compaction: maximum index was %u (%p)",
		      FLOW_IDX(hole), (void *)hole);
		memset(hole, 0, sizeof(*hole));
		return;
	}

	from = flowtab + c->flow_count;
	memcpy(hole, from, sizeof(*hole));

	switch (from->f.type) {
	case FLOW_TCP:
		tcp_tap_conn_update(c, &from->tcp, &hole->tcp);
		break;
	case FLOW_TCP_SPLICE:
		tcp_splice_conn_update(c, &hole->tcp_splice);
		break;
	default:
		die("Unexpected %s in tcp_table_compact()",
		    FLOW_TYPE(&from->f));
	}

	debug("flow: table compaction (%s): old index %u, new index %u, "
	      "from: %p, to: %p",
	      FLOW_TYPE(&from->f), FLOW_IDX(from), FLOW_IDX(hole),
	      (void *)from, (void *)hole);

	memset(from, 0, sizeof(*from));
}

/** flow_log_ - Log flow-related message
 * @f:		flow the message is related to
 * @pri:	Log priority
 * @fmt:	Format string
 * @...:	printf-arguments
 */
void flow_log_(const struct flow_common *f, int pri, const char *fmt, ...)
{
	char msg[BUFSIZ];
	va_list args;

	va_start(args, fmt);
	(void)vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	logmsg(pri, "Flow %u (%s): %s", flow_idx(f), FLOW_TYPE(f), msg);
}
