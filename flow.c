/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "flow.h"
#include "flow_table.h"

const char *flow_type_str[] = {
	[FLOW_TYPE_NONE]	= "<none>",
	[FLOW_TCP]		= "TCP connection",
	[FLOW_TCP_SPLICE]	= "TCP connection (spliced)",
};
static_assert(ARRAY_SIZE(flow_type_str) == FLOW_NUM_TYPES,
	      "flow_type_str[] doesn't match enum flow_type");

const uint8_t flow_proto[] = {
	[FLOW_TCP]		= IPPROTO_TCP,
	[FLOW_TCP_SPLICE]	= IPPROTO_TCP,
};
static_assert(ARRAY_SIZE(flow_proto) == FLOW_NUM_TYPES,
	      "flow_proto[] doesn't match enum flow_type");

/* Global Flow Table */

/**
 * DOC: Theory of Operation - allocating and freeing flow entries
 *
 * Flows are entries in flowtab[]. We need to routinely scan the whole table to
 * perform deferred bookkeeping tasks on active entries, and sparse empty slots
 * waste time and worsen data locality.  But, keeping the table fully compact by
 * moving entries on deletion is fiddly: it requires updating hash tables, and
 * the epoll references to flows. Instead, we implement the compromise described
 * below.
 *
 * Free clusters
 *    A "free cluster" is a contiguous set of unused (FLOW_TYPE_NONE) entries in
 *    flowtab[].  The first entry in each cluster contains metadata ('free'
 *    field in union flow), specifically the number of entries in the cluster
 *    (free.n), and the index of the next free cluster (free.next).  The entries
 *    in the cluster other than the first should have n == next == 0.
 *
 * Free cluster list
 *    flow_first_free gives the index of the first (lowest index) free cluster.
 *    Each free cluster has the index of the next free cluster, or MAX_FLOW if
 *    it is the last free cluster.  Together these form a linked list of free
 *    clusters, in strictly increasing order of index.
 *
 * Allocating
 *    We always allocate a new flow into the lowest available index, i.e. the
 *    first entry of the first free cluster, that is, at index flow_first_free.
 *    We update flow_first_free and the free cluster to maintain the invariants
 *    above (so the free cluster list is still in strictly increasing order).
 *
 * Freeing
 *    It's not possible to maintain the invariants above if we allow freeing of
 *    any entry at any time.  So we only allow freeing in two cases.
 *
 *    1) flow_alloc_cancel() will free the most recent allocation.  We can
 *    maintain the invariants because we know that allocation was made in the
 *    lowest available slot, and so will become the lowest index free slot again
 *    after cancellation.
 *
 *    2) Flows can be freed by returning true from the flow type specific
 *    deferred or timer function.  These are called from flow_defer_handler()
 *    which is already scanning the whole table in index order.  We can use that
 *    to rebuild the free cluster list correctly, either merging them into
 *    existing free clusters or creating new free clusters in the list for them.
 *
 * Scanning the table
 *    Theoretically, scanning the table requires FLOW_MAX iterations.  However,
 *    when we encounter the start of a free cluster, we can immediately skip
 *    past it, meaning that in practice we only need (number of active
 *    connections) + (number of free clusters) iterations.
 */

unsigned flow_first_free;
union flow flowtab[FLOW_MAX];

/* Last time the flow timers ran */
static struct timespec flow_timer_run;

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

/**
 * flow_alloc() - Allocate a new flow
 *
 * Return: pointer to an unused flow entry, or NULL if the table is full
 */
union flow *flow_alloc(void)
{
	union flow *flow = &flowtab[flow_first_free];

	if (flow_first_free >= FLOW_MAX)
		return NULL;

	ASSERT(flow->f.type == FLOW_TYPE_NONE);
	ASSERT(flow->free.n >= 1);
	ASSERT(flow_first_free + flow->free.n <= FLOW_MAX);

	if (flow->free.n > 1) {
		union flow *next;

		/* Use one entry from the cluster */
		ASSERT(flow_first_free <= FLOW_MAX - 2);
		next = &flowtab[++flow_first_free];

		ASSERT(FLOW_IDX(next) < FLOW_MAX);
		ASSERT(next->f.type == FLOW_TYPE_NONE);
		ASSERT(next->free.n == 0);

		next->free.n = flow->free.n - 1;
		next->free.next = flow->free.next;
	} else {
		/* Use the entire cluster */
		flow_first_free = flow->free.next;
	}

	memset(flow, 0, sizeof(*flow));
	return flow;
}

/**
 * flow_alloc_cancel() - Free a newly allocated flow
 * @flow:	Flow to deallocate
 *
 * @flow must be the last flow allocated by flow_alloc()
 */
void flow_alloc_cancel(union flow *flow)
{
	ASSERT(flow_first_free > FLOW_IDX(flow));

	flow->f.type = FLOW_TYPE_NONE;
	/* Put it back in a length 1 free cluster, don't attempt to fully
	 * reverse flow_alloc()s steps.  This will get folded together the next
	 * time flow_defer_handler runs anyway() */
	flow->free.n = 1;
	flow->free.next = flow_first_free;
	flow_first_free = FLOW_IDX(flow);
}

/**
 * flow_defer_handler() - Handler for per-flow deferred and timed tasks
 * @c:		Execution context
 * @now:	Current timestamp
 */
void flow_defer_handler(const struct ctx *c, const struct timespec *now)
{
	struct flow_free_cluster *free_head = NULL;
	unsigned *last_next = &flow_first_free;
	bool timer = false;
	unsigned idx;

	if (timespec_diff_ms(now, &flow_timer_run) >= FLOW_TIMER_INTERVAL) {
		timer = true;
		flow_timer_run = *now;
	}

	for (idx = 0; idx < FLOW_MAX; idx++) {
		union flow *flow = &flowtab[idx];
		bool closed = false;

		if (flow->f.type == FLOW_TYPE_NONE) {
			unsigned skip = flow->free.n;

			/* First entry of a free cluster must have n >= 1 */
			ASSERT(skip);

			if (free_head) {
				/* Merge into preceding free cluster */
				free_head->n += flow->free.n;
				flow->free.n = flow->free.next = 0;
			} else {
				/* New free cluster, add to chain */
				free_head = &flow->free;
				*last_next = idx;
				last_next = &free_head->next;
			}

			/* Skip remaining empty entries */
			idx += skip - 1;
			continue;
		}

		switch (flow->f.type) {
		case FLOW_TYPE_NONE:
			ASSERT(false);
			break;
		case FLOW_TCP:
			closed = tcp_flow_defer(flow);
			break;
		case FLOW_TCP_SPLICE:
			closed = tcp_splice_flow_defer(flow);
			if (!closed && timer)
				tcp_splice_timer(c, flow);
			break;
		default:
			/* Assume other flow types don't need any handling */
			;
		}

		if (closed) {
			flow->f.type = FLOW_TYPE_NONE;

			if (free_head) {
				/* Add slot to current free cluster */
				ASSERT(idx == FLOW_IDX(free_head) + free_head->n);
				free_head->n++;
				flow->free.n = flow->free.next = 0;
			} else {
				/* Create new free cluster */
				free_head = &flow->free;
				free_head->n = 1;
				*last_next = idx;
				last_next = &free_head->next;
			}
		} else {
			free_head = NULL;
		}
	}

	*last_next = FLOW_MAX;
}

/**
 * flow_init() - Initialise flow related data structures
 */
void flow_init(void)
{
	/* Initial state is a single free cluster containing the whole table */
	flowtab[0].free.n = FLOW_MAX;
	flowtab[0].free.next = FLOW_MAX;
}
