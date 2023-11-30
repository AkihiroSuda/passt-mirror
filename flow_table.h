/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions for the global table of packet flows.
 */
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

/**
 * union flow - Descriptor for a logical packet flow (e.g. connection)
 * @f:		Fields common between all variants
 * @tcp:	Fields for non-spliced TCP connections
 * @tcp_splice:	Fields for spliced TCP connections
*/
union flow {
	struct flow_common f;
	struct tcp_tap_conn tcp;
	struct tcp_splice_conn tcp_splice;
};

/* Global Flow Table */
extern union flow flowtab[];


/** flow_idx - Index of flow from common structure
 * @f:	Common flow fields pointer
 *
 * Return: index of @f in the flow table
 */
static inline unsigned flow_idx(const struct flow_common *f)
{
	return (union flow *)f - flowtab;
}

/** FLOW_IDX - Find the index of a flow
 * @f_:	Flow pointer, either union flow * or protocol specific
 *
 * Return: index of @f in the flow table
 */
#define FLOW_IDX(f_)		(flow_idx(&(f_)->f))

/** FLOW - Flow entry at a given index
 * @idx:	Flow index
 *
 * Return: pointer to entry @idx in the flow table
 */
#define FLOW(idx)		(&flowtab[(idx)])

#endif /* FLOW_TABLE_H */
