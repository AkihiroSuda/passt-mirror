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

#endif /* FLOW_TABLE_H */
