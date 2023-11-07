/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Passt/pasta interface types and IDs
 */
#ifndef PIF_H
#define PIF_H

/**
 * enum pif_type - Type of passt/pasta interface ("pif")
 *
 * pifs can be an L4 level channel (sockets) or an L2 level channel (tap device
 * or qemu socket).
 */
enum pif_type {
	/* Invalid or not present pif */
	PIF_NONE = 0,
	/* Host socket interface */
	PIF_HOST,
	/* Qemu socket or namespace tuntap interface */
	PIF_TAP,
	/* Namespace socket interface for splicing */
	PIF_SPLICE,
};

#endif /* PIF_H */
