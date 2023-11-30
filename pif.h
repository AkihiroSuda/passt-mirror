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

	PIF_NUM_TYPES,
};

#define PIF_NAMELEN	8

extern const char *pif_type_str[];

static inline const char *pif_type(enum pif_type pt)
{
	if (pt < PIF_NUM_TYPES)
		return pif_type_str[pt];
	else
		return "?";
}

static inline const char *pif_name(uint8_t pif)
{
	return pif_type(pif);
}

#endif /* PIF_H */
