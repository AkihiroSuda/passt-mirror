/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Passt/pasta interface types and IDs
 */

#include <stdint.h>
#include <assert.h>

#include "util.h"
#include "pif.h"

const char *pif_type_str[] = {
	[PIF_NONE]		= "<none>",
	[PIF_HOST]		= "HOST",
	[PIF_TAP]		= "TAP",
	[PIF_SPLICE]		= "SPLICE",
};
static_assert(ARRAY_SIZE(pif_type_str) == PIF_NUM_TYPES,
	      "pif_type_str[] doesn't match enum pif_type");
