/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_GUARD_NDPI_COMPAT72_H
#define DS_GUARD_NDPI_COMPAT72_H
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
#include <linux/string.h>
/* Linux 7.2 removed strncpy(). nDPI also uses it for bounded packet slices,
 * which must not lose their last byte as strscpy() would. Preserve its exact
 * bounded-copy/zero-padding semantics using the kernel's checked primitives.
 * This does not disable FORTIFY or change any destination capacity. */
static __always_inline char *ndpi_compat_strncpy(char *dest, const char *src, size_t count)
{
    size_t copied = strnlen(src, count);
    memcpy(dest, src, copied);
    if (copied < count)
        memset(dest + copied, 0, count - copied);
    return dest;
}
#define strncpy(dest, src, count) ndpi_compat_strncpy((dest), (src), (count))
#endif
#endif
