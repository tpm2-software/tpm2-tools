/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_ERRATA_H
#define TPM2_ERRATA_H

#include <tss2/tss2_esys.h>
#include <stdbool.h>

/*
 * Errata index pattern:
 *   spec version + the section number in the errata doc
 *
 * Note that it is unnecessary to describe errata version
 * because the section number should be kept consistent
 * across all errata versions for a specific spec revision.
 */
typedef enum {
    SPEC_116_ERRATA_2_7,
} tpm2_errata_index_t;

/**
 * Initialize errata subsystem
 *
 * @param ctx
 *  ESAPI context to be queried.
 */
void tpm2_errata_init(ESYS_CONTEXT *ctx);

/**
 * Request an errata correction for a specific errata version.
 * @param index
 *  the errata to be queried.
 *
 * This function requests an errata correction to work
 * around a known issue well documented in errata doc.
 * If the request is valid and known, the queried errata
 * will be applied by the corresponding pre-defined errata
 * correction handler. The fixup process is transparent to
 * the callers so there is no return values. Any tools can
 * call this function to apply an errata if necessary.
 */
void tpm2_errata_fixup(tpm2_errata_index_t index, ...);

#endif /* TPM2_ERRATA_H */
