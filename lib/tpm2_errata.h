//**********************************************************************;
// Copyright (c) 2017, Alibaba Group
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
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
