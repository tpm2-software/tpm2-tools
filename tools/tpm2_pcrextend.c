//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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

#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
struct tpm_pcr_extend_ctx {
    size_t digest_spec_len;
    tpm2_pcr_digest_spec *digest_spec;
};

static tpm_pcr_extend_ctx ctx;

static bool pcr_extend_one(ESYS_CONTEXT *ectx,
        TPMI_DH_PCR pcr_index, TPML_DIGEST_VALUES *digests) {;

    TSS2_RC rval = Esys_PCR_Extend(ectx, pcr_index,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            digests);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Could not extend pcr index: 0x%X", pcr_index);
        LOG_PERR(Esys_PCR_Extend, rval);
        return false;
    }

    return true;
}

static bool pcr_extend(ESYS_CONTEXT *ectx) {

    size_t i;
    for (i = 0; i < ctx.digest_spec_len; i++) {
        tpm2_pcr_digest_spec *dspec = &ctx.digest_spec[i];
        bool result = pcr_extend_one(ectx, dspec->pcr_index,
                &dspec->digests);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc < 1) {
        LOG_ERR("Expected at least one PCR Digest specification,"
                "ie: <pcr index>:<hash alg>=<hash value>, got: 0");
        return false;
    }

    /* this can never be negative */
    ctx.digest_spec_len = (size_t) argc;

    ctx.digest_spec = calloc(ctx.digest_spec_len, sizeof(*ctx.digest_spec));
    if (!ctx.digest_spec) {
        LOG_ERR("oom");
        return false;
    }

    return pcr_parse_digest_list(argv, ctx.digest_spec_len, ctx.digest_spec);
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return pcr_extend(ectx) != true;
}

void tpm2_tool_onexit(void) {

    free(ctx.digest_spec);
}
