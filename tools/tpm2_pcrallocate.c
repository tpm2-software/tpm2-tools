//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// Copyright (c) 2019, Fraunhofer SIT
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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

static struct {
    TPML_PCR_SELECTION pcrSelection;
    const char *platform_auth_str;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
} ctx = {
    .pcrSelection = {
        .count = 2,
        .pcrSelections = { {
            .hash = TPM2_ALG_SHA1,
            .sizeofSelect = 3,
            .pcrSelect = { 0xff, 0xff, 0xff, }
            }, {
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 0xff, 0xff, 0xff, }
        }, }
    },
};

static bool pcr_allocate(ESYS_CONTEXT *ectx) {
    TSS2_RC rval;
    TPMI_YES_NO allocationSuccess;
    UINT32 maxPCR;
    UINT32 sizeNeeded;
    UINT32 sizeAvailable;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_PLATFORM,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for lockout hierarchy");
        return false;
    }

    pcr_print_pcr_selections(&ctx.pcrSelection);

    rval = Esys_PCR_Allocate(ectx, ESYS_TR_RH_PLATFORM, 
                             shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                             &ctx.pcrSelection, &allocationSuccess,
                             &maxPCR, &sizeNeeded, &sizeAvailable);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Could not allocate PCRs.");
        LOG_PERR(Esys_PCR_Allocate, rval);
        return false;
    }

    if (!allocationSuccess) {
        LOG_ERR("Allocation failed. "
                "MaxPCR: %i, Size Needed: %i, Size available: %i",
                maxPCR, sizeNeeded, sizeAvailable);
        return false;
    }

    return true;
}

static bool on_arg(int argc, char **argv){
    if (argc > 1) {
        LOG_ERR("Too many arguments");
        return false;
    }

    if(argc == 1 && !pcr_parse_selections(argv[0], &ctx.pcrSelection))
    {
        LOG_ERR("Could not parse pcr selections");
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {
    switch (key) {
    case 'P':
        ctx.platform_auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {
    const struct option topts[] = {
        { "auth-platform",     required_argument, NULL, 'P' },
    };
 
    *opts = tpm2_options_new("P:", ARRAY_LEN(topts), topts, on_option, on_arg,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);
    bool result;

    if (ctx.platform_auth_str) {
        if (!tpm2_auth_util_from_optarg(ectx, ctx.platform_auth_str,
                &ctx.auth.session_data, &ctx.auth.session)) {
            LOG_ERR("Invalid platform authorization format");
            return 1;
        }
    }
    
    result = pcr_allocate(ectx);

    if (!tpm2_session_save(ectx, ctx.auth.session, NULL)) {
        LOG_ERR("Error saving sessions after command execution");
        return 1;
    }

    return (result == true)? 0 : 1;
}

void tpm2_tool_onexit(void) {
    tpm2_session_free(&ctx.auth.session);
}
