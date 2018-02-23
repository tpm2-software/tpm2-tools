//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_hierarchy.h"
#include "tpm2_util.h"

/**
 * Parses a hierarchy value from an option argument.
 * @param value
 *  The string to parse, which can be a numerical string as
 *  understood by strtoul() with a base of 0, or an:
 *    - o - Owner hierarchy
 *    - p - Platform hierarchy
 *    - e - Endorsement hierarchy
 *    - n - Null hierarchy
 * @param hierarchy
 *  The parsed hierarchy as output.
 * @param flags
 *  What hierarchies should be supported by
 *  the parsing.
 * @return
 *  True on success, False otherwise.
 */
bool tpm2_hierarchy_from_optarg(const char *value,
        TPMI_RH_PROVISION *hierarchy, tpm2_hierarchy_flags flags) {

    if (!value) {
        return false;
    }

    bool is_o = !strcmp(value, "o");
    if (is_o) {
        if (!(flags & TPM2_HIERARCHY_FLAGS_O)) {
            LOG_ERR("Owner hierarchy not supported by this command.");
            return false;
        }
        *hierarchy = TPM2_RH_OWNER;
        return true;
    }

    bool is_p = !strcmp(value, "p");
    if (is_p) {
        if (!(flags & TPM2_HIERARCHY_FLAGS_P)) {
            LOG_ERR("Platform hierarchy not supported by this command.");
            return false;
        }
        *hierarchy = TPM2_RH_PLATFORM;
        return true;
    }

    bool is_e = !strcmp(value, "e");
    if (is_e) {
        if (!(flags & TPM2_HIERARCHY_FLAGS_E)) {
            LOG_ERR("Endorsement hierarchy not supported by this command.");
            return false;
        }
        *hierarchy = TPM2_RH_ENDORSEMENT;
        return true;
    }

    bool is_n = !strcmp(value, "n");
    if (is_n) {
        if (!(flags & TPM2_HIERARCHY_FLAGS_N)) {
            LOG_ERR("NULL hierarchy not supported by this command.");
            return false;
        }
        *hierarchy = TPM2_RH_NULL;
        return true;
    }

    bool result = tpm2_util_string_to_uint32(value, hierarchy);
    if (!result) {
        LOG_ERR("Incorrect hierarchy value, got: \"%s\", expected [o|p|e|n]"
                "or a number",
            value);
    }

    return result;
}

bool tpm2_hierarrchy_create_primary(TSS2_SYS_CONTEXT *sapi_context,
        TPMS_AUTH_COMMAND *sdata,
        tpm2_hierearchy_pdata *objdata) {

    TSS2L_SYS_AUTH_COMMAND sessionsData =
            TSS2L_SYS_AUTH_COMMAND_INIT(1, {*sdata});

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2_RC rval = TSS2_RETRY_EXP(
            Tss2_Sys_CreatePrimary(sapi_context, objdata->in.hierarchy,
                &sessionsData, &objdata->in.sensitive, &objdata->in.public,
                &objdata->in.outside_info, &objdata->in.creation_pcr,
                &objdata->out.handle, &objdata->out.public,
                &objdata->out.creation.data, &objdata->out.hash,
                &objdata->out.creation.ticket, &objdata->out.name,
                &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_CreatePrimary, rval);
        return false;
    }

    return true;
}
