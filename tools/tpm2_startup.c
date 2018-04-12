/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

/*
 * Both the Microsoft and IBM TPM2 simulators require some specific setup
 * before they can be used by the SAPI. This setup is specific to the
 * simulators and is something that the low-level hardware / firmware does
 * for a discrete TPM.
 * NOTE: In the code that interacts with a TPM this can be a very ugly
 * abstraction leak.
 */
typedef struct tpm2_startup_ctx tpm2_startup_ctx;
struct tpm2_startup_ctx {
    UINT8 clear : 1;
};

static tpm2_startup_ctx ctx;

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
    case 'c':
        ctx.clear = 1;
        break;
        /*no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts [] = {
        { "clear", no_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("c", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    TPM2_SU startup_type = ctx.clear ? TPM2_SU_CLEAR : TPM2_SU_STATE;

    LOG_INFO ("Sending TPM_Startup command with type: %s",
            ctx.clear ? "TPM2_SU_CLEAR" : "TPM2_SU_STATE");

    TSS2_RC rval = Esys_Startup (context, startup_type);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_Startup, rval);
        return 1;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rval);
    return 0;
}
