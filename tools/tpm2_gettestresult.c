/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"

typedef struct tpm_gettestresult_ctx tpm_gettestresult_ctx;

struct tpm_gettestresult_ctx {
    TPM2B_MAX_BUFFER*    output;
    TPM2_RC              status;
};

static tpm_gettestresult_ctx ctx;

static int tpm_gettestresult(ESYS_CONTEXT *ectx) {
    TSS2_RC rval = Esys_GetTestResult(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &(ctx.output), &(ctx.status));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SelfTest, rval);
        return 3;
    }
    int retcode;

    tpm2_tool_output("status: ");
    print_yaml_indent(1);
    if(ctx.status){
        if((ctx.status & TPM2_RC_TESTING) == TPM2_RC_TESTING) {
            tpm2_tool_output("testing");
            retcode = 2;
        } else {
            tpm2_tool_output("failed");
            retcode = 1;
        }
    } else {
        tpm2_tool_output("success");
        retcode = 0;
    }

    if(ctx.output->size > 0){
        tpm2_tool_output("\ndata: ");
        print_yaml_indent(1);
        tpm2_util_hexdump(ctx.output->buffer, ctx.output->size);
    }
    tpm2_tool_output("\n");

    free(ctx.output);

    return retcode;
}

static bool on_arg(int argc, char **argv){
    UNUSED(argv);
    if (argc > 0) {
        LOG_ERR("No argument expected, got: %d", argc);
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {
    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);
    return tpm_gettestresult(ectx);
}

