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

typedef struct tpm_incrementalselftest_ctx tpm_incrementalselftest_ctx;

struct tpm_incrementalselftest_ctx {
    TPML_ALG    inputalgs;
    TPML_ALG*   totest;
    bool        isempty;
};

static tpm_incrementalselftest_ctx ctx;

static bool tpm_incrementalselftest(ESYS_CONTEXT *ectx) {
    TSS2_RC rval = Esys_IncrementalSelfTest(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &(ctx.inputalgs), &(ctx.totest));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SelfTest, rval);
        return false;
    }

    tpm2_tool_output("status: ");
    print_yaml_indent(1);

    /*
    * According to TSS2 ESAPI, toTest is callee-allocated and 
    * might be empty but not NULL
    */
    if(ctx.totest == NULL){
        tpm2_tool_output("error\n");
        return false;
    }

    if(ctx.totest->count == 0){
        tpm2_tool_output("all tested\n");
        free(ctx.totest);
        return true;
    }
    tpm2_tool_output("success\n");
    tpm2_tool_output("remaining:\n");

    uint32_t i;
    for(i = 0; i < ctx.totest->count; i++){
        print_yaml_indent(1);
        tpm2_tool_output("%s", tpm2_alg_util_algtostr(ctx.totest->algorithms[i], tpm2_alg_util_flags_any));
        tpm2_tool_output("\n");
    }

    free(ctx.totest);

    return true;
}

static bool on_arg(int argc, char **argv){
    int i;
    TPM2_ALG_ID algorithm;

    ctx.isempty = false;

    LOG_INFO("tocheck :");

    for(i = 0; i < argc; i++){
        algorithm = tpm2_alg_util_from_optarg(argv[i], tpm2_alg_util_flags_any);

        if(algorithm == TPM2_ALG_ERROR){
            LOG_INFO("\n");
            LOG_ERR("Got invalid or unsupported algorithm: \"%s\"", argv[i]);
            return false;
        }

        ctx.inputalgs.algorithms[i] = algorithm;
        ctx.inputalgs.count += 1;
        LOG_INFO("  - %s", argv[i]);
    }
    LOG_INFO("\n");
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    ctx.isempty = true;

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return tpm_incrementalselftest(ectx) != true;
}
