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
};

static tpm_incrementalselftest_ctx ctx;

static tool_rc tpm_incrementalselftest(ESYS_CONTEXT *ectx) {

    TPML_ALG *totest = NULL;
    TSS2_RC rval = Esys_IncrementalSelfTest(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &(ctx.inputalgs), &totest);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SelfTest, rval);
        return tool_rc_from_tpm(rval);
    }

    tpm2_tool_output("status: ");
    print_yaml_indent(1);

    if(totest->count == 0){
        tpm2_tool_output("complete\n");
    } else {
        tpm2_tool_output("success\n");

        tpm2_tool_output("remaining:\n");

        uint32_t i;
        for(i = 0; i < totest->count; i++){
            print_yaml_indent(1);
            tpm2_tool_output("%s",
                    tpm2_alg_util_algtostr(totest->algorithms[i],
                            tpm2_alg_util_flags_any));
            tpm2_tool_output("\n");
        }
    }

    free(totest);
    return tool_rc_success;
}

static bool on_arg(int argc, char **argv){
    int i;
    TPM2_ALG_ID algorithm;

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

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return tpm_incrementalselftest(ectx);
}
