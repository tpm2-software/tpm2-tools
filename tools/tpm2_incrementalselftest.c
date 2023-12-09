/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

typedef struct tpm_incrementalselftest_ctx tpm_incrementalselftest_ctx;

struct tpm_incrementalselftest_ctx {
    TPML_ALG inputalgs;
};

static tpm_incrementalselftest_ctx ctx;

static tool_rc do_tpm_incrementalselftest(ESYS_CONTEXT *ectx, tpm2_yaml *doc) {

    TPML_ALG *to_do_list = NULL;
    tool_rc rc = tpm2_incrementalselftest(ectx, &(ctx.inputalgs), &to_do_list);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_yaml_tpm_alg_todo(doc, to_do_list);
    free(to_do_list);
    return rc;
}

static bool on_arg(int argc, char **argv) {
    int i;
    TPM2_ALG_ID algorithm;

    LOG_INFO("tocheck :");

    for (i = 0; i < argc; i++) {
        algorithm = tpm2_alg_util_from_optarg(argv[i], tpm2_alg_util_flags_any);

        if (algorithm == TPM2_ALG_ERROR) {
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

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_yaml *doc, tpm2_option_flags flags) {

    UNUSED(flags);

    return do_tpm_incrementalselftest(ectx, doc);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("incrementalselftest", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
