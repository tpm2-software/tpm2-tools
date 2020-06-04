/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_hash.h"
#include "tpm2_hierarchy.h"
#include "tpm2_tool.h"

typedef struct tpm_hash_ctx tpm_hash_ctx;
struct tpm_hash_ctx {
    TPMI_RH_HIERARCHY hierarchy_value;
    FILE *input_file;
    TPMI_ALG_HASH halg;
    char *output_hash_path;
    char *output_ticket_path;
    bool hex;
};

static tpm_hash_ctx ctx = {
    .hierarchy_value = TPM2_RH_OWNER,
    .halg = TPM2_ALG_SHA1,
};

static tool_rc hash_and_save(ESYS_CONTEXT *context) {

    TPM2B_DIGEST *out_hash;
    TPMT_TK_HASHCHECK *validation;

    FILE *out = stdout;

    tool_rc rc = tpm2_hash_file(context, ctx.halg, ctx.hierarchy_value,
            ctx.input_file, &out_hash, &validation);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.output_ticket_path) {
        bool res = files_save_validation(validation, ctx.output_ticket_path);
        if (!res) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    rc = tool_rc_general_error;
    if (ctx.output_hash_path) {
        out = fopen(ctx.output_hash_path, "wb+");
        if (!out) {
            LOG_ERR("Could not open output file \"%s\", error: %s",
                    ctx.output_hash_path, strerror(errno));
            goto out;
        }
    } else if (!output_enabled) {
        rc = tool_rc_success;
        goto out;
    }

    if (ctx.hex) {
        tpm2_util_print_tpm2b2(out, out_hash);
    } else {

        bool res = files_write_bytes(out, out_hash->buffer, out_hash->size);
        if (!res) {
            goto out;
        }
    }

    rc = tool_rc_success;

out:
    if (out && out != stdout) {
        fclose(out);
    }

    free(out_hash);
    free(validation);

    return rc;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one hash input file, got: %d", argc);
        return false;
    }

    ctx.input_file = fopen(argv[0], "rb");
    if (!ctx.input_file) {
        LOG_ERR("Could not open input file \"%s\", error: %s", argv[0],
                strerror(errno));
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool res;
    switch (key) {
    case 'C':
        res = tpm2_util_handle_from_optarg(value, &ctx.hierarchy_value,
                TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
        if (!res) {
            return false;
        }
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            return false;
        }
        break;
    case 'o':
        ctx.output_hash_path = value;
        break;
    case 't':
        ctx.output_ticket_path = value;
        break;
    case 0:
        ctx.hex = true;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        {"hierarchy",      required_argument, NULL, 'C'},
        {"hash-algorithm", required_argument, NULL, 'g'},
        {"output",         required_argument, NULL, 'o'},
        {"ticket",         required_argument, NULL, 't'},
        {"hex",            no_argument,       NULL,  0 },
    };

    /* set up non-static defaults here */
    ctx.input_file = stdin;

    *opts = tpm2_options_new("C:g:o:t:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    return hash_and_save(context);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *context) {
    UNUSED(context);

    if (ctx.input_file) {
        fclose(ctx.input_file);
    }

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("hash", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
