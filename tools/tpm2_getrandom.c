/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_capability.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

typedef struct tpm_random_ctx tpm_random_ctx;
#define MAX_AUX_SESSIONS 3
#define MAX_SESSIONS 3
struct tpm_random_ctx {
    /*
     * Input options
     */
    UINT16 num_of_bytes;
    bool force;
    bool hex;

    /*
     * Outputs
     */
    char *output_file;
    TPM2B_DIGEST *random_bytes;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    TPMI_ALG_HASH parameter_hash_algorithm;
    bool is_command_dispatch;

    /*
     * Aux Sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_random_ctx ctx = {
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
    .aux_session_handle[2] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc get_random(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    tool_rc rc = tpm2_getrandom(ectx, ctx.num_of_bytes, &ctx.random_bytes,
        &ctx.cp_hash, &ctx.rp_hash, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1], ctx.aux_session_handle[2],
        ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed getrandom");
    }

    return rc;
}

static tool_rc process_outputs(void) {

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    /* ensure we got the expected number of bytes unless force is set */
    tool_rc rc = tool_rc_success;
    if (!ctx.force && ctx.random_bytes->size != ctx.num_of_bytes) {
        LOG_ERR("Got %"PRIu16" bytes, expected: %"PRIu16"\n"
                "Lower your requested amount or"
                " use --force to override this behavior",
                ctx.random_bytes->size, ctx.num_of_bytes);
        rc = tool_rc_general_error;
        goto out_skip_output_file;
    }

    /*
     * Either open an output file, or if stdout, do nothing as -Q
     * was specified.
     */
    FILE *out = stdout;
    if (ctx.output_file) {
        out = fopen(ctx.output_file, "wb+");
        if (!out) {
            LOG_ERR("Could not open output file \"%s\", error: %s",
                    ctx.output_file, strerror(errno));
            rc = tool_rc_general_error;
            goto out;
        }
    } else if (!output_enabled) {
        goto out;
    }

    if (ctx.hex) {
        tpm2_util_print_tpm2b2(out, ctx.random_bytes);
        goto out;
    }

    is_file_op_success = files_write_bytes(out, ctx.random_bytes->buffer,
        ctx.random_bytes->size);
    if (!is_file_op_success) {
        rc = tool_rc_general_error;
        goto out;
    }

    if(ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
        if (!is_file_op_success) {
            rc = tool_rc_general_error;
        }
    }

out:
    if (out && out != stdout) {
        fclose(out);
    }

out_skip_output_file:
    if (!ctx.cp_hash_path) {
        free(ctx.random_bytes);
    }

    return rc;
}

static tool_rc get_max_random(ESYS_CONTEXT *ectx, UINT32 *value) {

    TPMS_CAPABILITY_DATA *cap_data = NULL;
    tool_rc rc = tpm2_capability_get(ectx, TPM2_CAP_TPM_PROPERTIES,
            TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES, &cap_data);
    if (rc != tool_rc_success) {
        return rc;
    }

    UINT32 i;
    for (i = 0; i < cap_data->data.tpmProperties.count; i++) {
        TPMS_TAGGED_PROPERTY *p = &cap_data->data.tpmProperties.tpmProperty[i];
        if (p->property == TPM2_PT_MAX_DIGEST) {
            *value = p->value;
            free(cap_data);
            return tool_rc_success;
        }
    }

    LOG_ERR("TPM does not have property TPM2_PT_MAX_DIGEST");
    free(cap_data);

    return tool_rc_general_error;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     * Note: Old-auth value is ignored when calculating cpHash.
     */

    /*
     * 2. Restore auxiliary sessions
     */
    tool_rc rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Command specific initializations
     */

    /*
     * Error if bytes requested is bigger than max hash size, which is what TPMs
     * should bound their requests by and always have available per the spec.
     *
     * Per 16.1 of:
     *  - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
     *
     *  Allow the force flag to override this behavior.
     */
    if (!ctx.force) {
        UINT32 max = 0;
        rc = get_max_random(ectx, &max);
        if (rc != tool_rc_success) {
            return rc;
        }

        if (ctx.num_of_bytes > max) {
            LOG_ERR("TPM getrandom is bounded by max hash size, which is: "
                    "%"PRIu32"\n"
                    "Please lower your request (preferred) and try again or"
                    " use --force (advanced)", max);
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.aux_session[0],
        ctx.aux_session[1],
        ctx.aux_session[2]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);


    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return rc;
}

static bool on_option(char key, char *value) {

    UNUSED(key);

    switch (key) {
    case 'f':
        ctx.force = true;
        break;
    case 'o':
        ctx.output_file = value;
        break;
    case 0:
        ctx.hex = true;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 2:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
        /* no default */
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one SIZE octets, got: %d", argc);
        return false;
    }

    bool result = tpm2_util_string_to_uint16(argv[0], &ctx.num_of_bytes);
    if (!result) {
        LOG_ERR("Error converting size to a number, got: \"%s\".", argv[0]);
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "output",       required_argument, NULL, 'o' },
        { "force",        required_argument, NULL, 'f' },
        { "hex",          no_argument,       NULL,  0  },
        { "session",      required_argument, NULL, 'S' },
        { "cphash",       required_argument, NULL,  1  },
        { "rphash",       required_argument, NULL,  2  }
    };

    *opts = tpm2_options_new("S:o:f", ARRAY_LEN(topts), topts, on_option, on_args,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */

    /*
     * 2. Process inputs
     */
    tool_rc rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = get_random(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs();
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tool_rc_success;
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
        }
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getrandom", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
