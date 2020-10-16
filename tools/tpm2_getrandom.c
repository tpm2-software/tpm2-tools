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

typedef struct tpm_random_ctx tpm_random_ctx;
struct tpm_random_ctx {
    char *output_file;
    UINT16 num_of_bytes;
    bool force;
    bool hex;
    tpm2_session *audit_session;
    const char *audit_session_path;
    const char *cp_hash_path;
    const char *rp_hash_path;
};

static tpm_random_ctx ctx;

static tool_rc get_random_and_save(ESYS_CONTEXT *ectx) {

    ESYS_TR audit_session_handle = ESYS_TR_NONE;
    TPMI_ALG_HASH param_hash_algorithm = TPM2_ALG_SHA256;
    if (ctx.audit_session_path) {
            tool_rc rc = tpm2_session_restore(ectx, ctx.audit_session_path,
            false, &ctx.audit_session);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not restore audit session");
            return rc;
        }
        audit_session_handle = tpm2_session_get_handle(ctx.audit_session);
        param_hash_algorithm = tpm2_session_get_authhash(ctx.audit_session);
    }

    TPM2B_DIGEST *cp_hash =
        ctx.cp_hash_path ? calloc(1, sizeof(TPM2B_DIGEST)): NULL;
    TPM2B_DIGEST *rp_hash =
        ctx.rp_hash_path ? calloc(1, sizeof(TPM2B_DIGEST)) : NULL;
    TPM2B_DIGEST *random_bytes;
    tool_rc rc = tpm2_getrandom(ectx, ctx.num_of_bytes, &random_bytes,
    cp_hash, rp_hash, audit_session_handle, param_hash_algorithm);
    if (rc != tool_rc_success) {
        goto out_skip_output_file;
    }

    if (ctx.cp_hash_path) {
        bool result = files_save_digest(cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        if (!ctx.rp_hash_path) {
            goto out_skip_output_file;
        }
    }

    /* ensure we got the expected number of bytes unless force is set */
    if (!ctx.force && random_bytes->size != ctx.num_of_bytes) {
        LOG_ERR("Got %"PRIu16" bytes, expected: %"PRIu16"\n"
                "Lower your requested amount or"
                " use --force to override this behavior",
                random_bytes->size, ctx.num_of_bytes);
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
        tpm2_util_print_tpm2b2(out, random_bytes);
        goto out;
    }

    bool result = files_write_bytes(out, random_bytes->buffer,
    random_bytes->size);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    if (ctx.rp_hash_path) {
        bool result = files_save_digest(rp_hash, ctx.rp_hash_path);
        rc = result ? tool_rc_success : tool_rc_general_error;
    }

out:
    if (out && out != stdout) {
        fclose(out);
    }

out_skip_output_file:
    if (ctx.rp_hash_path || !ctx.cp_hash_path) {
        free(random_bytes);
    }
    free(cp_hash);
    free(rp_hash);

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
        ctx.audit_session_path = value;
        break;
        /* no default */
    }

    return true;
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
        tool_rc rc = get_max_random(ectx, &max);
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

    return get_random_and_save(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    if (ctx.audit_session_path) {
        return tpm2_session_close(&ctx.audit_session);
    }
    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getrandom", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
