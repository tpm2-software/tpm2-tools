/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <tss2/tss2_esys.h>

#include "tpm2_options.h"
#include "log.h"
#include "files.h"
#include "tpm2_capability.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_random_ctx tpm_random_ctx;
struct tpm_random_ctx {
    bool output_file_specified;
    char *output_file;
    UINT16 num_of_bytes;
    bool force;
};

static tpm_random_ctx ctx;

static tool_rc get_random_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST *random_bytes;

    TSS2_RC rval = Esys_GetRandom(ectx,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ctx.num_of_bytes, &random_bytes);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetRandom, rval);
        return tool_rc_from_tpm(rval);
    }

    /* ensure we got the expected number of bytes unless force is set */
    if (!ctx.force && random_bytes->size != ctx.num_of_bytes) {
        LOG_ERR("Got %"PRIu16" bytes, expected: %"PRIu16"\n"
                "Lower your requested amount or"
                " use --force to override this behavior", random_bytes->size,
                ctx.num_of_bytes);
        return tool_rc_general_error;
    }

    if (!ctx.output_file_specified) {
        UINT16 i;
        for (i = 0; i < random_bytes->size; i++) {
            tpm2_tool_output("%s0x%2.2X", i ? " " : "", random_bytes->buffer[i]);
        }
        tpm2_tool_output("\n");
        free(random_bytes);
        return tool_rc_success;
    }

    rval = files_save_bytes_to_file(ctx.output_file, random_bytes->buffer,
            random_bytes->size);
    if (!rval) {
        LOG_ERR("Failed to save bytes into file \"%s\"", ctx.output_file);
        free(random_bytes);
        return tool_rc_general_error;
    }

    free(random_bytes);
    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    UNUSED(key);

    switch (key) {
    case 'f':
        ctx.force = true;
        break;
    case 'o':
        ctx.output_file_specified = true;
        ctx.output_file = value;
        break;
        /* no default */
    }

    return true;
}

static bool get_max_random(ESYS_CONTEXT *ectx, UINT32 *value) {

    TPMS_CAPABILITY_DATA *cap_data = NULL;
    bool res = tpm2_capability_get (ectx,
            TPM2_CAP_TPM_PROPERTIES,
            TPM2_PT_FIXED,
            TPM2_MAX_TPM_PROPERTIES,
            &cap_data);
    if (!res) {
        return false;
    }

    UINT32 i;
    for (i=0; i < cap_data->data.tpmProperties.count; i++) {
        TPMS_TAGGED_PROPERTY *p = &cap_data->data.tpmProperties.tpmProperty[i];
        if (p->property == TPM2_PT_MAX_DIGEST) {
            *value = p->value;
            free(cap_data);
            return true;
        }
    }

    LOG_ERR("TPM does not have property TPM2_PT_MAX_DIGEST");
    free(cap_data);
    return false;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one SIZE octets, got: %d", argc);
        return false;
    }

    bool result = tpm2_util_string_to_uint16(argv[0], &ctx.num_of_bytes);
    if (!result) {
        LOG_ERR("Error converting size to a number, got: \"%s\".",
                argv[0]);
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "out-file",   required_argument, NULL, 'o' },
        { "force",      required_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("o:f", ARRAY_LEN(topts), topts, on_option, on_args,
                             0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

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
        bool res = get_max_random(ectx, &max);
        if (!res) {
            return tool_rc_general_error;
        }

        if (ctx.num_of_bytes > max) {
            LOG_ERR ("TPM getrandom is bounded by max hash size, which is: "
                    "%"PRIu32"\n"
                    "Please lower your request (preferred) and try again or"
                    " use --force (advanced)", max);
            return tool_rc_general_error;
        }
    }

    return get_random_and_save(ectx);
}
