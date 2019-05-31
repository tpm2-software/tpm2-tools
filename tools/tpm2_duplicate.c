/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct tpm_duplicate_ctx tpm_duplicate_ctx;
struct tpm_duplicate_ctx {
    struct {
        char *auth_str;
        tpm2_session *session;
        const char *object_arg;
        tpm2_loaded_object object;
    } object;

    char *duplicate_key_public_file;
    char *duplicate_key_private_file;

    TPMI_ALG_PUBLIC key_type;
    char *sym_key_in;
    char *sym_key_out;

    char *enc_seed_out;

    const char *new_parent_object_arg;
    tpm2_loaded_object new_parent_object_context;

    struct {
        UINT16 c : 1;
        UINT16 C : 1;
        UINT16 g : 1;
        UINT16 i : 1;
        UINT16 o : 1;
        UINT16 r : 1;
        UINT16 s : 1;
    } flags;

};

static tpm_duplicate_ctx ctx = {
    .key_type = TPM2_ALG_ERROR,
};

static tool_rc do_duplicate(ESYS_CONTEXT *ectx,
        TPM2B_DATA *in_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_DATA **out_key,
        TPM2B_PRIVATE **duplicate,
        TPM2B_ENCRYPTED_SECRET **encrypted_seed) {

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.object.object.tr_handle,
                            ctx.object.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return tool_rc_general_error;
    }

    TSS2_RC rval = Esys_Duplicate(ectx,
                        ctx.object.object.tr_handle, ctx.new_parent_object_context.tr_handle,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        in_key, sym_alg, out_key, duplicate, encrypted_seed);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Duplicate, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'p':
        ctx.object.auth_str = value;
        break;
    case 'g':
        ctx.key_type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_symmetric
                |tpm2_alg_util_flags_misc);
        if (ctx.key_type != TPM2_ALG_ERROR) {
            ctx.flags.g = 1;
        }
        break;
    case 'i':
        ctx.sym_key_in = value;
        ctx.flags.i = 1;
        break;
    case 'o':
        ctx.sym_key_out = value;
        ctx.flags.o = 1;
        break;
    case 'C':
        ctx.new_parent_object_arg = value;
        ctx.flags.C = 1;
        break;
    case 'c':
        ctx.object.object_arg = value;
        ctx.flags.c = 1;
        break;
    case 'r':
        ctx.duplicate_key_private_file = value;
        ctx.flags.r = 1;
        break;
    case 's':
        ctx.enc_seed_out = value;
        ctx.flags.s = 1;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-key",              required_argument, NULL, 'p'},
      { "inner-wrapper-alg",     required_argument, NULL, 'g'},
      { "duplicate-key-private", required_argument, NULL, 'r'},
      { "input-key-file",        required_argument, NULL, 'i'},
      { "output-key-file",       required_argument, NULL, 'o'},
      { "output-enc-seed-file",  required_argument, NULL, 's'},
      { "parent-key",            required_argument, NULL, 'C'},
      { "context",               required_argument, NULL, 'c'},
    };

    *opts = tpm2_options_new("p:g:i:C:o:s:r:c:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  true on success, false on failure.
 */
static bool check_options(void) {

    bool result = true;

    /* Check for NULL alg & (keyin | keyout) */
    if (ctx.flags.g == 0) {
        LOG_ERR("Expected key type to be specified via \"-G\","
                " missing option.");
        result = false;
    }

    if (ctx.key_type != TPM2_ALG_NULL) {
        if((ctx.flags.i == 0) && (ctx.flags.o == 0)) {
            LOG_ERR("Expected in or out encryption key file \"-k/K\","
                    " missing option.");
            result = false;
        }
        if (ctx.flags.i && ctx.flags.o) {
            LOG_ERR("Expected either in or out encryption key file \"-k/K\","
                    " conflicting options.");
            result = false;
        }
    } else {
        if (ctx.flags.i || ctx.flags.o) {
            LOG_ERR("Expected neither in nor out encryption key file \"-k/K\","
                    " conflicting options.");
            result = false;
        }
    }

    if (ctx.flags.C == 0) {
        LOG_ERR("Expected new parent object to be specified via \"-C\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.c == 0) {
        LOG_ERR("Expected object to be specified via \"-c\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.s == 0) {
        LOG_ERR("Expected encrypted seed out filename to be specified via \"-S\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.r == 0) {
        LOG_ERR("Expected private key out filename to be specified via \"-r\","
                " missing option.");
        result = false;
    }

    return result;
}

static bool set_key_algorithm(TPMI_ALG_PUBLIC alg, TPMT_SYM_DEF_OBJECT * obj) {
    bool result = true;
    switch (alg) {
    case TPM2_ALG_AES :
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        break;
    case TPM2_ALG_NULL :
        obj->algorithm = TPM2_ALG_NULL;
        break;
    default:
        LOG_ERR("The algorithm type input(0x%x) is not supported!", alg);
        result = false;
        break;
    }
    return result;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    tool_rc rc = tool_rc_general_error;
    TPMT_SYM_DEF_OBJECT sym_alg;
    TPM2B_DATA in_key;
    TPM2B_DATA* out_key = NULL;
    TPM2B_PRIVATE* duplicate;
    TPM2B_ENCRYPTED_SECRET* outSymSeed;

    bool result = check_options();
    if (!result) {
        return tool_rc_general_error;
    }

    result = tpm2_util_object_load(ectx, ctx.object.object_arg,
		    &ctx.object.object);
    if(!result) {
        return tool_rc_general_error;
    }

    result = tpm2_util_object_load(ectx, ctx.new_parent_object_arg,
		    &ctx.new_parent_object_context);
    if(!result) {
        return tool_rc_general_error;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.object.auth_str,
        &ctx.object.session, false);
    if (!result) {
        LOG_ERR("Invalid authorization, got\"%s\"", ctx.object.auth_str);
        return tool_rc_general_error;
    }

    result = set_key_algorithm(ctx.key_type, &sym_alg);
    if(!result) {
        return tool_rc_general_error;
    }

    if(ctx.flags.i) {
        in_key.size = 16;
        result = files_load_bytes_from_path(ctx.sym_key_in, in_key.buffer, &in_key.size);
        if(!result) {
            return tool_rc_general_error;
        }
        if(in_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16", in_key.size);
            return tool_rc_general_error;
        }
    }

    rc = do_duplicate(ectx,
        ctx.flags.i ? &in_key : NULL,
        &sym_alg,
        ctx.flags.o ? &out_key : NULL,
        &duplicate,
        &outSymSeed);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Maybe a false positive from scan-build but we'll check out_key anyway */
    if (ctx.flags.o) {
        if(out_key == NULL) {
            LOG_ERR("No encryption key from TPM ");
            rc = tool_rc_general_error;
            goto out;
        }
        result = files_save_bytes_to_file(ctx.sym_key_out,
                    out_key->buffer, out_key->size);
        if (!result) {
            LOG_ERR("Failed to save encryption key out into file \"%s\"",
                    ctx.sym_key_out);
            rc = tool_rc_general_error;
            goto out;
        }
    }

    result = files_save_encrypted_seed(outSymSeed, ctx.enc_seed_out);
    if (!result) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.enc_seed_out);
        rc = tool_rc_general_error;
        goto out;
    }

    result = files_save_private(duplicate, ctx.duplicate_key_private_file);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.duplicate_key_private_file);
        rc = tool_rc_general_error;
        goto out;
    }

    rc = tool_rc_success;

out:
    free(out_key);
    free(outSymSeed);
    free(duplicate);

    return rc;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.object.session);
}
