/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"

typedef struct tpm_sign_ctx tpm_sign_ctx;
struct tpm_sign_ctx {
    TPMT_TK_HASHCHECK validation;
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPMT_SIG_SCHEME in_scheme;
    TPM2B_DIGEST *digest;
    char *outFilePath;
    BYTE *msg;
    UINT16 length;
    char *inMsgFileName;
    tpm2_convert_sig_fmt sig_format;

    struct {
        UINT8 m : 1;
        UINT8 t : 1;
        UINT8 o : 1;
        UINT8 D : 1;
    } flags;
};

static tpm_sign_ctx ctx = {
        .halg = TPM2_ALG_SHA1,
        .digest = NULL,
        .sig_scheme = TPM2_ALG_NULL
};

static tool_rc sign_and_save(ESYS_CONTEXT *ectx) {

    TPMT_SIGNATURE *signature;
    bool result;

    tool_rc rc = tool_rc_general_error;

    if (!ctx.flags.D) {
      tool_rc tmp_rc = tpm2_hash_compute_data(ectx, ctx.halg, TPM2_RH_NULL,
              ctx.msg, ctx.length, &ctx.digest, NULL);
      if (tmp_rc != tool_rc_success) {
          LOG_ERR("Compute message hash failed!");
          return tmp_rc;
      }
    }

    rc = tpm2_sign(ectx, &ctx.signing_key.object, ctx.digest, &ctx.in_scheme,
      &ctx.validation, &signature);
    if (rc != tool_rc_success) {
      goto out;
    }

    result = tpm2_convert_sig_save(signature, ctx.sig_format,
                ctx.outFilePath);
    if (!result) {
        goto out;
    }

    rc = tool_rc_success;

out:
    free(signature);
    return rc;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    bool option_fail = false;

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option c");
        option_fail = true;
    }

    if (!ctx.flags.m && !ctx.flags.D) {
        LOG_ERR("Expected options m or D");
        option_fail = true;
    }

    if (!ctx.flags.o) {
        LOG_ERR("Expected option o");
        option_fail = true;
    }

    if (option_fail) {
        return tool_rc_option_error;
    }

    if (ctx.flags.D && (ctx.flags.t || ctx.flags.m)) {
        LOG_WARN("Option D provided, options m and t are ignored.");
    }

    if (ctx.flags.D || !ctx.flags.t) {
        ctx.validation.tag = TPM2_ST_HASHCHECK;
        ctx.validation.hierarchy = TPM2_RH_NULL;
        memset(&ctx.validation.digest, 0, sizeof(ctx.validation.digest));
    }

    /*
     * Set signature scheme for key type, or validate chosen scheme is allowed for key type.
     */
    tool_rc rc = tpm2_alg_util_get_signature_scheme(ectx,
      ctx.signing_key.object.tr_handle, ctx.halg, ctx.sig_scheme, &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("bad signature scheme for key type!");
        return rc;
    }

    /*
     * Process the msg file if needed
     */
    if (ctx.flags.m && !ctx.flags.D) {
      unsigned long file_size;
      bool result = files_get_file_size_path(ctx.inMsgFileName, &file_size);
      if (!result) {
          return tool_rc_general_error;
      }
      if (file_size == 0) {
          LOG_ERR("The message file \"%s\" is empty!", ctx.inMsgFileName);
          return tool_rc_general_error;
      }

      if (file_size > UINT16_MAX) {
          LOG_ERR(
                  "The message file \"%s\" is too large, got: %lu bytes, expected less than: %u bytes!",
                  ctx.inMsgFileName, file_size, UINT16_MAX + 1);
          return tool_rc_general_error;
      }

      ctx.msg = (BYTE*) calloc(required_argument, file_size);
      if (!ctx.msg) {
          LOG_ERR("oom");
          return tool_rc_general_error;
      }

      ctx.length = file_size;
      result = files_load_bytes_from_path(ctx.inMsgFileName, ctx.msg, &ctx.length);
      if (!result) {
          free(ctx.msg);
          return tool_rc_general_error;
      }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.signing_key.ctx_path = value;
        break;
    case 'p':
        ctx.signing_key.auth_str = value;
        break;
    case 'g': {
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: \"%s\"",
                    value);
            return false;
        }
    }
        break;
    case 's': {
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
    }
        break;
    case 'd': {
        ctx.digest = malloc(sizeof(TPM2B_DIGEST));
        ctx.digest->size = sizeof(TPM2B_DIGEST);
        if (!files_load_bytes_from_path(value, ctx.digest->buffer, &ctx.digest->size)) {
            LOG_ERR("Could not load digest from file \"%s\"!", value);
            return false;
        }
        ctx.flags.D = 1;
    }
        break;
    case 'm':
        ctx.inMsgFileName = value;
        ctx.flags.m = 1;
        break;
    case 't': {
        bool result = files_load_validation(value, &ctx.validation);
        if (!result) {
            return false;
        }
        ctx.flags.t = 1;
    }
        break;
    case 'o': {
        ctx.outFilePath = value;
        ctx.flags.o = 1;
    }
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
    /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",                 required_argument, NULL, 'p' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "scheme",               required_argument, NULL, 's' },
      { "message",              required_argument, NULL, 'm' },
      { "digest",               required_argument, NULL, 'd' },
      { "signature",            required_argument, NULL, 'o' },
      { "ticket",               required_argument, NULL, 't' },
      { "key-context",          required_argument, NULL, 'c' },
      { "format",               required_argument, NULL, 'f' }
    };

    *opts = tpm2_options_new("p:g:m:d:t:o:c:f:s:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
        ctx.signing_key.auth_str, &ctx.signing_key.object, false,
        TPM2_HANDLES_ALL);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return sign_and_save(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.signing_key.object.session);
}

void tpm2_tool_onexit(void) {

    if (ctx.digest) {
        free(ctx.digest);
    }
    free(ctx.msg);
}
