/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"

typedef struct tpm_readpub_ctx tpm_readpub_ctx;
struct tpm_readpub_ctx {
    struct {
        UINT8 f :1;
    } flags;
    char *output_path;
    char *out_name_file;
    char *out_qname_file;
    tpm2_convert_pubkey_fmt format;
    tpm2_loaded_object context_object;
    const char *context_arg;
    const char *out_tr_file;
};

static tpm_readpub_ctx ctx = {
    .format = pubkey_format_tss,
};

static tool_rc read_public_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC *public;
    TPM2B_NAME *name;
    TPM2B_NAME *qualified_name;

    tool_rc rc = tool_rc_general_error;

    tool_rc tmp_rc = tpm2_readpublic(ectx, ctx.context_object.tr_handle,
            &public, &name, &qualified_name);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    tpm2_tool_output("name: ");
    UINT16 i;
    for (i = 0; i < name->size; i++) {
        tpm2_tool_output("%02x", name->name[i]);
    }
    tpm2_tool_output("\n");

    bool ret = true;
    if (ctx.out_name_file) {
        ret = files_save_bytes_to_file(ctx.out_name_file, name->name,
                name->size);
        if (!ret) {
            LOG_ERR("Can not save object name file.");
            goto out;
        }
    }

    tpm2_tool_output("qualified name: ");
    for (i = 0; i < qualified_name->size; i++) {
        tpm2_tool_output("%02x", qualified_name->name[i]);
    }
    tpm2_tool_output("\n");

    tpm2_util_public_to_yaml(public, NULL);

    ret = ctx.output_path ?
            tpm2_convert_pubkey_save(public, ctx.format, ctx.output_path) :
            true;
    if (!ret) {
        goto out;
    }

    if (ctx.out_qname_file) {
        ret = files_save_bytes_to_file(ctx.out_qname_file, qualified_name->name,
                qualified_name->size);
        if (!ret) {
            goto out;
        }
    }

    if (ctx.out_tr_file) {
        rc = files_save_ESYS_TR(ectx, ctx.context_object.tr_handle,
                ctx.out_tr_file);
    } else {
        rc = tool_rc_success;
    }

out:
    free(public);
    free(name);
    free(qualified_name);

    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = 1;
        break;
    case 'n':
        ctx.out_name_file = value;
        break;
    case 't':
        ctx.out_tr_file = value;
        break;
    case 'q':
        ctx.out_qname_file = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "output",            required_argument, NULL, 'o' },
        { "object-context",    required_argument, NULL, 'c' },
        { "format",            required_argument, NULL, 'f' },
        { "name",              required_argument, NULL, 'n' },
        { "serialized-handle", required_argument, NULL, 't' },
        { "qualified-name",    required_argument, NULL, 'q' }
    };

    *opts = tpm2_options_new("o:c:f:n:t:q:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *context) {

    tool_rc rc = tpm2_util_object_load(context, ctx.context_arg,
            &ctx.context_object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool is_persistent = ctx.context_object.handle
            && ((ctx.context_object.handle >> TPM2_HR_SHIFT)
                    == TPM2_HT_PERSISTENT);
    if (ctx.out_tr_file && !is_persistent) {
        LOG_ERR("Can only output a serialized handle for persistent object "
                "handles");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(context);
    if (rc != tool_rc_success) {
        return rc;
    }

    return read_public_and_save(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("readpublic", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
