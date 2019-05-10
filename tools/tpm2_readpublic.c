/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "tpm2_convert.h"
#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_readpub_ctx tpm_readpub_ctx;
struct tpm_readpub_ctx {
    struct {
        UINT8 f      : 1;
    } flags;
    char *outFilePath;
    char *out_name_file;
    tpm2_convert_pubkey_fmt format;
    tpm2_loaded_object context_object;
    const char *context_arg;
    const char *out_tr_file;
};

static tpm_readpub_ctx ctx = {
    .format = pubkey_format_tss,
};

static int read_public_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC *public;
    TPM2B_NAME *name;
    TPM2B_NAME *qualified_name;

    TSS2_RC rval = Esys_ReadPublic(ectx, ctx.context_object.tr_handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &public, &name, &qualified_name);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Eys_ReadPublic, rval);
        return false;
    }

    tpm2_tool_output("name: ");
    UINT16 i;
    for (i = 0; i < name->size; i++) {
        tpm2_tool_output("%02x", name->name[i]);
    }
    tpm2_tool_output("\n");

    bool ret = true;
    if (ctx.out_name_file) {
        ret = files_save_bytes_to_file(ctx.out_name_file, name->name, name->size);
        if(!ret) {
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

    ret = ctx.outFilePath ?
            tpm2_convert_pubkey_save(public, ctx.format, ctx.outFilePath) : true;
    if (!ret) {
        goto out;
    }

    if (ctx.out_tr_file) {
        ret = files_save_ESYS_TR(ectx, ctx.context_object.tr_handle,
            ctx.out_tr_file);
    }

out:
    free(public);
    free(name);
    free(qualified_name);

    return ret;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'o':
        ctx.outFilePath = value;
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
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "out-file",   required_argument, NULL, 'o' },
        { "context",    required_argument, NULL, 'c' },
        { "format",     required_argument, NULL, 'f' },
        { "name",       required_argument, NULL, 'n' },
        { "handle",     required_argument, NULL, 't' }
    };

    *opts = tpm2_options_new("o:c:f:n:t:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool init(ESYS_CONTEXT *context) {

    bool result = tpm2_util_object_load(context,
                                ctx.context_arg, &ctx.context_object);
    if (!result) {
        return false;
    }

    bool is_persistent = ctx.context_object.handle
            && ((ctx.context_object.handle >> TPM2_HR_SHIFT) == TPM2_HT_PERSISTENT);
    if (ctx.out_tr_file && !is_persistent) {
        LOG_ERR("Can only output a serialized handle for persistent object handles");
        return false;
    }

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(context);
    if (!result) {
        return 1;
    }

    return read_public_and_save(context) != true;
}
