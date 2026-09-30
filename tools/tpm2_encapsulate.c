/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************;
* Copyright (c) 2026, STMicroelectronics
*
* All rights reserved.
***********************************************************************/

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"

typedef struct tpm_encapsulate_ctx tpm_encapsulate_ctx;
struct tpm_encapsulate_ctx {
	
    char *context_arg;
    char *out_secret_file;
    char *out_ciphertext_file;
    tpm2_loaded_object context_object;
};

static tpm_encapsulate_ctx ctx = {0};


static tool_rc check_options(void){
	
	if (!ctx.context_arg) {
		LOG_ERR("Expected options -c for object context");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}

static tool_rc encapsulate_and_save(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;
    TPM2B_SHARED_SECRET *sharedSecret = NULL;
    TPM2B_KEM_CIPHERTEXT *ciphertext = NULL;

    tool_rc tmp_rc = tpm2_encapsulate(ectx, ctx.context_object.tr_handle,
            &ciphertext, &sharedSecret);
            
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }
    
    if (sharedSecret == NULL || ciphertext == NULL){
		LOG_ERR("TPM returned NULL output for encapsulate");
		goto error;
	}

    tpm2_tool_output("shared secret: ");
    UINT16 i;
    for (i = 0; i < sharedSecret->size; i++) {
        tpm2_tool_output("%02x", sharedSecret->buffer[i]);
    }
    tpm2_tool_output("\n");

    tpm2_tool_output("ciphertext: ");
    for (i = 0; i < ciphertext->size; i++) {
        tpm2_tool_output("%02x", ciphertext->buffer[i]);
    }
    tpm2_tool_output("\n");
    
    if (ctx.out_secret_file){
		bool ret = files_save_bytes_to_file(ctx.out_secret_file,
										    sharedSecret->buffer,
											sharedSecret->size);
		if (!ret) {
			LOG_ERR("Cannot save shared secret file");
			goto error;
		}
	}

    if (ctx.out_ciphertext_file){
		bool ret = files_save_bytes_to_file(ctx.out_ciphertext_file,
											ciphertext->buffer,
											ciphertext->size);
		if (!ret){
			LOG_ERR("Cannot save ciphertext file");
			goto error;
		}
	}
	rc = tool_rc_success;

error:
    free(sharedSecret);
    free(ciphertext);

    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 's':
        ctx.out_secret_file = value;
        break;
    case 't':
        ctx.out_ciphertext_file = value;
        break;
    default:
		return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "object-context",    required_argument, NULL, 'c' },
        { "shared-secret",     required_argument, NULL, 's' },
        { "ciphertext",        required_argument, NULL, 't' }
    };
    
    *opts = tpm2_options_new("c:s:t:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *context) {

    tool_rc rc = tpm2_util_object_load(context, ctx.context_arg,
            &ctx.context_object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);
    
    tool_rc rc = check_options();
    if (rc != tool_rc_success){
		return rc;
	}

    rc = init(context);
    if (rc != tool_rc_success) {
        return rc;
    }

    return encapsulate_and_save(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("encapsulate", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
