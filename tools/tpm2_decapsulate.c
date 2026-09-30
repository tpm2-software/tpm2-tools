/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************;
* Copyright (c) 2026, STMicroelectronics
*
* All rights reserved.
***********************************************************************/

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

typedef struct tpm_decapsulate_ctx tpm_decapsulate_ctx;
struct tpm_decapsulate_ctx {
	
    char *context_arg;
    char *auth_arg;
    char *in_ciphertext_file;
    char *out_secret_file;
    tpm2_loaded_object context_object;
};

static tpm_decapsulate_ctx ctx = {0};

static bool load_ciphertext(const char *path, TPM2B_KEM_CIPHERTEXT *ciphertext){
	
	FILE *f = fopen(path, "rb");
	
	if(!f){
		LOG_ERR("Cannot open ciphertext file : %s", path);
		return false;
	}
	
	size_t n = fread(ciphertext->buffer, 1, sizeof(ciphertext->buffer), f);
	if (ferror(f)){
		fclose(f);
		LOG_ERR("Error while reading ciphertext file: %s", path);
		return false;
	}
	
	fclose(f);
	
	if (n > sizeof(ciphertext->buffer)){
		LOG_ERR("Ciphertext file too large");
		return false;
	}
	
	ciphertext->size = (UINT16)n;
	return true;
	
}

static tool_rc check_options(void){
	
	if(!ctx.context_arg){
		LOG_ERR("Expected option -c for object context");
		return tool_rc_option_error;
	}
	
	if(!ctx.in_ciphertext_file){
		LOG_ERR("Expected option -i for ciphertext input");
		return tool_rc_option_error;
	}
	
	if(!ctx.out_secret_file){
		LOG_ERR("Expected option -s for shared secret output");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}
	

static tool_rc decapsulate_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_SHARED_SECRET *sharedSecret = NULL;
    TPM2B_KEM_CIPHERTEXT ciphertext = {0};

    bool ret = load_ciphertext(ctx.in_ciphertext_file, &ciphertext);
    if (!ret) {
		return tool_rc_general_error;
	}
	
	TSS2_RC rval = Esys_Decapsulate(ectx,
									ctx.context_object.tr_handle,
									ESYS_TR_PASSWORD,
									ESYS_TR_NONE,
									ESYS_TR_NONE,
									&ciphertext,
									&sharedSecret);
	
	if (rval != TSS2_RC_SUCCESS){
		LOG_PERR(Esys_Decapsulate, rval);
		return tool_rc_general_error;
	}
	
	if (!sharedSecret){
		LOG_ERR("TPM returned NULL shared secret");
		return tool_rc_general_error;
	}
	
	tpm2_tool_output("shared secret: ");
	for (UINT16 i=0; i < sharedSecret->size; i++){
		tpm2_tool_output("%02x", sharedSecret->buffer[i]);
	}
	tpm2_tool_output("\n");
	
	ret = files_save_bytes_to_file(ctx.out_secret_file,
								   sharedSecret->buffer,
								   sharedSecret->size);
	if (!ret) {
		LOG_ERR("Cannot save shared secret");
		Esys_Free(sharedSecret);
		return tool_rc_general_error;
	}
    Esys_Free(sharedSecret);
    return tool_rc_success;        
    
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 's':
        ctx.out_secret_file = value;
        break;
    case 'p':
        ctx.auth_arg = value;
        break;
    case 'i' : 
		ctx.in_ciphertext_file = value;
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
        { "auth",              required_argument, NULL, 'p' },
        { "ciphertext",        required_argument, NULL, 'i' }
    };

    *opts = tpm2_options_new("c:p:i:s:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.context_arg,
		ctx.auth_arg, &ctx.context_object, false,
		TPM2_HANDLE_ALL_W_NV);
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

    return decapsulate_and_save(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("decapsulate", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
