/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************;
* Copyright (c) 2026, STMicroelectronics
*
* All rights reserved.
***********************************************************************/

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"
#include "object.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"

typedef struct tpm_verifydigestsignature_ctx tpm_verifydigestsignature_ctx;
struct tpm_verifydigestsignature_ctx {
	
    struct{
		const char *ctx_path;
		tpm2_loaded_object object;
	}key;
	
	const char *context_path;
	TPM2B_SIGNATURE_CTX context;
	const char *digest_path;
	TPM2B_DIGEST digest;
	const char *signature_path;
	TPMT_SIGNATURE signature;
	
	const char *validation_path;
	TPMT_TK_VERIFIED *validation;
};

static tpm_verifydigestsignature_ctx ctx = {
	.context ={
		.size = 0,
	},
	.digest = {
		.size = 0,
	},
	.signature = {0} ,
	.validation = NULL,
};

static bool load_signature_context(const char *path, TPM2B_SIGNATURE_CTX *context){
	
	if (!path){
		context->size = 0;
		return true;
	}
	
	unsigned long size = 0;
	bool result = files_get_file_size_path(path, &size);
	if (!result){
		LOG_ERR("Unable to get signature context file: %s", path);
		return false;
	}
	
	if (size > sizeof(context->buffer)){
		LOG_ERR("Signature context too large: got %lu max %lu", size, sizeof(context->buffer));
		return false;
	}
	
	context->size = size;
	return files_load_bytes_from_path(path, context->buffer, &context->size);
	
}

static bool load_digest(const char *path, TPM2B_DIGEST *digest){
	
	if (!path){
		LOG_ERR("Expected digest input file");
		return false;
	}
	
	unsigned long size = 0;
	bool result = files_get_file_size_path(path, &size);
	if (!result){
		LOG_ERR("Unable to get digest file size: %s", path);
		return false;
	}
	
	if (size > sizeof(digest->buffer)){
		LOG_ERR("Digest too large: got %lu max %zu", size, sizeof(digest->buffer));
		return false;
	}
	
	digest->size = size;
	return files_load_bytes_from_path(path, digest->buffer, &digest->size);
	
}

static bool load_signature_file(const char *path, TPMT_SIGNATURE *signature){
	
	FILE *f = fopen(path, "rb");
	if (!f){
		LOG_ERR("Cannot open file");
		return false;
	}
	
	UINT8 buffer[8192];	
	size_t size_file = fread(buffer, 1, sizeof(buffer), f);	
	fclose(f);
	
	size_t offset = 0;
	TSS2_RC rval = Tss2_MU_TPMT_SIGNATURE_Unmarshal(buffer, size_file, &offset, signature);
	if (rval != TSS2_RC_SUCCESS){
		return false;
	}
	return true;
	
}

static bool save_validation(const char *path, TPMT_TK_VERIFIED *validation){
	
	if(!path){
		return true;
	}
	
	FILE *f = fopen(path, "wb");
	if (!f){
		LOG_ERR("Cannot open validation output file");
		return false;
	}
	
	bool ok = true;
	
	if (fwrite(&validation->tag, sizeof(validation->tag), 1, f) != 1){
		ok = false;
	}
	
	if (ok && fwrite(&validation->hierarchy,sizeof(validation->hierarchy), 1, f) != 1) {
		ok = false;
	}
	
	if (ok && fwrite(&validation->digest.size,sizeof(validation->digest.size), 1, f) != 1) {
		ok = false;
	}
	
	if (ok && validation->digest.size > 0){
		if (fwrite(validation->digest.buffer, 1, validation->digest.size, f) != validation->digest.size) {
			ok = false;
		}
	}
	
	fclose(f);
	
	if (!ok){
		LOG_ERR("could not write validation ticket");
	}
	
	return ok;	
}


static tool_rc check_options(ESYS_CONTEXT *ectx){
	
	UNUSED(ectx);
	
	if (!ctx.key.ctx_path) {
		LOG_ERR("Expected options -c for key object");
		return tool_rc_option_error;
	}
	
	if (!ctx.digest_path) {
		LOG_ERR("Expected options -d for input digest");
		return tool_rc_option_error;
	}
	
	if (!ctx.signature_path) {
		LOG_ERR("Expected options -s for signature output");
		return tool_rc_option_error;
	}
	
	if (!ctx.validation_path) {
		LOG_ERR("Expected options -t for signature output");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
		NULL, &ctx.key.object, false,
		TPM2_HANDLE_ALL_W_NV);
	
	if (rc != tool_rc_success){
		return rc;
	}
	
	bool result = load_signature_context(ctx.context_path, &ctx.context);
	if(!result){
		return tool_rc_general_error;
	}
	
	result = load_digest(ctx.digest_path, &ctx.digest);
	if(!result){
		return tool_rc_general_error;
	}
	
	result = load_signature_file(ctx.signature_path, &ctx.signature);
	if(!result){
		return tool_rc_general_error;
	}
	
	return tool_rc_success;
}
    
static tool_rc verify_digest_signature(ESYS_CONTEXT *ectx){
		
	TSS2_RC rval = Esys_VerifyDigestSignature(ectx, ctx.key.object.tr_handle,
		ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
		&ctx.context, &ctx.digest, &ctx.signature, &ctx.validation);
		
	if (rval != TPM2_RC_SUCCESS){
		LOG_PERR(Esys_VerifyDigestSignature, rval);
		return tool_rc_from_tpm(rval);
	}
	
	return tool_rc_success;
}

static tool_rc process_output(ESYS_CONTEXT *ectx){
	
	UNUSED(ectx);
	
	bool result = save_validation(ctx.validation_path, ctx.validation);
	if(!result){
		return tool_rc_general_error;
	}
	
	return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'g':
		ctx.context_path = value;
		break;
	case 'd':
		ctx.digest_path = value;
		break;
    case 's':
        ctx.signature_path = value;
        break;
    case 't':
        ctx.validation_path = value;
        break;
    default:
		return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",       required_argument, NULL, 'c' },
        { "context",           required_argument, NULL, 'g' },
        { "digest",            required_argument, NULL, 'd' },
        { "signature",         required_argument, NULL, 's' },
        { "validation",        required_argument, NULL, 't' }
    };


    *opts = tpm2_options_new("c:g:d:s:t:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    
    UNUSED(flags);
    
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success){
		return rc;
	}

    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }
    
    rc = verify_digest_signature(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

	UNUSED(ectx);
	
    return tpm2_session_close(&ctx.key.object.session);
}


// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("verifydigestsignature", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
