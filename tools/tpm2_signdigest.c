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

typedef struct tpm_signdigest_ctx tpm_signdigest_ctx;
struct tpm_signdigest_ctx {
	
    struct{
		const char *ctx_path;
		const char *auth_str;
		tpm2_loaded_object object;
	}key;
	
	const char *context_path;
	TPM2B_SIGNATURE_CTX context;
	const char *digest_path;
	TPM2B_DIGEST digest;
	const char *ticket_path;
	TPMT_TK_HASHCHECK validation;
	
	const char *signature_path;
	TPMT_SIGNATURE *signature;
};

static tpm_signdigest_ctx ctx = {
	.context ={
		.size = 0,
	},
	.digest = {
		.size = 0,
	},
	.validation = {
		.tag = TPM2_ST_HASHCHECK,
		.hierarchy = TPM2_RH_NULL,
		.digest = {
			.size = 0,
		},
	},
	.signature = NULL,
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

static bool load_ticket(const char *path, TPMT_TK_HASHCHECK *validation){
	
	if (!path){
		validation->tag = TPM2_ST_HASHCHECK;
		validation->hierarchy = TPM2_RH_NULL;
		validation->digest.size = 0;
		return true;
	}
	
	FILE *f = fopen(path, "rb");
	if (!f){
		LOG_ERR("Cannot open file");
		return false;
	}
	
	UINT16 tag = 0;
	UINT32 hierarchy = 0;
	UINT16 digest_size = 0;
	
	if (fread(&tag, sizeof(tag), 1, f) != 1){
		LOG_ERR("Could not read ticket tag");
		fclose(f);
		return false;
	}
	
	if (fread(&hierarchy, sizeof(hierarchy), 1, f) != 1){
		LOG_ERR("Could not read ticket hierarchy");
		fclose(f);
		return false;
	}
	
	if (fread(&digest_size, sizeof(digest_size), 1, f) != 1){
		LOG_ERR("Could not read ticket digest size");
		fclose(f);
		return false;
	}
	
	if (digest_size > sizeof(validation->digest.buffer)){
		LOG_ERR("Ticket digest too large");
		fclose(f);
		return false;
	}
	
	if (fread(validation->digest.buffer, 1, digest_size, f) != digest_size){
		LOG_ERR("Could not read ticket digest bytes");
		fclose(f);
		return false;
	}
	
	fclose(f);
	
	validation->tag = tag;
	validation->hierarchy = hierarchy;
	validation->digest.size = digest_size;
	
	return true;
}

static tool_rc check_options(void){
	
	if (!ctx.key.ctx_path) {
		LOG_ERR("Expected options -c for key object");
		return tool_rc_option_error;
	}
	
	if (!ctx.digest_path) {
		LOG_ERR("Expected options -d for input digest");
		return tool_rc_option_error;
	}
	
	if (!ctx.signature_path) {
		LOG_ERR("Expected options -o for signature output");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
		ctx.key.auth_str, &ctx.key.object, false,
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
	
	result = load_ticket(ctx.ticket_path, &ctx.validation);
	if(!result){
		return tool_rc_general_error;
	}
	
	return tool_rc_success;
}
    
static tool_rc sign_digest(ESYS_CONTEXT *ectx){
	
	ESYS_TR shandle1 = ESYS_TR_PASSWORD;
	
	TSS2_RC rval = Esys_SignDigest(ectx, ctx.key.object.tr_handle,
		shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
		&ctx.context, &ctx.digest, &ctx.validation, &ctx.signature);
		
	if (rval != TPM2_RC_SUCCESS){
		LOG_PERR(Esys_SignDigest, rval);
		return tool_rc_from_tpm(rval);
	}
	
	return tool_rc_success;
}

static bool save_signature_file(const char *path, TPMT_SIGNATURE *signature){

	if(!path){
		return true;
	}
	
	UINT8 buffer[8192];
	size_t offset = 0;
	
	TSS2_RC rval = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, buffer,
				sizeof(buffer), &offset);
	if (rval != TSS2_RC_SUCCESS){
		return false;
	}
	
	FILE *f = fopen(path, "wb");
	if (!f){
		LOG_ERR("Cannot open signature output file");
		return false;
	}
	
	size_t size_file = fwrite(buffer, 1, offset, f);
	fclose(f);
	
	if(size_file != offset){
		LOG_ERR("Cannot save signature file");
		return false;
	}
	
	return true;
	
	
}

static tool_rc process_output(ESYS_CONTEXT *ectx){
	
	UNUSED(ectx);
	
	bool result = save_signature_file(ctx.signature_path, ctx.signature);
	if(!result){
		LOG_ERR("Could not save signature to file : %s", ctx.signature_path);
		return tool_rc_general_error;
	}
	
	return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'g':
		ctx.context_path = value;
		break;
	case 'd':
		ctx.digest_path = value;
		break;
    case 't':
        ctx.ticket_path = value;
        break;
    case 'o':
        ctx.signature_path = value;
        break;
    default:
		return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",       required_argument, NULL, 'c' },
        { "auth",              required_argument, NULL, 'p' },
        { "context",           required_argument, NULL, 'g' },
        { "digest",            required_argument, NULL, 'd' },
        { "ticket",            required_argument, NULL, 't' },
        { "signature",          required_argument, NULL, 'o' }
    };


    *opts = tpm2_options_new("c:p:g:d:t:o:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    
    UNUSED(flags);
    
    tool_rc rc = check_options();
    if (rc != tool_rc_success){
		return rc;
	}

    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }
    
    rc = sign_digest(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

	UNUSED(ectx);
	
	free(ctx.signature);
	
    return tpm2_session_close(&ctx.key.object.session);
}


// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("signdigest", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
