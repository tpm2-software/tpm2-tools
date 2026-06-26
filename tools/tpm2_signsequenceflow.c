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
#include "object.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"

typedef struct tpm_signsequenceflow_ctx tpm_signsequenceflow_ctx;
struct tpm_signsequenceflow_ctx {
	
    char *sequence_auth_arg;
    char *key_context_arg;
    char *key_auth_arg;
    char *input_file;
    char *signature_file;
    
    tpm2_loaded_object key_object;
    tpm2_session *sequence_auth_session;
    tpm2_session *key_auth_session;
    ESYS_TR sequence_handle;
};

static tpm_signsequenceflow_ctx ctx = {
	.sequence_auth_session = NULL,
	.key_auth_session = NULL,	
	.sequence_handle = ESYS_TR_NONE,
};

static bool load_file(const char *path, UINT8 **data, size_t *size){
	
	*data = NULL;
	*size = 0;
	
	FILE *f = fopen(path, "rb");
	if (!f){
		LOG_ERR("Cannot open file");
		return false;
	}
	
	if (fseek(f, 0, SEEK_END) != 0){
		fclose(f);
		return false;
	}
	
	long sz = ftell(f);
	if (sz < 0){
		fclose(f);
		return false;
	}
	
	if(fseek(f, 0, SEEK_SET) != 0){
		fclose(f);
		return false;
	}
	
	UINT8 *buf = calloc(1, (size_t)sz ? (size_t)sz : 1);
	if (!buf){
		fclose(f);
		return false;
	}
	
	size_t size_file = fread(buf, 1, (size_t)sz, f);
	if (ferror(f)){
		free(buf);
		fclose(f);
		LOG_ERR("Error while reading file");
		return false;
	}
	
	fclose(f);
	
	*data = buf;
	*size = size_file;
	
	return true;
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

static tool_rc check_options(void){
	
	if (!ctx.key_context_arg) {
		LOG_ERR("Expected options -c for key context");
		return tool_rc_option_error;
	}
	
	if (!ctx.input_file) {
		LOG_ERR("Expected options -i for input data");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}

static tool_rc sign_sequence_start(ESYS_CONTEXT *ectx) {
	
	const TPM2B_AUTH *seq_auth = tpm2_session_get_auth_value(ctx.sequence_auth_session);
	if(!seq_auth){
		return tool_rc_general_error;
	}
	
	TPM2B_SIGNATURE_CTX context = {0};
	
	tool_rc rc= tpm2_signsequencestart(ectx,
							   ctx.key_object.tr_handle,
							   (TPM2B_AUTH *)seq_auth,
							   &context,
							   &ctx.sequence_handle);
	if (rc != tool_rc_success){
		return rc;
	}
	
	return tool_rc_success;
	
}

static tool_rc do_sequence_update(ESYS_CONTEXT *ectx, const UINT8 *data, size_t sz) {
	
	const TPM2B_AUTH *seq_auth = tpm2_session_get_auth_value(ctx.sequence_auth_session);
	if(!seq_auth){
		return tool_rc_general_error;
	}
	
	TSS2_RC rval = Esys_TR_SetAuth(ectx, ctx.sequence_handle, seq_auth);
	if(rval != TSS2_RC_SUCCESS){
		LOG_PERR(Esys_TR_SetAuth, rval);
		return tool_rc_general_error;
	}
	
	TPM2B_MAX_BUFFER buffer = {0};
	buffer.size = (UINT16)sz;
	memcpy(buffer.buffer, data, sz);
	
	return tpm2_sequence_update(ectx, ctx.sequence_handle, &buffer);
	
}

static tool_rc sign_sequence_complete(ESYS_CONTEXT *ectx, const UINT8 *data, size_t sz) {
	
	const TPM2B_AUTH *seq_auth = tpm2_session_get_auth_value(ctx.sequence_auth_session);
	if(!seq_auth){
		return tool_rc_general_error;
	}
	
	const TPM2B_AUTH *key_auth = tpm2_session_get_auth_value(ctx.key_auth_session);
	if(!key_auth){
		return tool_rc_general_error;
	}
	
	TSS2_RC rval = Esys_TR_SetAuth(ectx, ctx.sequence_handle, seq_auth);
	if(rval != TSS2_RC_SUCCESS){
		LOG_PERR(Esys_TR_SetAuth, rval);
		return tool_rc_general_error;
	}
	
	rval = Esys_TR_SetAuth(ectx, ctx.key_object.tr_handle, key_auth);
	if(rval != TSS2_RC_SUCCESS){
		LOG_PERR(Esys_TR_SetAuth, rval);
		return tool_rc_general_error;
	}
	
	TPM2B_MAX_BUFFER buffer = {0};
	buffer.size = (UINT16)sz;
	memcpy(buffer.buffer, data, sz);
	
	TPMT_SIGNATURE *signature = NULL;
	
	tool_rc rc = tpm2_signsequencecomplete(ectx,
			ctx.sequence_handle,
			ctx.key_object.tr_handle,
			&buffer,
			&signature);
	if(rc!=tool_rc_success){
		return rc;
	}
	
	if (!signature){
		LOG_ERR("TPM returned NULL signature");
		return tool_rc_general_error;
	}
	
	bool ok = save_signature_file(ctx.signature_file, signature);
	if (!ok){
		Esys_Free(signature);
		return tool_rc_general_error;
	}
	
	tpm2_tool_output("signature generated\n");
	Esys_Free(signature);
	
	ctx.sequence_handle = ESYS_TR_NONE;
	
	return tool_rc_success;	
}

static tool_rc run_flow(ESYS_CONTEXT *ectx){
	
	UINT8 *msg = NULL;
	size_t msg_size = 0;
	
	bool ok = load_file(ctx.input_file, &msg, &msg_size);
	if(!ok){
		return tool_rc_general_error;
	}
	
	tool_rc rc = sign_sequence_start(ectx);
	if (rc != tool_rc_success){
		free(msg);
		return rc;
	}
	
	const size_t max_chunk = sizeof(((TPM2B_MAX_BUFFER *)0)->buffer);
	
	if (msg_size == 0){
		rc = sign_sequence_complete(ectx, msg, 0);
		free(msg);
		return rc;
	}
	
	if (msg_size <= max_chunk){
		rc = sign_sequence_complete(ectx, msg, msg_size);
		free(msg);
		return rc;
	}
	
	size_t offset = 0;
	
	while ((msg_size - offset) > max_chunk){
		size_t remaining = msg_size - offset;
		size_t this_chunk = remaining - offset > max_chunk ? max_chunk : remaining;
		
		if((msg_size - (offset + this_chunk)) == 0){
			break;
		}
		
		rc = do_sequence_update(ectx, msg + offset, this_chunk);
		if (rc != tool_rc_success){
			free(msg);
			return rc;
		}
		
		offset += this_chunk;
		
		if ((msg_size - offset) <= max_chunk){
			break;
		}
	}
	
	rc = sign_sequence_complete(ectx, msg + offset, msg_size - offset);
	free(msg);
	return rc;
	
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key_context_arg = value;
        break;
    case 'P':
        ctx.key_auth_arg = value;
        break;
    case 'p':
        ctx.sequence_auth_arg = value;
        break;
    case 'i':
        ctx.input_file = value;
        break;
    case 's':
        ctx.signature_file = value;
        break;
    default:
		return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",       required_argument, NULL, 'c' },
        { "key-auth",          required_argument, NULL, 'P' },
        { "sequence-auth",     required_argument, NULL, 'p' },
        { "input",             required_argument, NULL, 'i' },
        { "signature",         required_argument, NULL, 's' }
    };


    *opts = tpm2_options_new("c:P:p:i:s:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    
    tool_rc rc = tpm2_util_object_load(ectx, ctx.key_context_arg,
							&ctx.key_object, TPM2_HANDLE_ALL_W_NV);
	if (rc != tool_rc_success) {
        return rc;
    }	
    
    rc = tpm2_auth_util_from_optarg(ectx, ctx.key_auth_arg, &ctx.key_auth_session, false);
    if (rc != tool_rc_success) {
        return rc;
    }
    
    const TPM2B_AUTH *key_auth = tpm2_session_get_auth_value(ctx.key_auth_session);
    if(!key_auth){
		return tool_rc_general_error;
	}
    
    TSS2_RC rval = Esys_TR_SetAuth(ectx, ctx.key_object.tr_handle, key_auth);
    
    if (rval != TSS2_RC_SUCCESS) {
		LOG_PERR(Esys_TR_SetAuth, rval);
        return tool_rc_general_error;
    }
    
     rc = tpm2_auth_util_from_optarg(ectx, ctx.sequence_auth_arg, &ctx.sequence_auth_session, false);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
	
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    
    tool_rc rc = check_options();
    if (rc != tool_rc_success){
		return rc;
	}

    rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return run_flow(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

	tool_rc rc = tool_rc_success;
	tool_rc tmp_rc;
	
	if (ctx.sequence_handle != ESYS_TR_NONE){
		TSS2_RC rval = Esys_TR_Close(ectx, &ctx.sequence_handle);
		if (rval != TSS2_RC_SUCCESS){
			LOG_PERR(Esys_TR_Close, rval);
			rc = tool_rc_general_error;
		}
	}
	
	if (ctx.key_object.tr_handle != ESYS_TR_NONE){
		TSS2_RC rval = Esys_TR_Close(ectx, &ctx.key_object.tr_handle);
		if (rval != TSS2_RC_SUCCESS){
			LOG_PERR(Esys_TR_Close, rval);
			rc = tool_rc_general_error;
		}
	}
	
	tmp_rc = tpm2_session_close(&ctx.sequence_auth_session);
	if (tmp_rc != tool_rc_success && rc == tool_rc_success){
		rc = tmp_rc;
	}
	
	tmp_rc = tpm2_session_close(&ctx.key_auth_session);
	if (tmp_rc != tool_rc_success && rc == tool_rc_success){
		rc = tmp_rc;
	}
	
	tmp_rc = tpm2_session_close(&ctx.key_object.session);
	if (tmp_rc != tool_rc_success && rc == tool_rc_success){
		rc = tmp_rc;
	}
    
    return rc;
}


// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("signsequence", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
