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

typedef struct tpm_verifysequenceflow_ctx tpm_verifysequenceflow_ctx;
struct tpm_verifysequenceflow_ctx {
	
    char *context_arg;
    char *sequence_auth_arg;
    char *input_file;
    char *signature_file;
    char *ticket_file;
    char *hint_file;
    char *context_file;
    
    tpm2_loaded_object key_context_object;
    tpm2_session *sequence_auth_session;
    ESYS_TR sequence_handle;
    
};

static tpm_verifysequenceflow_ctx ctx = {
	.sequence_auth_session = NULL,
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

static bool save_ticket_file(const char *path, TPMT_TK_VERIFIED *ticket){
	
	if(!path){
		return true;
	}
	
	FILE *f = fopen(path, "wb");
	if (!f){
		LOG_ERR("Cannot open validation output file");
		return false;
	}
	
	size_t size_file = fwrite(ticket, 1, sizeof(*ticket), f);
	fclose(f);
	
	if(size_file != sizeof(*ticket)){
		LOG_ERR("Cannot save validation file");
		return false;
	}
	
	return true;
	
}

static tool_rc check_options(void){
	
	if (!ctx.context_arg) {
		LOG_ERR("Expected options -c for key context");
		return tool_rc_option_error;
	}
	
	if (!ctx.input_file) {
		LOG_ERR("Expected options -i for input message");
		return tool_rc_option_error;
	}
	
	if (!ctx.signature_file) {
		LOG_ERR("Expected options -s for signature input");
		return tool_rc_option_error;
	}
	
	return tool_rc_success;
}

static tool_rc verify_sequence_start(ESYS_CONTEXT *ectx) {

    const TPM2B_AUTH *seq_auth = tpm2_session_get_auth_value(ctx.sequence_auth_session);
	if(!seq_auth){
		return tool_rc_general_error;
	}
    
    TPM2B_SIGNATURE_HINT hint = {0};
    TPM2B_SIGNATURE_CTX context = {0};
    
    if (ctx.hint_file){
		UINT8 *buf = NULL;
		size_t size_file = 0;
		bool ok = load_file(ctx.hint_file, &buf, &size_file);
		if (!ok){
			return tool_rc_general_error;
		}
		if (size_file > sizeof(hint.buffer)){
			free(buf);
			return tool_rc_general_error;
		}
		hint.size = (UINT16)size_file;
		memcpy(hint.buffer, buf, size_file);
		free(buf);
	}
	
	if (ctx.context_file){
		UINT8 *buf = NULL;
		size_t size_file = 0;
		bool ok = load_file(ctx.context_file, &buf, &size_file);
		if (!ok){
			return tool_rc_general_error;
		}
		if (size_file > sizeof(context.buffer)){
			free(buf);
			return tool_rc_general_error;
		}
		context.size = (UINT16)size_file;
		memcpy(context.buffer, buf, size_file);
		free(buf);
		
	}
	
	return tpm2_verifysequencestart(ectx, 
			ctx.key_context_object.tr_handle,
			(TPM2B_AUTH *)seq_auth,
			&hint,
			&context,
			&ctx.sequence_handle);
}
    
static tool_rc do_sequence_update(ESYS_CONTEXT *ectx, const UINT8 *data, size_t size_file){
	
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
	buffer.size = (UINT16)size_file;
	memcpy(buffer.buffer, data, size_file);
	
	return tpm2_sequence_update(ectx, ctx.sequence_handle, &buffer);
	
}   

static tool_rc verify_sequence_complete(ESYS_CONTEXT *ectx, TPMT_SIGNATURE *signature) {

    const TPM2B_AUTH *seq_auth = tpm2_session_get_auth_value(ctx.sequence_auth_session);
	if(!seq_auth){
		return tool_rc_general_error;
	}
	
	TSS2_RC rval = Esys_TR_SetAuth(ectx, ctx.sequence_handle, seq_auth);
	if(rval != TSS2_RC_SUCCESS){
		LOG_PERR(Esys_TR_SetAuth, rval);
		return tool_rc_general_error;
	}
	
	TPMT_TK_VERIFIED *validation = NULL;
	
	tool_rc rc = tpm2_verifysequencecomplete(ectx,
			ctx.sequence_handle,
			ctx.key_context_object.tr_handle,
			signature,
			&validation);
	if (rc!= tool_rc_success){
		return rc;
	}
	
	if(!validation){
		return tool_rc_general_error;
	}
	
	bool ok = save_ticket_file(ctx.ticket_file, validation);
	if(!ok){
		Esys_Free(validation);
		return tool_rc_general_error;
	}
	
	tpm2_tool_output("signature verified\n");
	
	Esys_Free(validation);
	
	ctx.sequence_handle = ESYS_TR_NONE;
	
	return tool_rc_success;
}

static tool_rc run_flow(ESYS_CONTEXT *ectx){
	
	UINT8 *msg = NULL;
	size_t msg_size = 0;
	TPMT_SIGNATURE signature;
	
	bool ok = load_file(ctx.input_file, &msg, &msg_size);
	if(!ok){
		return tool_rc_general_error;
	}
	
	ok = load_signature_file(ctx.signature_file, &signature);
	if(!ok){
		free(msg);
		return tool_rc_general_error;
	}
	
	tool_rc rc = verify_sequence_start(ectx);
	if (rc!= tool_rc_success){
		free(msg);
		return rc;
	}
	
	const size_t max_chunk = sizeof(((TPM2B_MAX_BUFFER *)0)->buffer);
	
	if(msg_size == 0){
		rc = verify_sequence_complete(ectx, &signature);
		free(msg);
		return rc;
	}
	
	size_t offset = 0;
	
	while (offset < msg_size){
		size_t remaining = msg_size - offset;
		size_t this_chunk = remaining > max_chunk ? max_chunk : remaining;

		rc = do_sequence_update(ectx, msg + offset, this_chunk);
		if (rc != tool_rc_success){
			free(msg);
			return rc;
		}
		
		offset += this_chunk;

	}
	
	
	rc = verify_sequence_complete(ectx, &signature);
	free(msg);
	return rc;
	
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
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
    case 't':
        ctx.ticket_file = value;
        break;
    case 'h':
        ctx.hint_file = value;
        break;
    case 'C':
        ctx.context_file = value;
        break;
    default:
		return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",       required_argument, NULL, 'c' },
        { "sequence-auth",     required_argument, NULL, 'p' },
        { "input",             required_argument, NULL, 'i' },
        { "signature",         required_argument, NULL, 's' },
        { "ticket",            required_argument, NULL, 't' },
        { "hint",              required_argument, NULL, 'h' },
        { "context",           required_argument, NULL, 'C' }
    };


    *opts = tpm2_options_new("c:p:i:s:t:h:C:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load(ectx, ctx.context_arg,
            &ctx.key_context_object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }
    
    rc = tpm2_auth_util_from_optarg(ectx, ctx.sequence_auth_arg,
            &ctx.sequence_auth_session, false);
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
	
	tmp_rc = tpm2_session_close(&ctx.sequence_auth_session);
	if (tmp_rc != tool_rc_success && rc == tool_rc_success){
		rc = tmp_rc;
	}
	
	tmp_rc = tpm2_session_close(&ctx.key_context_object.session);
	if (tmp_rc != tool_rc_success && rc == tool_rc_success){
		rc = tmp_rc;
	}
    
    return rc;
}


// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("verifysequence", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
