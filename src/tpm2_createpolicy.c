//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <sys/stat.h>
#include <limits.h>
#include <getopt.h>
#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sample.h"
#include "log.h"
#include "common.h"
#include "options.h"
#include "main.h"
#include "string-bytes.h"
#include "tpm_session.h"
#include "tpm_hash.h"


typedef struct createpolicypcr_ctx createpolicypcr_ctx;
struct createpolicypcr_ctx {
    //common policy options
    TSS2_SYS_CONTEXT *sapi_context;
    SESSION *policy_session;
    TPM2B_DIGEST policy_digest;
    char policyfile[PATH_MAX];
    //build_pcr_policy options
    unsigned int pcr_index;
    TPMI_ALG_HASH hash_alg;
    char raw_pcr_file[PATH_MAX];
    unsigned raw_pcr_flag;
};

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
 (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

TPM_RC build_pcr_policy( createpolicypcr_ctx *ctx) {

    TPML_PCR_SELECTION pcrs = {
        .count = 1,
        .pcrSelections[0].hash = ctx->hash_alg,
        .pcrSelections[0].sizeofSelect = 3, 
        .pcrSelections[0].pcrSelect[0] = 0, 
        .pcrSelections[0].pcrSelect[1] = 0, 
        .pcrSelections[0].pcrSelect[2] = 0 
    };
    SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], ctx->pcr_index);

    //digests[count{2:}]{:8}
    TPML_DIGEST pcrValues = {
        .count = pcrs.count
    };
    UINT32 pcrUpdateCounter;
    TPM2B_DIGEST pcrDigest;
    TPML_PCR_SELECTION pcrSelectionOut;
    
    TPM_RC rval = TPM_RC_SUCCESS;
    FILE *fp;
    unsigned i=0, sz=0;
    long filesize=0;
    if(ctx->raw_pcr_flag) {
        rval = getFileSize(ctx->raw_pcr_file, &filesize);
        if(rval!=TPM_RC_SUCCESS) {
            return rval;
        }

        switch(ctx->hash_alg) {
            case TPM_ALG_SHA1: 
                pcrValues.digests[0].t.size = SHA1_DIGEST_SIZE;
                break;
            case TPM_ALG_SHA256:
                pcrValues.digests[0].t.size = SHA256_DIGEST_SIZE;
                break;
            case TPM_ALG_SHA384:
                pcrValues.digests[0].t.size = SHA384_DIGEST_SIZE;
                break;            
            case TPM_ALG_SHA512:
                pcrValues.digests[0].t.size = SHA512_DIGEST_SIZE;
                break;
            case TPM_ALG_SM3_256:
                pcrValues.digests[0].t.size = SM3_256_DIGEST_SIZE;
                break;
            default:
                pcrValues.digests[0].t.size = SHA1_DIGEST_SIZE;
                break;
        }

        if(filesize!=pcrValues.digests[0].t.size) {
            LOG_ERR("Input PCR file %s size mismatched the chosen PCR algorithm\n",
                ctx->raw_pcr_file);
            return -1;
        }

        fp = fopen(ctx->raw_pcr_file, "rb");
        for(i=0; i<pcrValues.digests[0].t.size; i++) {
            sz = fread(&pcrValues.digests[0].t.buffer[i],1,1,fp);
        }
        fclose(fp);
    } else {
        // Read PCRs
        rval = Tss2_Sys_PCR_Read( ctx->sapi_context, 0, &pcrs, &pcrUpdateCounter, 
            &pcrSelectionOut, &pcrValues, 0 );
        if( rval!=TPM_RC_SUCCESS ) {
            return rval;
        }    
    }
    
    // Calculate digest( with authhash alg) of pcrvalues in variable pcrDigest
    pcrDigest.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( pcrDigest );
    rval = tpm_hash_sequence( ctx->sapi_context, ctx->policy_session->authHash,
        pcrValues.count, &pcrValues.digests[0], &pcrDigest);
    if( rval!=TPM_RC_SUCCESS ){
        return rval;
    }

    rval = Tss2_Sys_PolicyPCR( ctx->sapi_context, 
        ctx->policy_session->sessionHandle, 0, &pcrDigest, &pcrs, 0 );

    return rval;
}

TPM_RC build_policy( createpolicypcr_ctx *ctx,
    TPM_RC (*build_policy_function )( createpolicypcr_ctx *ctx)) {
    // NOTE:  this policy_session will be a trial policy session
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric= {
            .algorithm = TPM_ALG_NULL,
    };

    TPM2B_NONCE nonceCaller = { { 0, } };
    nonceCaller.t.size = 0;
    
    // Start policy session.
    TPM_RC rval;
    rval = tpm_session_start_auth_with_params(ctx->sapi_context,
        &ctx->policy_session, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, 
        &encryptedSalt, TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA256);

    if( rval != TPM_RC_SUCCESS ){
        return rval;        
    }

    // Send policy command.
    rval = ( *build_policy_function )( ctx);
    if( rval!=TPM_RC_SUCCESS ){
        return rval;
    }

    // Get policy hash.
    ctx->policy_digest.t.size = 0;
    INIT_SIMPLE_TPM2B_SIZE( ctx->policy_digest );
    rval = Tss2_Sys_PolicyGetDigest( ctx->sapi_context, 
        ctx->policy_session->sessionHandle, 0, &ctx->policy_digest, 0 );
    if( rval!=TPM_RC_SUCCESS ){
        return rval;
    }

    printf("Created Policy Digest:\n");
    string_bytes_print_tpm2b(&ctx->policy_digest.b);

    //save the policy buffer in a file for use later
    if (saveDataToFile(ctx->policyfile, (UINT8 *)&ctx->policy_digest.t.buffer,
        ctx->policy_digest.t.size)) {
        LOG_ERR("Failed to save policy digest into file \"%s\"", ctx->policyfile);
        return -1;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext( ctx->sapi_context,
        ctx->policy_session->sessionHandle );
    if( rval!=TPM_RC_SUCCESS ){
        return rval;
    }

    // And remove the session from sessions table.
    rval = tpm_session_auth_end(ctx->policy_session);

    return rval;
}

static bool init(int argc, char *argv[], char *envp[], createpolicypcr_ctx *ctx) {
    
    unsigned policyfile_flag=0, pcr_index_flag=0, policy_type_pcr_flag=0,
             pcr_alg_flag=0; 
    
    struct option sOpts[] = {
            { "policyfile",     required_argument,  NULL,  'F' },
            { "policyPCR",      no_argument,        NULL,  'P' },
            { "pcrIndex",       required_argument,  NULL,  'I' },
            { "pcrAlg",         required_argument,  NULL,  'A' },
            { "pcrInputFile",   required_argument,  NULL,  'Q' },
            { NULL,             no_argument,        NULL, '\0' },
    };

    if (argc == 1) {
        execute_man(argv[0], envp);
        return false;
    }

    if (argc > (int) (2 * sizeof(sOpts) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "PF:I:A:Q:", sOpts, NULL)) != -1) {
        switch (opt) {
        case 'F':
            snprintf(ctx->policyfile, sizeof(ctx->policyfile), "%s", optarg);
            policyfile_flag=1;
            break;
        case 'P':
            printf("Policy type chosen is policyPCR.\n");
            policy_type_pcr_flag = 1;
            break;       
        case 'I':
            if(string_bytes_get_uint32(optarg, &ctx->pcr_index)!=true) {
                return false;
            }
            if(ctx->pcr_index > 23 || ctx->pcr_index<0) {
                printf("Invalid pcr_index %d. Choose between 0..23\n",
                    ctx->pcr_index );
                return false;
            }
            pcr_index_flag=1;
            break;
        case 'Q':
            snprintf(ctx->raw_pcr_file, sizeof(ctx->raw_pcr_file), "%s", optarg);
            ctx->raw_pcr_flag = 1;
            break;
        case 'A':
            if(string_bytes_get_uint16(optarg, &ctx->hash_alg)!=true) {
                return false;
            }
            pcr_alg_flag = 1;
            break;
        case '?':
        default:
            showArgMismatch(argv[0]);
            return false;
        }
    }

    if(!policyfile_flag || !pcr_index_flag) {
        showArgMismatch(argv[0]);
    }

    UINT32 rval = 0;
    if(policyfile_flag && pcr_index_flag) {
        LOG_INFO("Policy File = %s\n", ctx->policyfile);
        LOG_INFO("PCR Index= %d\n",ctx->pcr_index);
        rval = build_policy(ctx, build_pcr_policy);
        if( rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed build_policy\n");
        }
    }
    
    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused */
    (void) opts;

    createpolicypcr_ctx ctx = {
            .sapi_context = sapi_context,
            .policy_session = malloc(sizeof(SESSION)),
            .policy_digest = { 0 },
            .pcr_index = 0,
            .hash_alg = TPM_ALG_SHA1,
            .raw_pcr_flag = 0
    };

    bool result = init(argc, argv, envp, &ctx);
    if (!result) {
        return 1;
    }

    /* true is success, coerce to 0 for program success */
    return false;
}
