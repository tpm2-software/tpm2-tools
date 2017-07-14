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
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "tpm2_util.h"
#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm_session.h"
#include "tpm_hash.h"
#include "pcr.h"

typedef struct createpolicypcr_ctx createpolicypcr_ctx;
struct createpolicypcr_ctx {
    //common policy options
    TSS2_SYS_CONTEXT *sapi_context;
    SESSION *policy_session;
    TPM2B_DIGEST policy_digest;
    char *policyfile;
    //build_pcr_policy options
    unsigned int pcr_index;
    UINT32 max_supported_pcrs;
    TPMI_ALG_HASH hash_alg;
    char *raw_pcr_file;
    struct {
        bool policy_type_pcr_flag;
        bool raw_pcr_flag;
        bool pcr_index_flag;
    } pcr_flags;
    tpm_table *t;
};

TPM_RC build_pcr_policy(createpolicypcr_ctx *ctx) {
    TPML_PCR_SELECTION pcrs = {
        .count = 1, 
        .pcrSelections[0] = {
            .hash = ctx->hash_alg,
            .sizeofSelect = ctx->max_supported_pcrs/8,
        },
    };
    pcrs.pcrSelections[0].pcrSelect[ (ctx->pcr_index/8) ] |= ( 1 << ( (ctx->pcr_index) % 8) );
    
    TPML_DIGEST pcr_values = { .count = pcrs.count };
    long filesize = 0;
    if (ctx->pcr_flags.raw_pcr_flag) {
        bool result = files_get_file_size(ctx->raw_pcr_file, &filesize);
        if (!result) {
            return 1;
        }

        switch (ctx->hash_alg) {
        case TPM_ALG_SHA1:
            pcr_values.digests[0].t.size = SHA1_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA256:
            pcr_values.digests[0].t.size = SHA256_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA384:
            pcr_values.digests[0].t.size = SHA384_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA512:
            pcr_values.digests[0].t.size = SHA512_DIGEST_SIZE;
            break;
        case TPM_ALG_SM3_256:
            pcr_values.digests[0].t.size = SM3_256_DIGEST_SIZE;
            break;
        default:
            pcr_values.digests[0].t.size = SHA1_DIGEST_SIZE;
            break;
        }

        if (filesize != pcr_values.digests[0].t.size) {
            LOG_ERR(
                    "Input PCR file %s size mismatched the chosen PCR algorithm\n",
                    ctx->raw_pcr_file);
            return -1;
        }

        FILE *fp = fopen(ctx->raw_pcr_file, "rb");
        if (!fp) {
            LOG_ERR("Could not open file \"%s\", error: %s", ctx->raw_pcr_file,
                    strerror(errno));
            return -1;
        }

        unsigned i;
        // TODO is byte by byte the best way here?
        for (i = 0; i < pcr_values.digests[0].t.size; i++) {
            size_t sz = fread(&pcr_values.digests[0].t.buffer[i], 1, 1, fp);
            if (sz != 1) {
                const char *msg = ferror(fp) ? strerror(errno) :
                        "end of file reached";
                LOG_ERR("Reading from file \"%s\" failed: %s",
                        ctx->raw_pcr_file, msg);
                fclose(fp);
                return -1;
            }
        }
        fclose(fp);

    } else {
        UINT32 pcr_update_counter;
        TPML_PCR_SELECTION pcr_selection_out;
        // Read PCRs
        TPM_RC rval = Tss2_Sys_PCR_Read(ctx->sapi_context, 0, &pcrs, &pcr_update_counter,
                &pcr_selection_out, &pcr_values, 0);
        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }
    }

    // Calculate digest( with authhash alg) of pcrvalues in variable pcr_digest
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM_RC rval = tpm_hash_sequence(ctx->sapi_context, ctx->policy_session->authHash,
            pcr_values.count, &pcr_values.digests[0], &pcr_digest);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

    rval = Tss2_Sys_PolicyPCR(ctx->sapi_context,
            ctx->policy_session->sessionHandle, 0, &pcr_digest, &pcrs, 0);

    return rval;
}

TPM_RC build_policy(createpolicypcr_ctx *ctx,
        TPM_RC (*build_policy_function)(createpolicypcr_ctx *ctx)) {
    // NOTE:  this policy_session will be a trial policy session
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM_ALG_NULL, };

    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;

    // Start policy session.
    TPM_RC rval = tpm_session_start_auth_with_params(ctx->sapi_context,
            &ctx->policy_session, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller,
            &encryptedSalt, TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA256);

    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed tpm session start auth with params\n");
        return rval;
    }

    // Send policy command.
    rval = (*build_policy_function)(ctx);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed build_policy_function\n");
        return rval;
    }

    // Get policy hash.
    rval = Tss2_Sys_PolicyGetDigest(ctx->sapi_context,
            ctx->policy_session->sessionHandle, 0, &ctx->policy_digest, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed Policy Get Digest\n");
        return rval;
    }

    LOG_INFO("Created Policy Digest:\n");

    //save the policy buffer in a file for use later or print hex to stdout.
    if (ctx->policyfile) {
        bool result = files_save_bytes_to_file(ctx->policyfile, (UINT8 *) &ctx->policy_digest.t.buffer,
                ctx->policy_digest.t.size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx->policyfile);
            return -1;
        }
    } else {

        char *s = tpm2_util_to_hex(ctx->policy_digest.t.buffer, ctx->policy_digest.t.size);
        if (!s) {
            LOG_ERR("oom");
            return TPM_RC_MEMORY;
        }

        TOOL_OUTPUT(ctx->t, "policy", s);

        free(s);
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(ctx->sapi_context,
            ctx->policy_session->sessionHandle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed Flush Context\n");
        return rval;
    }

    // And remove the session from sessions table.
    return tpm_session_auth_end(ctx->policy_session);
}

bool parse_policy_type(createpolicypcr_ctx *ctx, char *argv[]) {

    if (ctx->pcr_flags.policy_type_pcr_flag) {
        if (!ctx->policyfile || !ctx->pcr_flags.pcr_index_flag) {
            showArgMismatch(argv[0]);
            return false;
        } else {
            // pcr_index is unsigned... never can be less than 0
            TPM_RC rval = get_max_supported_pcrs(ctx->sapi_context,
                &ctx->max_supported_pcrs);
            if(rval != TPM_RC_SUCCESS) {
                LOG_ERR("Failure to read the capability data from TPM.\n");
                return false;
            }
            if (!ctx->max_supported_pcrs) {
                LOG_ERR("Failed to retrieve number of supported PCRs on the TPM\n");
                return false;
            }

            if (ctx->pcr_index > (ctx->max_supported_pcrs - 1)) {
                LOG_ERR("Invalid pcr_index %u. Choose between 0..%d\n",
                        ctx->pcr_index, ctx->max_supported_pcrs);
                return false;
            }

            LOG_INFO("Policy File = %s\n", ctx->policyfile);
            LOG_INFO("PCR Index= %d\n", ctx->pcr_index);
            rval = build_policy(ctx, build_pcr_policy);
            if (rval != TPM_RC_SUCCESS) {
                LOG_ERR("Failed build_policy\n");
                return false;
            }
        }
    }
    return true;
}

static bool init(int argc, char *argv[], createpolicypcr_ctx *ctx) {

    struct option sOpts[] = { 
        { "policy-file",    required_argument,  NULL,   'f' }, 
        { "policy-pcr",     no_argument,        NULL,  'P' }, 
        { "pcr-index",      required_argument,  NULL,   'i' }, 
        { "pcr-alg",        required_argument,  NULL,   'g' }, 
        { "pcr-input-file", required_argument,  NULL,   'F' }, 
        { NULL,             no_argument,        NULL,   '\0'}, 
    };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    if (argc > (int) (2 * sizeof(sOpts) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "Pf:i:g:F:", sOpts, NULL)) != -1) {
        switch (opt) {
        case 'f':
            ctx->policyfile = optarg;
            break;
        case 'P':
            ctx->pcr_flags.policy_type_pcr_flag = true;
            LOG_INFO("Policy type chosen is policyPCR.\n");
            break;
        case 'i':
            ctx->pcr_flags.pcr_index_flag = true;
            if (tpm2_util_string_to_uint32(optarg, &ctx->pcr_index) != true) {
                return false;
            }
            break;
        case 'F':
            ctx->raw_pcr_file = optarg;
            break;
        case 'g':
            result = tpm2_util_string_to_uint16(optarg, &ctx->hash_alg);
            if (!result) {
                return false;
            }
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }

    return true;
}

ENTRY_POINT(createpolicy) {

    /* opts and envp are unused */
    (void) opts;
    (void) envp;

    createpolicypcr_ctx ctx = { 
        .sapi_context = sapi_context, 
        .policy_session = NULL,
        .policy_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
        .pcr_index = 0,
        .max_supported_pcrs = 0,
        .hash_alg = TPM_ALG_SHA1,
        .policyfile = NULL,
        .raw_pcr_file = NULL,
        .pcr_flags.policy_type_pcr_flag = false,
        .pcr_flags.pcr_index_flag = false,
        .pcr_flags.raw_pcr_flag = false,
        .t = table
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    result = parse_policy_type(&ctx, argv);
    if (!result) {
        return 1;
    }

    /* true is success, coerce to 0 for program success */
    return 0;
}
