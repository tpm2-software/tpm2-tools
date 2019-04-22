//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "conversion.h"
#include "tpm2_alg_util.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct {
    int size;
    UINT32 id[24];
} PCR_LIST;

static TPMS_AUTH_COMMAND sessionData = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW);
static char *outFilePath;
static char *signature_path;
static char *message_path;
static signature_format sig_format;
static TPMI_ALG_HASH sig_hash_algorithm;
static TPM2B_DATA qualifyingData = TPM2B_EMPTY_INIT;
static TPML_PCR_SELECTION  pcrSelections;
static bool is_auth_session;
static TPMI_SH_AUTH_SESSION auth_session_handle;
static int k_flag, c_flag, l_flag, g_flag, L_flag, o_flag, G_flag, P_flag;
static char *contextFilePath;
static TPM2_HANDLE akHandle;

static void PrintBuffer( UINT8 *buffer, UINT32 size )
{
    UINT32 i;
    for( i = 0; i < size; i++ )
    {
        tpm2_tool_output("%2.2x", buffer[i]);
    }
    tpm2_tool_output("\n");
}

static bool write_output_files(TPM2B_ATTEST *quoted, TPMT_SIGNATURE *signature) {

    bool res = true;
    if (signature_path) {
        res &= tpm2_convert_signature(signature, sig_format, signature_path);
    }

    if (message_path) {
        res &= files_save_bytes_to_file(message_path,
                (UINT8*)quoted->attestationData,
                quoted->size);
    }

    return res;
}

static int quote(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE akHandle, TPML_PCR_SELECTION *pcrSelection)
{
    UINT32 rval;
    TPMT_SIG_SCHEME inScheme;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, { sessionData }};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_ATTEST quoted = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData);
    TPMT_SIGNATURE signature;

    if (is_auth_session) {
        sessionsData.auths[0].sessionHandle = auth_session_handle;
    }

    if(!G_flag || !get_signature_scheme(sapi_context, akHandle, sig_hash_algorithm, &inScheme)) {
        inScheme.scheme = TPM2_ALG_NULL;
    }

    memset( (void *)&signature, 0, sizeof(signature) );

    rval = TSS2_RETRY_EXP(Tss2_Sys_Quote(sapi_context, akHandle, &sessionsData,
            &qualifyingData, &inScheme, pcrSelection, &quoted,
            &signature, &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS)
    {
        printf("\nQuote Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -1;
    }

    tpm2_tool_output( "\nquoted:\n " );
    tpm2_util_print_tpm2b( (TPM2B *)&quoted );
    //PrintTPM2B_ATTEST(&quoted);
    tpm2_tool_output( "\nsignature:\n " );
    PrintBuffer( (UINT8 *)&signature, sizeof(signature) );
    //PrintTPMT_SIGNATURE(&signature);

    bool res = write_output_files(&quoted, &signature);
    return res == true ? 0 : 1;
}

static bool on_option(char key, char *value) {

    switch(key)
    {
    case 'k':
        if(!tpm2_util_string_to_uint32(value, &akHandle))
        {
            LOG_ERR("Invalid AK handle, got\"%s\"", value);
            return false;
        }
        k_flag = 1;
        break;
    case 'c':
        contextFilePath = optarg;
        c_flag = 1;
        break;

    case 'P': {
        bool res = tpm2_password_util_from_optarg(value, &sessionData.hmac);
        if (!res) {
            LOG_ERR("Invalid AK password, got\"%s\"", value);
            return false;
        }
        P_flag = 1;
    } break;
    case 'l':
        if(!pcr_parse_list(value, strlen(value), &pcrSelections.pcrSelections[0]))
        {
            LOG_ERR("Could not parse pcr list, got: \"%s\"", value);
            return false;
        }
        l_flag = 1;
        break;
    case 'g':
        pcrSelections.pcrSelections[0].hash = tpm2_alg_util_from_optarg(optarg);
        if (pcrSelections.pcrSelections[0].hash == TPM2_ALG_ERROR)
        {
            LOG_ERR("Could not convert pcr hash selection, got: \"%s\"", value);
            return false;
        }
        pcrSelections.count = 1;
        g_flag = 1;
        break;
    case 'L':
        if(!pcr_parse_selections(value, &pcrSelections))
        {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        L_flag = 1;
        break;
    case 'o':
        outFilePath = optarg;
        o_flag = 1;
        break;
    case 'q':
        qualifyingData.size = sizeof(qualifyingData) - 2;
        if(tpm2_util_hex_to_byte_structure(value,&qualifyingData.size,qualifyingData.buffer) != 0)
        {
            LOG_ERR("Could not convert \"%s\" from a hex string to byte array!", value);
            return false;
        }
        break;
    case 'S':
         if (!tpm2_util_string_to_uint32(value, &auth_session_handle)) {
             LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                     optarg);
             return false;
         }
         is_auth_session = true;
         break;
    case 's':
         signature_path = optarg;
         break;
    case 'm':
         message_path = optarg;
         break;
    case 'f':
         sig_format = tpm2_parse_signature_format(optarg);

         if (sig_format == signature_format_err) {
            return false;
         }
         break;
    case 'G':
        sig_hash_algorithm = tpm2_alg_util_from_optarg(optarg);
        if(sig_hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signature hash algorithm selection, got: \"%s\"", value);
            return false;
        }
        G_flag = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "ak-handle",             required_argument, NULL, 'k' },
        { "ak-context",            required_argument, NULL, 'c' },
        { "ak-password",           required_argument, NULL, 'P' },
        { "id-list",               required_argument, NULL, 'l' },
        { "algorithm",            required_argument, NULL, 'g' },
        { "sel-list",              required_argument, NULL, 'L' },
        { "qualify-data",          required_argument, NULL, 'q' },
        { "input-session-handle", required_argument, NULL, 'S' },
        { "signature",            required_argument, NULL, 's' },
        { "message",              required_argument, NULL, 'm' },
        { "format",               required_argument, NULL, 'f' },
        { "sig-hash-algorithm",   required_argument, NULL, 'G' }
    };

    *opts = tpm2_options_new("k:c:P:l:g:L:S:q:s:m:f:G:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!l_flag && !L_flag) {
        LOG_ERR("Expected either -l or -L to be specified");
        return 1;
    }

    if(c_flag) {
        bool result = files_load_tpm_context_from_file(sapi_context, &akHandle, contextFilePath);
        if (!result) {
            return 1;
        }
    }

    if (P_flag == 0) {
        sessionData.hmac.size = 0;
    }

    return quote(sapi_context, akHandle, &pcrSelections);
}
