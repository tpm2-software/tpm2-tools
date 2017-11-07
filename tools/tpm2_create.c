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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT parent_handle;
    char *input;
    char *opu_path;
    char *opr_path;
    char *context_parent_path;
    struct {
        UINT16 H : 1;
        UINT16 P : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 G : 1;
        UINT16 A : 1;
        UINT16 I : 1;
        UINT16 L : 1;
        UINT16 o : 1;
        UINT16 c : 1;
        UINT16 O : 1;
    } flags;
};

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .t = { \
        .publicArea = { \
            .objectAttributes = { \
                .val = TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN|TPMA_OBJECT_FIXEDTPM \
                      |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN| \
					  TPMA_OBJECT_USERWITHAUTH \
            }, \
        }, \
    }, \
}

static tpm_create_ctx ctx = {
    .session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    },
    .type = TPM_ALG_SHA1,
    .nameAlg = TPM_ALG_RSA,
    .in_public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT
};

int setup_alg()
{
    switch(ctx.nameAlg) {
    case TPM_ALG_SHA1:
    case TPM_ALG_SHA256:
    case TPM_ALG_SHA384:
    case TPM_ALG_SHA512:
    case TPM_ALG_SM3_256:
    case TPM_ALG_NULL:
        ctx.in_public.t.publicArea.nameAlg = ctx.nameAlg;
        break;
    default:
        LOG_ERR("nameAlg algrithm: 0x%0x not support !", ctx.nameAlg);
        return -1;
    }

    switch(ctx.in_public.t.publicArea.type) {
    case TPM_ALG_RSA:
        ctx.in_public.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.rsaDetail.keyBits = 2048;
        ctx.in_public.t.publicArea.parameters.rsaDetail.exponent = 0;
        ctx.in_public.t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        ctx.in_public.t.publicArea.unique.keyedHash.t.size = 0;
        ctx.in_public.t.publicArea.objectAttributes.decrypt = 0;
        if (ctx.flags.I) {
            // sealing
            ctx.in_public.t.publicArea.objectAttributes.sign = 0;
            ctx.in_public.t.publicArea.objectAttributes.sensitiveDataOrigin = 0;
            ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
        } else {
            // hmac
            ctx.in_public.t.publicArea.objectAttributes.sign = 1;
            ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
            ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = ctx.nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM_ALG_ECC:
        ctx.in_public.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        ctx.in_public.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.unique.ecc.x.t.size = 0;
        ctx.in_public.t.publicArea.unique.ecc.y.t.size = 0;
        break;

    case TPM_ALG_SYMCIPHER:
        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                          &ctx.in_public.t.publicArea.objectAttributes);

        ctx.in_public.t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        ctx.in_public.t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        ctx.in_public.t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        ctx.in_public.t.publicArea.unique.sym.t.size = 0;
        break;

    default:
        LOG_ERR("type algrithm: 0x%0x not support !", ctx.in_public.t.publicArea.type);
        return -2;
    }
    return 0;
}

int create(TSS2_SYS_CONTEXT *sapi_context)
{
    TPM_RC rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE           outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionDataArray[0] = &ctx.session_data;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &ctx.session_data;

    ctx.in_sensitive.t.size = ctx.in_sensitive.t.sensitive.userAuth.b.size + 2;

    if(setup_alg())
        return -1;

    tpm2_tool_output("ObjectAttribute: 0x%08X\n", ctx.in_public.t.publicArea.objectAttributes.val);

    creationPCR.count = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx.parent_handle, &sessionsData, &ctx.in_sensitive,
                           &ctx.in_public, &outsideInfo, &creationPCR, &outPrivate,&outPublic,
                           &creationData, &creationHash, &creationTicket, &sessionsDataOut));
    if(rval != TPM_RC_SUCCESS) {
        LOG_ERR("\nCreate Object Failed ! ErrorCode: 0x%0x\n",rval);
        return -2;
    }
    tpm2_tool_output("\nCreate Object Succeed !\n");

    /*
     * TODO These public and private serializations are not safe since its outputting size as well.
     */
    if(ctx.flags.o == 1) {
        if(!files_save_bytes_to_file(ctx.opu_path, (UINT8 *)&outPublic, sizeof(outPublic)))
            return -3;
    }

    if(ctx.flags.O == 1) {
        if(!files_save_bytes_to_file(ctx.opr_path, (UINT8 *)&outPrivate, sizeof(outPrivate)))
            return -4;
    }

    return 0;
}

static bool on_option(char key, char *value) {

    bool res;

    switch(key) {
    case 'H':
        if(!tpm2_util_string_to_uint32(value, &ctx.parent_handle)) {
            LOG_ERR("Invalid parent handle, got\"%s\"", value);
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'P':
        res = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!res) {
            LOG_ERR("Invalid parent key password, got\"%s\"", value);
            return false;
        }
        ctx.flags.P = 1;
        break;
    case 'K':
        res = tpm2_password_util_from_optarg(value, &ctx.in_sensitive.t.sensitive.userAuth);
        if (!res) {
            LOG_ERR("Invalid key password, got\"%s\"", value);
            return false;
        }
        ctx.flags.K = 1;
        break;
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value);
        if(ctx.nameAlg == TPM_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'G':
        ctx.in_public.t.publicArea.type = tpm2_alg_util_from_optarg(value);
        if(ctx.in_public.t.publicArea.type == TPM_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
            return false;
        }

        ctx.flags.G = 1;
        break;
    case 'A': {
        bool res = tpm2_attr_util_obj_from_optarg(value,
                &ctx.in_public.t.publicArea.objectAttributes);
        if(!res) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
        ctx.flags.A = 1;
    } break;
    case 'I':
        ctx.input = value;
        ctx.flags.I = 1;
        break;
    case 'L':
        ctx.in_public.t.publicArea.authPolicy.t.size = sizeof(ctx.in_public.t.publicArea.authPolicy) - 2;
        if(!files_load_bytes_from_path(value, ctx.in_public.t.publicArea.authPolicy.t.buffer,
                                       &ctx.in_public.t.publicArea.authPolicy.t.size)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'u':
        ctx.opu_path = value;
        if(files_does_file_exist(ctx.opu_path) != 0) {
            return false;
        }
        ctx.flags.o = 1;
        break;
    case 'r':
        ctx.opr_path = value;
        if(files_does_file_exist(ctx.opr_path) != 0) {
            return false;
        }
        ctx.flags.O = 1;
        break;
    case 'c':
        ctx.context_parent_path = value;
        if(ctx.context_parent_path == NULL || ctx.context_parent_path[0] == '\0') {
            return false;
        }
        ctx.flags.c = 1;
        break;
    };

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      {"parent",1,NULL,'H'},
      {"pwdp",1,NULL,'P'},
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"kalg",1,NULL,'G'},
      {"object-attributes",1,NULL,'A'},
      {"in-file",1,NULL,'I'},
      {"policy-file",1,NULL,'L'},
      {"pubfile",1,NULL,'u'},
      {"privfile",1,NULL,'r'},
      {"context-parent",1,NULL,'c'},
      {"input-session-handle",1,NULL,'S'},
      {0,0,0,0}
    };

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    *opts = tpm2_options_new("H:P:K:g:G:A:I:L:u:r:c:S:", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    bool is_stdin = !strcmp(ctx.input, "-");
    FILE *file =  !is_stdin ? fopen(ctx.input, "rb") : stdin;
    char *path = !is_stdin ? ctx.input : "<stdin>";
    if (!file) {
        LOG_ERR("Could not open file: \"%s\", error: %s", path, strerror(errno));
        return false;
    }

    /*
     * Attempt to accurately read the file based on the file size.
     * This may fail on stdin when it's a pipe.
     */
    if (is_stdin) {
        path = NULL;
    }

    ctx.in_sensitive.t.sensitive.data.t.size = BUFFER_SIZE(typeof(ctx.in_sensitive.t.sensitive.data), buffer);
    bool res = files_load_bytes_from_file(file, ctx.in_sensitive.t.sensitive.data.t.buffer,
            &ctx.in_sensitive.t.sensitive.data.t.size, path);

    if (!res) {
        res = true;
        ctx.in_sensitive.t.sensitive.data.t.size = fread(ctx.in_sensitive.t.sensitive.data.t.buffer, 1,
                ctx.in_sensitive.t.sensitive.data.t.size, file);
        if (!feof(file)) {
            LOG_ERR("Data to be sealed larger than expected. Got %u expected %u",
                    ctx.in_sensitive.t.sensitive.data.t.size, res);
            res = false;
        }
        else if (ferror(file)) {
            LOG_ERR("Error reading sealed data from \"<stdin>\"");
            res = false;
        }
    }

    if (!is_stdin) {
        fclose(file);
    }

    return res;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int returnVal = 0;
    int flagCnt = 0;

    if(ctx.flags.P == 0)
        ctx.session_data.hmac.t.size = 0;

    if (ctx.flags.I) {
        bool res = load_sensitive();
        if (!res) {
            return 1;
        }
    }

    if (ctx.flags.I && ctx.in_public.t.publicArea.type != TPM_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return 1;
    }

    flagCnt = ctx.flags.H + ctx.flags.g + ctx.flags.G + ctx.flags.c;
    if(flagCnt == 1) {
        return 1;
    } else if(flagCnt == 3 && (ctx.flags.H == 1 || ctx.flags.c == 1) &&
              ctx.flags.g == 1 && ctx.flags.G == 1) {
        if(ctx.flags.c)
            returnVal = files_load_tpm_context_from_file(sapi_context,
                                                         &ctx.parent_handle, ctx.context_parent_path) != true;
        if(returnVal == 0)
            returnVal = create(sapi_context);

        if(returnVal)
            return 1;
    } else {
        return 1;
    }

    return 0;
}
