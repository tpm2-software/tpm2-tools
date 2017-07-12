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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "tpm2_util.h"
#include "password_util.h"
#include "files.h"
#include "main.h"
#include "options.h"

TSS2_SYS_CONTEXT *sysContext;
TPMS_AUTH_COMMAND sessionData = {
    .sessionHandle = TPM_RS_PW,
    .nonce = TPM2B_EMPTY_INIT,
    .hmac = TPM2B_EMPTY_INIT,
    .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
};

bool hexPasswd = false;

int setAlg(TPMI_ALG_PUBLIC type,TPMI_ALG_HASH nameAlg,TPM2B_PUBLIC *inPublic, int I_flag, bool is_policy_enforced)
{
    switch(nameAlg)
    {
    case TPM_ALG_SHA1:
    case TPM_ALG_SHA256:
    case TPM_ALG_SHA384:
    case TPM_ALG_SHA512:
    case TPM_ALG_SM3_256:
    case TPM_ALG_NULL:
        inPublic->t.publicArea.nameAlg = nameAlg;
        break;
    default:
        printf("nameAlg algrithm: 0x%0x not support !\n", nameAlg);
        return -1;
    }

    // First clear attributes bit field.
    *(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
    inPublic->t.publicArea.objectAttributes.restricted = 0;
    //check if auth policy needs to be enforced
    inPublic->t.publicArea.objectAttributes.userWithAuth = !is_policy_enforced;        
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.sign = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic->t.publicArea.type = type;
    switch(type)
    {
    case TPM_ALG_RSA:
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        inPublic->t.publicArea.objectAttributes.decrypt = 0;
        if (I_flag)
        {
            // sealing
            inPublic->t.publicArea.objectAttributes.sign = 0;
            inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 0;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
        }
        else
        {
            // hmac
            inPublic->t.publicArea.objectAttributes.sign = 1;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM_ALG_ECC:
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.unique.ecc.x.t.size = 0;
        inPublic->t.publicArea.unique.ecc.y.t.size = 0;
        break;

    case TPM_ALG_SYMCIPHER:
        inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.unique.sym.t.size = 0;
        break;

    default:
        printf("type algrithm: 0x%0x not support !\n",type);
        return -2;
    }
    return 0;
}

int create(TPMI_DH_OBJECT parentHandle, TPM2B_PUBLIC *inPublic, TPM2B_SENSITIVE_CREATE *inSensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, const char *opuFilePath, const char *oprFilePath, int o_flag, int O_flag, int I_flag, int A_flag, UINT32 objectAttributes, bool is_policy_enforced)
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

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;
    if (sessionData.hmac.t.size > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (tpm2_util_hex_to_byte_structure((char *)sessionData.hmac.t.buffer,
                              &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for parent Passwd.\n");
            return -1;
        }
    }

    if (inSensitive->t.sensitive.userAuth.t.size > 0 && hexPasswd)
    {
        inSensitive->t.sensitive.userAuth.t.size = sizeof(inSensitive->t.sensitive.userAuth) - 2;
        if (tpm2_util_hex_to_byte_structure((char *)inSensitive->t.sensitive.userAuth.t.buffer,
                              &inSensitive->t.sensitive.userAuth.t.size,
                              inSensitive->t.sensitive.userAuth.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for object Passwd.\n");
            return -1;
        }
    }
    inSensitive->t.size = inSensitive->t.sensitive.userAuth.b.size + 2;

    if(setAlg(type, nameAlg, inPublic, I_flag, is_policy_enforced))
        return -1;

    if(A_flag == 1)
        inPublic->t.publicArea.objectAttributes.val = objectAttributes;
    printf("ObjectAttribute: 0x%08X\n",inPublic->t.publicArea.objectAttributes.val);

    creationPCR.count = 0;

    rval = Tss2_Sys_Create(sysContext, parentHandle, &sessionsData, inSensitive, inPublic,
            &outsideInfo, &creationPCR, &outPrivate,&outPublic,&creationData, &creationHash,
            &creationTicket, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nCreate Object Failed ! ErrorCode: 0x%0x\n\n",rval);
        return -2;
    }
    printf("\nCreate Object Succeed !\n");

    /*
     * TODO These public and private serializations are not safe since its outputting size as well.
     */
    if(o_flag == 1)
    {
        if(!files_save_bytes_to_file(opuFilePath, (UINT8 *)&outPublic, sizeof(outPublic)))
            return -3;
    }
    if(O_flag == 1)
    {
        if(!files_save_bytes_to_file(oprFilePath, (UINT8 *)&outPrivate, sizeof(outPrivate)))
            return -4;
    }

    return 0;
}

int
execute_tool (int              argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context)
{
    (void)envp;
    (void)opts;

    sysContext = sapi_context;

    TPM2B_SENSITIVE_CREATE  inSensitive = TPM2B_EMPTY_INIT;

    TPM2B_PUBLIC            inPublic;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT parentHandle;
    UINT32 objectAttributes = 0;
    char opuFilePath[PATH_MAX] = {0};
    char oprFilePath[PATH_MAX] = {0};
    char *contextParentFilePath = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "H:P:K:g:G:A:I:L:o:O:c:XE";
    static struct option long_options[] = {
      {"parent",1,NULL,'H'},
      {"pwdp",1,NULL,'P'},
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"kalg",1,NULL,'G'},
      {"objectAttributes",1,NULL,'A'},
      {"inFile",1,NULL,'I'},
      {"policy-file",1,NULL,'L'},
      {"enforce-policy",1,NULL,'E'},
      {"opu",1,NULL,'o'},
      {"opr",1,NULL,'O'},
      {"contextParent",1,NULL,'c'},
      {"passwdInHex",0,NULL,'X'},
      {0,0,0,0}
    };


    int returnVal = 0;
    int flagCnt = 0;
    int H_flag = 0,
        P_flag = 0,
        K_flag = 0,
        g_flag = 0,
        G_flag = 0,
        A_flag = 0,
        I_flag = 0,
        L_flag = 0,
        o_flag = 0,
        c_flag = 0,
        O_flag = 0;
	bool is_policy_enforced = false;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'H':
            if(!tpm2_util_string_to_uint32(optarg,&parentHandle))
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            H_flag = 1;
            break;

        case 'P':
            if(!password_tpm2_util_copy_password(optarg, "Parent key password", &sessionData.hmac))
            {
                returnVal = -2;
                break;
            }
            P_flag = 1;
            break;
        case 'K':
            if(!password_tpm2_util_copy_password(optarg, "Key password", &inSensitive.t.sensitive.userAuth))
            {
                returnVal = -3;
                break;
            }
            K_flag = 1;
            break;
        case 'g':
            if(!tpm2_util_string_to_uint16(optarg,&nameAlg))
            {
                showArgError(optarg, argv[0]);
                returnVal = -4;
                break;
            }
            printf("nameAlg = 0x%4.4x\n", nameAlg);
            g_flag = 1;
            break;
        case 'G':
            if(!tpm2_util_string_to_uint16(optarg,&type))
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            printf("type = 0x%4.4x\n", type);
            G_flag = 1;
            break;
        case 'A':
            if(!tpm2_util_string_to_uint32(optarg,&objectAttributes))
            {
                showArgError(optarg, argv[0]);
                returnVal = -6;
                break;
            }
            A_flag = 1;//H_flag = 1;
            break;
        case 'I':
            inSensitive.t.sensitive.data.t.size = sizeof(inSensitive.t.sensitive.data) - 2;
            if(!files_load_bytes_from_file(optarg, inSensitive.t.sensitive.data.t.buffer, &inSensitive.t.sensitive.data.t.size))
            {
                returnVal = -7;
                break;
            }
            I_flag = 1;
            printf("inSensitive.t.sensitive.data.t.size = %d\n",inSensitive.t.sensitive.data.t.size);
            break;
        case 'L':
            inPublic.t.publicArea.authPolicy.t.size = sizeof(inPublic.t.publicArea.authPolicy) - 2;
            if(!files_load_bytes_from_file(optarg, inPublic.t.publicArea.authPolicy.t.buffer, &inPublic.t.publicArea.authPolicy.t.size))
            {
                returnVal = -8;
                break;
            }
            L_flag = 1;
            break;
        case 'E':
            is_policy_enforced = true;
            break;
        case 'o':
            snprintf(opuFilePath, sizeof(opuFilePath), "%s", optarg);
            if(files_does_file_exist(opuFilePath) != 0)
            {
                returnVal = -9;
                break;
            }
            o_flag = 1;
            break;
        case 'O':
            snprintf(oprFilePath, sizeof(oprFilePath), "%s", optarg);
            if(files_does_file_exist(oprFilePath) != 0)
            {
                returnVal = -10;
                break;
            }
            O_flag = 1;
            break;
        case 'c':
            contextParentFilePath = optarg;
            if(contextParentFilePath == NULL || contextParentFilePath[0] == '\0')
            {
                returnVal = -11;
                break;
            }
            printf("contextParentFile = %s\n", contextParentFilePath);
            c_flag = 1;
            break;
        case 'X':
            hexPasswd = true;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -14;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -15;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;

    if(P_flag == 0)
        sessionData.hmac.t.size = 0;
    if(I_flag == 0)
        inSensitive.t.sensitive.data.t.size = 0;
    if(K_flag == 0)
        inSensitive.t.sensitive.userAuth.t.size = 0;
    if(L_flag == 0)
        inPublic.t.publicArea.authPolicy.t.size = 0;

    flagCnt = H_flag + g_flag + G_flag + c_flag ;
    if(flagCnt == 1)
    {
        showArgMismatch(argv[0]);
        return -16;
    }
    else if(flagCnt == 3 && (H_flag == 1 || c_flag == 1) && g_flag == 1 && G_flag == 1)
    {
        if(c_flag)
            returnVal = file_load_tpm_context_from_file(sysContext, &parentHandle, contextParentFilePath) != true;
        if(returnVal == 0)
            returnVal = create(parentHandle, &inPublic, &inSensitive, type, nameAlg, opuFilePath, oprFilePath, o_flag, O_flag, I_flag, A_flag, objectAttributes, is_policy_enforced);

        if(returnVal)
            return -17;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -18;
    }
    return 0;
}
