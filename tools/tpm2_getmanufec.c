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
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>

#include <sapi/tpm20.h>

#include "main.h"
#include "options.h"
#include "string-bytes.h"
#include "tpm_hash.h"


int debugLevel = 0;
char outputFile[PATH_MAX];
char ownerPasswd[sizeof(TPMU_HA)];
char endorsePasswd[sizeof(TPMU_HA)];
char ekPasswd[sizeof(TPMU_HA)];
bool hexPasswd = false;
TPM_HANDLE persistentHandle;
UINT32 algorithmType = TPM_ALG_RSA;

char ECcertFile[PATH_MAX];
char *EKserverAddr = NULL;
unsigned int nonPersistentRead = 0;
unsigned int SSL_NO_VERIFY = 0;
unsigned int OfflineProv = 0;

BYTE authPolicy[] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
                     0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                     0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                     0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA};
int setKeyAlgorithm(UINT16 algorithm, TPM2B_PUBLIC *inPublic)
{
    inPublic->t.publicArea.nameAlg = TPM_ALG_SHA256;
    // First clear attributes bit field.
    *(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
    inPublic->t.publicArea.objectAttributes.restricted = 1;
    inPublic->t.publicArea.objectAttributes.userWithAuth = 0;
    inPublic->t.publicArea.objectAttributes.adminWithPolicy = 1;
    inPublic->t.publicArea.objectAttributes.sign = 0;
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic->t.publicArea.authPolicy.t.size = 32;
    memcpy(inPublic->t.publicArea.authPolicy.t.buffer, authPolicy, 32);

    inPublic->t.publicArea.type = algorithm;

    switch (algorithm)
    {
    case TPM_ALG_RSA:
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0x0;
        inPublic->t.publicArea.unique.rsa.t.size = 256;
        break;
    case TPM_ALG_KEYEDHASH:
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_SHA256;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        break;
    case TPM_ALG_ECC:
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.unique.ecc.x.t.size = 32;
        inPublic->t.publicArea.unique.ecc.y.t.size = 32;
        break;
    case TPM_ALG_SYMCIPHER:
        inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.unique.sym.t.size = 0;
        break;
    default:
        printf("\nThe algorithm type input(%4.4x) is not supported!\n", algorithm);
        return -1;
    }

    return 0;
}

int createEKHandle(TSS2_SYS_CONTEXT *sapi_context)
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_SENSITIVE_CREATE inSensitive = {{sizeof(TPM2B_SENSITIVE_CREATE)- 2,}};
    TPM2B_PUBLIC inPublic = {{sizeof(TPM2B_PUBLIC) - 2,}};
    TPM2B_DATA outsideInfo = { { 0, } };
    TPML_PCR_SELECTION creationPCR;

    TPM2B_NAME name = { { sizeof(TPM2B_NAME) - 2, } };

    TPM2B_PUBLIC outPublic = { { 0, } };
    TPM2B_CREATION_DATA creationData = { { 0, } };
    TPM2B_DIGEST creationHash = { { sizeof(TPM2B_DIGEST) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, };

    TPM_HANDLE handle2048ek;

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    /*
     * use enAuth in Tss2_Sys_CreatePrimary
     */
    if (strlen(endorsePasswd) > 0 && !hexPasswd) {
            sessionData.hmac.t.size = strlen(endorsePasswd);
            memcpy( &sessionData.hmac.t.buffer[0], endorsePasswd, sessionData.hmac.t.size );
    }
    else {
        if (strlen(endorsePasswd) > 0 && hexPasswd) {
                sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;

                if (hex2ByteStructure(endorsePasswd, &sessionData.hmac.t.size,
                                      sessionData.hmac.t.buffer) != 0) {
                        printf( "Failed to convert Hex format password for endorsePasswd.\n");
                        return -1;
                }
        }
    }

    if (strlen(ekPasswd) > 0 && !hexPasswd) {
        inSensitive.t.sensitive.userAuth.t.size = strlen(ekPasswd);
        memcpy( &inSensitive.t.sensitive.userAuth.t.buffer[0], ekPasswd,
                inSensitive.t.sensitive.userAuth.t.size );
    }
    else {
        if (strlen(ekPasswd) > 0 && hexPasswd) {
             inSensitive.t.sensitive.userAuth.t.size = sizeof(inSensitive.t.sensitive.userAuth) - 2;
             if (hex2ByteStructure(ekPasswd, &inSensitive.t.sensitive.userAuth.t.size,
                                   inSensitive.t.sensitive.userAuth.t.buffer) != 0) {
                  printf( "Failed to convert Hex format password for ekPasswd.\n");
                  return -1;
            }
        }
    }

    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    if (setKeyAlgorithm(algorithmType, &inPublic) )
          return -1;

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(sapi_context, TPM_RH_ENDORSEMENT, &sessionsData,
                                  &inSensitive, &inPublic, &outsideInfo,
                                  &creationPCR, &handle2048ek, &outPublic,
                                  &creationData, &creationHash, &creationTicket,
                                  &name, &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS ) {
          printf("\nTPM2_CreatePrimary Error. TPM Error:0x%x\n", rval);
          return -2;
    }
    printf("\nEK create succ.. Handle: 0x%8.8x\n", handle2048ek);

    if (!nonPersistentRead) {
         /*
          * To make EK persistent, use own auth
          */
         sessionData.hmac.t.size = 0;
         if (strlen(ownerPasswd) > 0 && !hexPasswd) {
             sessionData.hmac.t.size = strlen(ownerPasswd);
             memcpy( &sessionData.hmac.t.buffer[0], ownerPasswd, sessionData.hmac.t.size );
         }
         else {
            if (strlen(ownerPasswd) > 0 && hexPasswd) {
                sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
                if (hex2ByteStructure(ownerPasswd, &sessionData.hmac.t.size,
                                   sessionData.hmac.t.buffer) != 0) {
                 printf( "Failed to convert Hex format password for ownerPasswd.\n");
                 return -1;
                }
            }
        }

        rval = Tss2_Sys_EvictControl(sapi_context, TPM_RH_OWNER, handle2048ek,
                                     &sessionsData, persistentHandle, &sessionsDataOut);
        if (rval != TPM_RC_SUCCESS ) {
            printf("\nEvictControl:Make EK persistent Error. TPM Error:0x%x\n", rval);
            return -3;
        }
        printf("EvictControl EK persistent succ.\n");
    }

    rval = Tss2_Sys_FlushContext(sapi_context,
                                 handle2048ek);
    if (rval != TPM_RC_SUCCESS ) {
        printf("\nFlush transient EK failed. TPM Error:0x%x\n", rval);
        return -4;
    }

    printf("Flush transient EK succ.\n");

    /* TODO this serialization is not correct */
    if (!files_save_bytes_to_file(outputFile, (UINT8 *)&outPublic, sizeof(outPublic))) {
        printf("\nFailed to save EK pub key into file(%s)\n", outputFile);
        return -5;
    }

    return 0;
}

unsigned char *HashEKPublicKey(void)
{
    printf("Calculating the SHA256 hash of the Endorsement Public Key\n");
    FILE *fp;
    unsigned char EKpubKey[259];
    fp = fopen(outputFile, "rb");
    if (fp == NULL) {
        printf("File Open Error\n");
    }
    else {
        fseek(fp, 0x66, 0);
        size_t read = fread(EKpubKey, 1, 256, fp);
        if (read != 256) {
            printf ("Could not read whole file.");
            return NULL;
        }
    }
    fclose(fp);

    unsigned char *hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    if (hash == NULL) {
        printf ("Memory allocation failed.");
        return NULL;
    }

    EKpubKey[256] = 0x01;
    EKpubKey[257] = 0x00;
    EKpubKey[258] = 0x01; //Exponent
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, EKpubKey, sizeof(EKpubKey));
    SHA256_Final(hash, &sha256);
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return hash;
}

char *Base64Encode(const unsigned char* buffer)
{
    printf("Calculating the Base64Encode of the hash of the Endorsement Public Key:\n");
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, SHA256_DIGEST_LENGTH);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    char *b64text = (*bufferPtr).data;
    int i;
    for (i = 0; i < strlen(b64text); i++) {
        if (b64text[i] == '+') {
            b64text[i] = '-';
        }
        if (b64text[i] == '/') {
            b64text[i] = '_';
        }
    }
    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_escape(curl, b64text, strlen(b64text));
        if (output) {
            strncpy(b64text, output, strlen(output));
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    printf("%s\n", b64text);
    return b64text;
}

int RetrieveEndorsementCredentials(char *b64h)
{
    printf("Retrieving Endorsement Credential Certificate from the TPM Manufacturer EK Provisioning Server\n");
    char *weblink = (char*)malloc(1 + strlen(b64h) + strlen(EKserverAddr));
    if (weblink == NULL) {
        printf ("Memory allocation failed.");
        return -1;
    }
    memset(weblink, 0, (1 + strlen(b64h) + strlen(EKserverAddr)));
    strcat(weblink, EKserverAddr);
    strcat(weblink, b64h);
    printf("%s\n", weblink);
    CURL *curl;
    CURLcode res;

    FILE * respfile;
    respfile = fopen(ECcertFile, "wb");

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        /*
         * should not be used - Used only on platforms with older CA certificates.
         */
        if (SSL_NO_VERIFY) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        }
        curl_easy_setopt(curl, CURLOPT_URL, weblink);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, respfile);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, respfile);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "\ncurl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    printf("\n");
    free(weblink);
    return 0;
}


int TPMinitialProvisioning(void)
{
    if (EKserverAddr == NULL) {
        printf("TPM Manufacturer Endorsement Credential Server Address cannot be NULL\n");
        return -99;
    }
    RetrieveEndorsementCredentials(Base64Encode(HashEKPublicKey()));
    return 0;
}

int execute_tool (int argc, char *argv[], char *envp[], common_opts_t *opts,
                  TSS2_SYS_CONTEXT *sapi_context)
{
    static const char*optstring = "e:o:H:P:g:f:X:N:O:E:S:U";

    static struct option long_options[] =
    {
        { "endorsePasswd", 1, NULL, 'e' },
        { "ownerPasswd"  , 1, NULL, 'o' },
        { "handle"       , 1, NULL, 'H' },
        { "ekPasswd"     , 1, NULL, 'P' },
        { "alg"          , 1, NULL, 'g' },
        { "file"         , 1, NULL, 'f' },
        { "passwdInHex"  , 0, NULL, 'X' },
        { "NonPersistent", 0, NULL, 'N' },
        { "OfflineProv"  , 0, NULL, 'O' },
        { "ECcertFile"   , 1, NULL, 'E' },
        { "EKserverAddr" , 1, NULL, 'S' },
        { "SSL_NO_VERIFY", 0, NULL, 'U' },
        { NULL           , 0, NULL,  0  },
    };

    if (argc > (int)(2 * sizeof(long_options) / sizeof(struct option)) ) {
        showArgMismatch(argv[0]);
        return -1;
    }

    int opt;
    while ( ( opt = getopt_long( argc, argv, optstring, long_options, NULL ) ) != -1 ) {
              switch ( opt ) {
                case 'H':
                    if (getSizeUint32Hex(optarg, &persistentHandle) ) {
                        printf("\nPlease input the handle used to make EK persistent(hex) in correct format.\n");
                        return -2;
                    }
                    break;

                case 'e':
                    if (optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) ) {
                        printf("\nPlease input the endorsement password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA) - 1);
                        return -3;
                    }
                    snprintf(endorsePasswd, sizeof(endorsePasswd), "%s", optarg);
                    break;

                case 'o':
                    if (optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) ) {
                        printf("\nPlease input the owner password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA) - 1);
                        return -4;
                    }
                    snprintf(ownerPasswd, sizeof(ownerPasswd), "%s", optarg);
                    break;

                case 'P':
                    if (optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) ) {
                        printf("\nPlease input the EK password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA) - 1);
                        return -5;
                    }
                    snprintf(ekPasswd, sizeof(ekPasswd), "%s", optarg);
                    break;

                case 'g':
                    if (getSizeUint32Hex(optarg, &algorithmType) ) {
                        printf("\nPlease input the algorithm type in correct format.\n");
                        return -6;
                    }
                    break;

                case 'f':
                    if (optarg == NULL ) {
                        printf("\nPlease input the file used to save the pub ek.\n");
                        return -7;
                    }
                    snprintf(outputFile, sizeof(outputFile), "%s", optarg);
                    break;

                case 'X':
                    hexPasswd = true;
                    break;

                case 'E':
                    if (optarg == NULL ) {
                        printf("\nPlease input the file used to save the EC Certificate retrieved from server\n");
                        return -99;
                    }
                    snprintf(ECcertFile, sizeof(ECcertFile), "%s", optarg);
                    break;
                case 'N':
                    nonPersistentRead = 1;
                    printf("Tss2_Sys_CreatePrimary called with Endorsement Handle without making it persistent\n");
                    break;
                case 'O':
                    OfflineProv = 1;
                    printf("Setting up for offline provisioning - reading the retrieved EK specified by the file \n");
                    break;
                case 'U':
                    SSL_NO_VERIFY = 1;
                    printf("CAUTION: TLS communication with the said TPM manufacturer server setup with SSL_NO_VERIFY!\n");
                    break;
                case 'S':
                    if (optarg == NULL ) {
                        printf("TPM Manufacturer Endorsement Credential Server Address cannot be NULL\n");
                        return -99;
                    }
                    EKserverAddr = (char *)malloc(strlen(optarg));
                    if (EKserverAddr == NULL) {
                        printf ("Memory allocation failed.");
                        return -99;
                    }
                    strncpy(EKserverAddr, optarg, strlen(optarg));
                    printf("TPM Manufacturer EK provisioning address -- %s\n", EKserverAddr);
                    break;
            }
    }

    int return_val = 1;
    int provisioning_return_val = 0;
    if (argc < 2) {
        showArgMismatch(argv[0]);
        return -1;
    }
    else {
        if (!OfflineProv) {
            return_val  = createEKHandle(sapi_context);
        }
        provisioning_return_val = TPMinitialProvisioning();
    }

    if (return_val && provisioning_return_val) {
        return -11;
    }

    return 0;
}
