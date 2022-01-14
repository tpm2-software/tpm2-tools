/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_policy.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policy_ctx tpm2_policy_ctx;
struct tpm2_policy_ctx {
    TSS2_POLICY_CALLBACKS cb;
    const char *policy_file;
};

static tpm2_policy_ctx ctx;

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected single file path argument");
        return false;
    }

    ctx.policy_file = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
//    static const struct option topts[] = {
//        { "type",   required_argument, NULL, 't' },
//        { "format", required_argument, NULL, 'f' },
//    };

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    TSS2_POLICY *policy_ctx = NULL;

    TSS2_RC rc = Tss2_PolicyInstantiate(
        ctx.policy_file,
        &ctx.cb,
        &policy_ctx);
    if (rc) {
        LOG_ERR("Instantiate failed");
        return tool_rc_general_error;
    }

    TPMU_HA digest = { 0 };
    rc = Tss2_PolicyCalculate(
            policy_ctx,
            TPM2_ALG_SHA256,
            &digest);
    if (rc) {
        LOG_ERR("Calculate failed");
        return tool_rc_general_error;
    }

    printf("hash: ");
    tpm2_util_hexdump2(stdout, digest.sha256, 32);
    printf("\n");

    /* TODO TAKE USER INPUTS */
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = { 0 };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_NULL
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };

    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };

    TPM2B_NONCE nonceCaller = {
        .size = 32,
        .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
    };

    TPM2B_DATA outsideInfo = { 0 };
    TPML_PCR_SELECTION creationPCR = { 0 };
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    ESYS_TR session = ESYS_TR_NONE;

    rc = Esys_CreatePrimary(ectx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (rc) {
        LOG_ERR("CreatePrimary failed");
        return tool_rc_general_error;
    }

    rc = Esys_StartAuthSession(ectx,
            primaryHandle, // tpm key
            ESYS_TR_NONE,  // bind key
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, // sessions
            &nonceCaller, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &session);
    if (rc) {
        LOG_ERR("StartAuthSession failed");
        return tool_rc_general_error;
    }

    rc = Tss2_PolicyExecute(
        TPM2_ALG_SHA256,
        policy_ctx,
        ectx,
        session);
    if (rc) {
        LOG_ERR("Execute failed");
        return tool_rc_general_error;
    }

    /* AFter execute hashes should match */
    TPM2B_DIGEST *digest2 = NULL;
    rc = Esys_PolicyGetDigest(ectx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest2);
    if (rc) {
        LOG_ERR("Esys_PolicyGetDigest failed");
        return tool_rc_general_error;
    }

    printf("hash: ");
    tpm2_util_hexdump2(stdout, digest2->buffer, digest2->size);
    printf("\n");
    Esys_Free(digest2);

    const char *description = NULL;
    rc = Tss2_PolicyGetDescription(policy_ctx, &description);
    if (rc) {
        LOG_ERR("Tss2_PolicyGetDescription failed");
        return tool_rc_general_error;
    }

    printf("description: \"%s\"\n", description);

    printf("success\n");
    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policy", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
