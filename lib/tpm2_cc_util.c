/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "log.h"
#include "tpm2_cc_util.h"

typedef struct cc_map cc_map;
struct cc_map {
    TPM2_CC cc;
    const char *str;
};

#define ADDCC(c) { .str = #c, .cc = c }

static const cc_map _g_map[] = {
    ADDCC(TPM2_CC_NV_UndefineSpaceSpecial),
    ADDCC(TPM2_CC_EvictControl),
    ADDCC(TPM2_CC_HierarchyControl),
    ADDCC(TPM2_CC_NV_UndefineSpace),
    ADDCC(TPM2_CC_ChangeEPS),
    ADDCC(TPM2_CC_ChangePPS),
    ADDCC(TPM2_CC_Clear),
    ADDCC(TPM2_CC_ClearControl),
    ADDCC(TPM2_CC_ClockSet),
    ADDCC(TPM2_CC_HierarchyChangeAuth),
    ADDCC(TPM2_CC_NV_DefineSpace),
    ADDCC(TPM2_CC_PCR_Allocate),
    ADDCC(TPM2_CC_PCR_SetAuthPolicy),
    ADDCC(TPM2_CC_PP_Commands),
    ADDCC(TPM2_CC_SetPrimaryPolicy),
    ADDCC(TPM2_CC_FieldUpgradeStart),
    ADDCC(TPM2_CC_ClockRateAdjust),
    ADDCC(TPM2_CC_CreatePrimary),
    ADDCC(TPM2_CC_NV_GlobalWriteLock),
    ADDCC(TPM2_CC_GetCommandAuditDigest),
    ADDCC(TPM2_CC_NV_Increment),
    ADDCC(TPM2_CC_NV_SetBits),
    ADDCC(TPM2_CC_NV_Extend),
    ADDCC(TPM2_CC_NV_Write),
    ADDCC(TPM2_CC_NV_WriteLock),
    ADDCC(TPM2_CC_DictionaryAttackLockReset),
    ADDCC(TPM2_CC_DictionaryAttackParameters),
    ADDCC(TPM2_CC_NV_ChangeAuth),
    ADDCC(TPM2_CC_PCR_Event),
    ADDCC(TPM2_CC_PCR_Reset),
    ADDCC(TPM2_CC_SequenceComplete),
    ADDCC(TPM2_CC_SetAlgorithmSet),
    ADDCC(TPM2_CC_SetCommandCodeAuditStatus),
    ADDCC(TPM2_CC_FieldUpgradeData),
    ADDCC(TPM2_CC_IncrementalSelfTest),
    ADDCC(TPM2_CC_SelfTest),
    ADDCC(TPM2_CC_Startup),
    ADDCC(TPM2_CC_Shutdown),
    ADDCC(TPM2_CC_StirRandom),
    ADDCC(TPM2_CC_ActivateCredential),
    ADDCC(TPM2_CC_Certify),
    ADDCC(TPM2_CC_PolicyNV),
    ADDCC(TPM2_CC_CertifyCreation),
    ADDCC(TPM2_CC_Duplicate),
    ADDCC(TPM2_CC_GetTime),
    ADDCC(TPM2_CC_GetSessionAuditDigest),
    ADDCC(TPM2_CC_NV_Read),
    ADDCC(TPM2_CC_NV_ReadLock),
    ADDCC(TPM2_CC_ObjectChangeAuth),
    ADDCC(TPM2_CC_PolicySecret),
    ADDCC(TPM2_CC_Rewrap),
    ADDCC(TPM2_CC_Create),
    ADDCC(TPM2_CC_ECDH_ZGen),
    ADDCC(TPM2_CC_HMAC),
    ADDCC(TPM2_CC_Import),
    ADDCC(TPM2_CC_Load),
    ADDCC(TPM2_CC_Quote),
    ADDCC(TPM2_CC_RSA_Decrypt),
    ADDCC(TPM2_CC_HMAC_Start),
    ADDCC(TPM2_CC_SequenceUpdate),
    ADDCC(TPM2_CC_Sign),
    ADDCC(TPM2_CC_Unseal),
    ADDCC(TPM2_CC_PolicySigned),
    ADDCC(TPM2_CC_ContextLoad),
    ADDCC(TPM2_CC_ContextSave),
    ADDCC(TPM2_CC_ECDH_KeyGen),
    ADDCC(TPM2_CC_EncryptDecrypt),
    ADDCC(TPM2_CC_FlushContext),
    ADDCC(TPM2_CC_LoadExternal),
    ADDCC(TPM2_CC_MakeCredential),
    ADDCC(TPM2_CC_NV_ReadPublic),
    ADDCC(TPM2_CC_PolicyAuthorize),
    ADDCC(TPM2_CC_PolicyAuthValue),
    ADDCC(TPM2_CC_PolicyCommandCode),
    ADDCC(TPM2_CC_PolicyCounterTimer),
    ADDCC(TPM2_CC_PolicyCpHash),
    ADDCC(TPM2_CC_PolicyLocality),
    ADDCC(TPM2_CC_PolicyNameHash),
    ADDCC(TPM2_CC_PolicyOR),
    ADDCC(TPM2_CC_PolicyTicket),
    ADDCC(TPM2_CC_ReadPublic),
    ADDCC(TPM2_CC_RSA_Encrypt),
    ADDCC(TPM2_CC_StartAuthSession),
    ADDCC(TPM2_CC_VerifySignature),
    ADDCC(TPM2_CC_ECC_Parameters),
    ADDCC(TPM2_CC_FirmwareRead),
    ADDCC(TPM2_CC_GetCapability),
    ADDCC(TPM2_CC_GetRandom),
    ADDCC(TPM2_CC_GetTestResult),
    ADDCC(TPM2_CC_Hash),
    ADDCC(TPM2_CC_PCR_Read),
    ADDCC(TPM2_CC_PolicyPCR),
    ADDCC(TPM2_CC_PolicyRestart),
    ADDCC(TPM2_CC_ReadClock),
    ADDCC(TPM2_CC_PCR_Extend),
    ADDCC(TPM2_CC_PCR_SetAuthValue),
    ADDCC(TPM2_CC_NV_Certify),
    ADDCC(TPM2_CC_EventSequenceComplete),
    ADDCC(TPM2_CC_HashSequenceStart),
    ADDCC(TPM2_CC_PolicyPhysicalPresence),
    ADDCC(TPM2_CC_PolicyDuplicationSelect),
    ADDCC(TPM2_CC_PolicyGetDigest),
    ADDCC(TPM2_CC_TestParms),
    ADDCC(TPM2_CC_Commit),
    ADDCC(TPM2_CC_PolicyPassword),
    ADDCC(TPM2_CC_ZGen_2Phase),
    ADDCC(TPM2_CC_EC_Ephemeral),
    ADDCC(TPM2_CC_PolicyNvWritten),
    ADDCC(TPM2_CC_PolicyTemplate),
    ADDCC(TPM2_CC_CreateLoaded),
    ADDCC(TPM2_CC_PolicyAuthorizeNV),
    ADDCC(TPM2_CC_EncryptDecrypt2),
    ADDCC(TPM2_CC_AC_GetCapability),
    ADDCC(TPM2_CC_AC_Send),
    ADDCC(TPM2_CC_Policy_AC_SendSelect),
    ADDCC(TPM2_CC_Vendor_TCG_Test),
};

bool tpm2_cc_util_from_str(const char *str, TPM2_CC *cc) {

    if (!str || !cc) {
        return false;
    }

    bool result = tpm2_util_string_to_uint32(str, cc);
    if (result) {
        return true;
    }

    size_t i;
    for (i = 0; i < ARRAY_LEN(_g_map); i++) {
        const cc_map *m = &_g_map[i];
        if (!strcmp(str, m->str)) {
            *cc = m->cc;
            return true;
        }
    }

    LOG_ERR("Could not convert command-code to number, got: \"%s\"", str);

    return false;
}

const char *tpm2_cc_util_to_str(TPM2_CC cc) {

    size_t i;
    for (i = 0; i < ARRAY_LEN(_g_map); i++) {
        const cc_map *m = &_g_map[i];
        if (m->cc == cc) {
            return m->str;
        }
    }

    /* we intentionally don't decode hex here so we don't have to keep
     * an internal buffer state that could be clobbered. Thus keeping it
     * reentrant and thread safe even though the tools never need thread
     * safety.
     *
     * DO NOT LOG ERROR as tpm2_getcap can have unknown commands and knows
     * how to deal with NULL returns.
     */

    return NULL;
}
