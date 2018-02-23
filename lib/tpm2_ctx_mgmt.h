#ifndef LIB_TPM2_CTX_MGMT_H_
#define LIB_TPM2_CTX_MGMT_H_

/**
 * Invokes evictcontrol for manipulating the persistence of loaded
 * objects in TPM memory.
 * @param sapi_context
 *  The system api context
 * @param sdata
 *  The authorization data.
 * @param objhandle
 *  The object handle to manipulate.
 * @param phandle
 *  The persistent handle to use.
 * @return
 *  True on success, False on error.
 *  Use LOG_PERR() to output error information.
 */
bool tpm2_ctx_mgmt_evictcontrol(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_PROVISION provision,
        TPMS_AUTH_COMMAND *sdata,
        TPMI_DH_OBJECT objhandle,
        TPMI_DH_PERSISTENT phandle);

#endif /* LIB_TPM2_CTX_MGMT_H_ */
