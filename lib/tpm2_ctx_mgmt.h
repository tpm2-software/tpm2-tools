#ifndef LIB_TPM2_CTX_MGMT_H_
#define LIB_TPM2_CTX_MGMT_H_

#include "tpm2_session.h"

/**
 * Invokes evictcontrol for manipulating the persistence of loaded
 * objects in TPM memory.
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param auth
 *  The authorisation hierarchy, either TPM2_RH_OWNER or TPM2_RH_PLATFORM
 * @param sdata
 *  The authorization data for auth.
 * @param objhandle
 *  The object handle of a loaded object to manipulate.
 * @param phandle
 *  The handle to persist objhandle at, if objhandle is transient.
 * @return
 *  True on success, False on error.
 *  Use LOG_PERR() to output error information.
 */
bool tpm2_ctx_mgmt_evictcontrol(ESYS_CONTEXT *context,
        ESYS_TR auth,
        TPMS_AUTH_COMMAND *sdata,
        tpm2_session *sess,
        ESYS_TR objhandle,
        TPMI_DH_PERSISTENT phandle);

#endif /* LIB_TPM2_CTX_MGMT_H_ */
