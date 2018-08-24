#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_ctx_mgmt.h"

bool tpm2_ctx_mgmt_evictcontrol(ESYS_CONTEXT *ectx,
        ESYS_TR auth,
        TPMS_AUTH_COMMAND *sdata,
        tpm2_session *sess,
        ESYS_TR objhandle,
        TPMI_DH_PERSISTENT phandle) {

    TSS2_RC rval;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, auth, sdata, sess);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for eviction target");
        return false;
    }

    ESYS_TR outHandle;
    rval = Esys_EvictControl(ectx, auth, objhandle,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            phandle, &outHandle);

    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_EvictControl, rval);
        switch(rval) {
            case TSS2_ESYS_RC_BAD_TR:
                LOG_ERR("Bad TR");
                break;
            default:
            break;
        }
        return false;
    }

    rval = Esys_TR_Close(ectx, &outHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_Close, rval);
    }

    return true;
}
