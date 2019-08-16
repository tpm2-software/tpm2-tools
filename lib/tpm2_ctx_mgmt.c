#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_ctx_mgmt.h"

tool_rc tpm2_ctx_mgmt_evictcontrol(ESYS_CONTEXT *ectx, ESYS_TR auth,
        tpm2_session *sess, ESYS_TR objhandle, TPMI_DH_PERSISTENT phandle,
        ESYS_TR *out_tr) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx, auth, sess, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    ESYS_TR out_handle;

    TSS2_RC rval = Esys_EvictControl(ectx, auth, objhandle, shandle1,
            ESYS_TR_NONE, ESYS_TR_NONE, phandle, &out_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_EvictControl, rval);
        return tool_rc_from_tpm(rval);
    }

    if (out_tr) {
        *out_tr = out_handle;
        return tool_rc_success;
    }

    return tpm2_close(ectx, &out_handle);
}
