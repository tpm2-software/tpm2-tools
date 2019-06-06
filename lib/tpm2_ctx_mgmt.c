#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_ctx_mgmt.h"

#include <stdlib.h>

tool_rc tpm2_ctx_mgmt_evictcontrol(
        ESYS_CONTEXT *ectx,
        ESYS_TR auth,
        tpm2_session *sess,
        ESYS_TR objhandle,
        TPMI_DH_PERSISTENT phandle,
        ESYS_TR *out_tr) {

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, auth, sess);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for eviction target");
        return false;
    }

    ESYS_TR outHandle;
    tool_rc rc = tpm2_evictcontrol(ectx, auth, objhandle,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            phandle, &outHandle);

    if (rc != tool_rc_success) {
        return rc;
    }

    if (out_tr) {
        *out_tr = outHandle;
        return tool_rc_success;
    }

    return tpm2_close(ectx, &outHandle);
}
