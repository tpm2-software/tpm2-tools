#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_ctx_mgmt.h"

bool tpm2_ctx_mgmt_evictcontrol(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_PROVISION provision,
        TPMS_AUTH_COMMAND *sdata,
        TPMI_DH_OBJECT objhandle,
        TPMI_DH_PERSISTENT phandle) {

    TSS2L_SYS_AUTH_COMMAND sessionsData =
        TSS2L_SYS_AUTH_COMMAND_INIT(1, { *sdata });

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context,
        provision,
        objhandle,
        &sessionsData,
        phandle,
        &sessionsDataOut));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_EvictControl, rval);
        return false;
    }

    return true;
}
