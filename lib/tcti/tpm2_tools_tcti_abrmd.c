#include <inttypes.h>
#include <stdlib.h>
#include <tcti/tcti-tabrmd.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_util.h"

//#ifdef HAVE_TCTI_DEV
//#include <tcti/tcti_device.h>
//#endif
//#ifdef HAVE_TCTI_SOCK
//#include <tcti/tcti_socket.h>
//#endif

TSS2_TCTI_CONTEXT *tpm2_tools_tcti_abrmd_init(char *opts) {

    UNUSED(opts);

    TSS2_RC rc;
    size_t size;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = tss2_tcti_tabrmd_init(NULL, &size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to get size for TABRMD TCTI context: 0x%" PRIx32, rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("Allocation for TABRMD TCTI context failed: oom");
        return NULL;
    }
    rc = tss2_tcti_tabrmd_init(tcti_ctx, &size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("Failed to initialize TABRMD TCTI context: 0x%" PRIx32, rc);
        free(tcti_ctx);
        return NULL;
    }

    return tcti_ctx;
}
