#include <inttypes.h>
#include <stdlib.h>
#include <tcti/tcti-tabrmd.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_device.h>

#include "log.h"
#include "tpm2_util.h"

#define TPM2TOOLS_ENV_DEVICE_FILE    "TPM2TOOLS_DEVICE_FILE"
#define TCTI_DEVICE_DEFAULT_PATH "/dev/tpm0"

TSS2_TCTI_CONTEXT *tpm2_tools_tcti_device_init(char *opts) {
    TCTI_DEVICE_CONF conf = {
        .device_path = opts,
        .logCallback = NULL,
        .logData = NULL,
    };

    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitDeviceTcti(NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
                "Failed to get allocation size for device tcti context: "
                        "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("Allocation for device TCTI context failed: oom");
        return NULL;
    }
    rc = InitDeviceTcti(tcti_ctx, &size, &conf);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to initialize device TCTI context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
