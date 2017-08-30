#include <inttypes.h>
#include <stdlib.h>

#include <tcti/tcti_socket.h>
#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_util.h"

#define TCTI_SOCKET_DEFAULT_ADDRESS "127.0.0.1"
#define TCTI_SOCKET_DEFAULT_PORT     2321

#define TPM2TOOLS_ENV_SOCKET_ADDRESS "TPM2TOOLS_SOCKET_ADDRESS"
#define TPM2TOOLS_ENV_SOCKET_PORT    "TPM2TOOLS_SOCKET_PORT"

TSS2_TCTI_CONTEXT*
tpm2_tools_tcti_socket_init (char *opts)
{
    UNUSED(opts);

    TCTI_SOCKET_CONF conf = {
        .hostname          = TCTI_SOCKET_DEFAULT_ADDRESS,
        .port              = TCTI_SOCKET_DEFAULT_PORT,
        .logCallback       = NULL,
        .logBufferCallback = NULL,
        .logData           = NULL,
    };
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitSocketTcti (NULL, &size, &conf, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Faled to get allocation size for tcti context: "
                 "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("Allocation for tcti context failed: oom");
        return NULL;
    }
    rc = InitSocketTcti (tcti_ctx, &size, &conf, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to initialize tcti context: 0x%x\n", rc);
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
