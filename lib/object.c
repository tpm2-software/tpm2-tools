#include "config.h"

#include <stdio.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tool_rc.h"
#include "tpm2_auth_util.h"

#define NULL_OBJECT "null"
#define NULL_OBJECT_LEN (sizeof(NULL_OBJECT) - 1)


#include <tss2/tss2_fapi.h>
#include <tss2/tss2_mu.h>

#define check(X) if (X != TSS2_RC_SUCCESS) { return TSS2_FAPI_RC_GENERAL_FAILURE; }

#define FAPI_ESYSBLOB_CONTEXTLOAD 1
#define FAPI_ESYSBLOB_DESERIALIZE 2
TSS2_RC Fapi_GetEsysBlobs(FAPI_CONTEXT *fctx, const char *path, uint8_t *type, uint8_t **data, size_t *length) {
    (void)(path);
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
    ESYS_TR esystr;
    check(Fapi_GetTcti(fctx, &tcti));
    check(Esys_Initialize(&esys, tcti, NULL));
    check(Esys_TR_FromTPMPublic(esys, 0x81000001, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &esystr));
    check(Esys_TR_Serialize(esys, esystr, data, length));
    Esys_Finalize(&esys);
    *type = FAPI_ESYSBLOB_DESERIALIZE;
    return TSS2_RC_SUCCESS;
}


static tool_rc do_ctx_file(ESYS_CONTEXT *ctx, const char *objectstr, FILE *f,
        tpm2_loaded_object *outobject) {
    /* assign a dummy transient handle */
    outobject->handle = TPM2_TRANSIENT_FIRST;
    outobject->path = objectstr;
    return files_load_tpm_context_from_file(ctx, &outobject->tr_handle, f);
}

static tool_rc tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth,
        bool do_auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    ESYS_CONTEXT *tmp_ctx = is_restricted_pswd_session ? NULL : ctx;

    if (do_auth) {
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_auth_util_from_optarg(tmp_ctx, auth, &s,
                is_restricted_pswd_session);
        if (rc != tool_rc_success) {
            return rc;
        }

        outobject->session = s;
    }

    if (!objectstr) {
        LOG_ERR("object string is empty");
        return tool_rc_general_error;
    }

//#ifdef FAPI_3_0
    if (!strncmp(objectstr, "tss2:", strlen("tss2:"))) {
        FAPI_CONTEXT *fapi;
        TSS2_RC rval = Fapi_Initialize(&fapi, NULL);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Fapi_Initialize, rval);
            return tool_rc_general_error;
        }
        uint8_t type;
        uint8_t *data;
        size_t length;

        rval = Fapi_GetEsysBlobs(fapi, &objectstr[strlen("tss2:")], &type, &data, &length);
        Fapi_Finalize(&fapi);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Fapi_GetEsysBlobs, rval);
            return tool_rc_general_error;
        }

        /* assign a dummy transient handle */
        outobject->handle = TPM2_TRANSIENT_FIRST;
        outobject->path = NULL;

        TPMS_CONTEXT blob;
        switch(type) {
        case FAPI_ESYSBLOB_CONTEXTLOAD:
            rval = Tss2_MU_TPMS_CONTEXT_Unmarshal(data, length, NULL, &blob);
            Fapi_Free(data);
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Tss2_MU_TPMS_CONTEXT_Unmarshal, rval);
                return tool_rc_general_error;
            }
            rval = Esys_ContextLoad(ctx, &blob, &outobject->tr_handle);
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Esys_ContextLoad, rval);
                return tool_rc_general_error;
            }
            return tool_rc_success;
        case FAPI_ESYSBLOB_DESERIALIZE:
            rval = Esys_TR_Deserialize(ctx, data, length, &outobject->tr_handle);
            Fapi_Free(data);
            if (!rval) {
                LOG_PERR(Esys_TR_Deserialize, rval);
                return tool_rc_general_error;
            }
            return tool_rc_success;
        default:
            Fapi_Free(data);
            return tool_rc_general_error;
        }
    }
//#endif /* FAPI_3_0 */

    // 1. Always attempt file
    FILE *f = fopen(objectstr, "rb");
    if (f) {
        tool_rc rc = do_ctx_file(ctx, objectstr, f, outobject);
        fclose(f);
        return rc;
    }

    // 2. Try to convert a hierarchy or raw handle
    TPMI_RH_PROVISION handle;
    bool result = tpm2_util_handle_from_optarg(objectstr, &handle, flags);
    if (result) {
        outobject->handle = handle;
        outobject->path = NULL;
        return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle,
                &outobject->tr_handle);
    }

    LOG_ERR("Cannot make sense of object context \"%s\"", objectstr);

    return tool_rc_general_error;
}

tool_rc tpm2_util_object_load(ESYS_CONTEXT *ctx, const char *objectstr,
        tpm2_loaded_object *outobject, tpm2_handle_flags flags) {

    return tpm2_util_object_load2(ctx, objectstr, NULL, false, outobject,
    false, flags);
}

tool_rc tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    return tpm2_util_object_load2(ctx, objectstr, auth, true, outobject,
            is_restricted_pswd_session, flags);
}
