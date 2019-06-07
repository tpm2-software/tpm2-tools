#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2_auth_util.h"

#define FILE_PREFIX "file:"
#define FILE_PREFIX_LEN (sizeof(FILE_PREFIX) - 1)

#define NULL_OBJECT "null"
#define NULL_OBJECT_LEN (sizeof(NULL_OBJECT) - 1)

static tool_rc tpm2_util_object_load2(
            ESYS_CONTEXT *ctx,
            const char *objectstr,
            const char *auth,
            bool do_auth,
            tpm2_loaded_object *outobject) {

    if (do_auth) {
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_auth_util_from_optarg(ctx, auth, &s, false);
        if (rc != tool_rc_success) {
            return rc;
        }

        outobject->session = s;
    }

    // 0. If objecstr is NULL return error
    if (!objectstr) {
        LOG_ERR("tpm2_util_object_load called with empty objectstr parameter");
        return tool_rc_general_error;
    }

    // 1. If the objectstr starts with a file: prefix, treat as a context file
    bool starts_with_file = !strncmp(objectstr, FILE_PREFIX, FILE_PREFIX_LEN);
    if (starts_with_file) {
        outobject->handle = 0;
        outobject->path = objectstr += FILE_PREFIX_LEN;
        return files_load_tpm_context_from_path(ctx,
                &outobject->tr_handle, outobject->path);
    }

    // 2. If the objstr is "null" set the handle to RH_NULL
    bool is_rh_null = !strncmp(objectstr, NULL_OBJECT, NULL_OBJECT_LEN);
    if (is_rh_null){
        outobject->path = NULL;
        outobject->tr_handle = ESYS_TR_RH_NULL;
        outobject->handle = TPM2_RH_NULL;
        return tool_rc_success;
    }

    // 3. Try to load objectstr as a TPM2_HANDLE
    bool result = tpm2_util_string_to_uint32(objectstr,
                    &outobject->handle);
    if (result) {
        outobject->path = NULL;
        return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle, &outobject->tr_handle);
    }

    // 4. we must assume the whole value is a file path
    outobject->handle = 0;
    outobject->path = objectstr;
    return files_load_tpm_context_from_path(ctx,
            &outobject->tr_handle, outobject->path);
}

tool_rc tpm2_util_object_load(ESYS_CONTEXT *ctx,
            const char *objectstr, tpm2_loaded_object *outobject) {

    return tpm2_util_object_load2(ctx, objectstr, NULL, false, outobject);
}

tool_rc tpm2_util_object_load_auth(
            ESYS_CONTEXT *ctx,
            const char *objectstr,
            const char *auth,
            tpm2_loaded_object *outobject) {

    return tpm2_util_object_load2(ctx, objectstr, auth, true, outobject);
}
