/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tool_rc.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_alg_util.h"
#include "tpm2_hierarchy.h"

tool_rc tpm2_hierarchy_create_primary(ESYS_CONTEXT *ectx, tpm2_session *sess,
        tpm2_hierarchy_pdata *objdata, TPM2B_DIGEST *cp_hash) {

    ESYS_TR hierarchy;

    hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(objdata->in.hierarchy);

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx, hierarchy, sess, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Couldn't get shandle for hierarchy");
        return rc;
    }

    if (cp_hash) {
        /*
         * Need sys_context to be able to calculate CpHash
         */
        TSS2_SYS_CONTEXT *sys_context = NULL;
        rc = tpm2_getsapicontext(ectx, &sys_context);
        if(rc != tool_rc_success) {
            LOG_ERR("Failed to acquire SAPI context.");
            return rc;
        }

        TSS2_RC rval = Tss2_Sys_CreatePrimary_Prepare(sys_context,
        objdata->in.hierarchy, &objdata->in.sensitive, &objdata->in.public,
        &objdata->in.outside_info, &objdata->in.creation_pcr);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_CreatePrimary_Prepare, rval);
            return tool_rc_general_error;
        }

        TPM2B_NAME *name1 = NULL;
        rc = tpm2_tr_get_name(ectx, hierarchy, &name1);
        if (rc != tool_rc_success) {
            goto tpm2_create_free_name1;
        }

        cp_hash->size = tpm2_alg_util_get_hash_size(
            tpm2_session_get_authhash(sess));
        rc = tpm2_sapi_getcphash(sys_context, name1, NULL, NULL,
            tpm2_session_get_authhash(sess), cp_hash);

        /*
         * Exit here without making the ESYS call since we just need the cpHash
         */
tpm2_create_free_name1:
        Esys_Free(name1);
        return rc;
    }

    return tpm2_create_primary(ectx, hierarchy, shandle1, ESYS_TR_NONE,
            ESYS_TR_NONE, &objdata->in.sensitive, &objdata->in.public,
            &objdata->in.outside_info, &objdata->in.creation_pcr,
            &objdata->out.handle, &objdata->out.public,
            &objdata->out.creation.data, &objdata->out.hash,
            &objdata->out.creation.ticket);
}

void tpm2_hierarchy_pdata_free(tpm2_hierarchy_pdata *objdata) {

    free(objdata->out.creation.data);
    objdata->out.creation.data = NULL;
    free(objdata->out.creation.ticket);
    objdata->out.creation.ticket = NULL;
    free(objdata->out.hash);
    objdata->out.hash = NULL;
    free(objdata->out.public);
    objdata->out.public = NULL;
}
