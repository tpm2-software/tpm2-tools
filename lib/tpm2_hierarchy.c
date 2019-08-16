/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tool_rc.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"

tool_rc tpm2_hierarchy_create_primary(ESYS_CONTEXT *ectx, tpm2_session *sess,
        tpm2_hierarchy_pdata *objdata) {

    ESYS_TR hierarchy;

    hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(objdata->in.hierarchy);

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx, hierarchy, sess, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Couldn't get shandle for hierarchy");
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
