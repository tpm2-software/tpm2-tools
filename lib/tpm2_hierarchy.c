/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_util.h"

/**
 * Parses a hierarchy value from an option argument.
 * @param value
 *  The string to parse, which can be a numerical string as
 *  understood by strtoul() with a base of 0, or an:
 *    - o - Owner hierarchy
 *    - p - Platform hierarchy
 *    - e - Endorsement hierarchy
 *    - n - Null hierarchy
 * @param hierarchy
 *  The parsed hierarchy as output.
 * @param flags
 *  What hierarchies should be supported by
 *  the parsing.
 * @return
 *  True on success, False otherwise.
 */

static bool filter_hierarchy_handles(TPMI_RH_PROVISION hierarchy,
    tpm2_hierarchy_flags flags) {

    switch(hierarchy) {
        case TPM2_RH_OWNER:
            if ( !(flags & TPM2_HIERARCHY_FLAGS_O) ) {
                LOG_ERR("Unexpected handle - TPM2_RH_OWNER");
                return false;
            }
            break;
        case TPM2_RH_PLATFORM:
            if ( !(flags & TPM2_HIERARCHY_FLAGS_P) ) {
                LOG_ERR("Unexpected handle - TPM2_RH_PLATFORM");
                return false;
            }
            break;
        case TPM2_RH_ENDORSEMENT:
            if ( !(flags & TPM2_HIERARCHY_FLAGS_E) ) {
                LOG_ERR("Unexpected handle - TPM2_RH_ENDORSEMENT");
                return false;
            }
            break;
        case TPM2_RH_NULL:
            if ( !(flags & TPM2_HIERARCHY_FLAGS_N) ) {
                LOG_ERR("Unexpected handle - TPM2_RH_NULL");
                return false;
            }
            break;
        case TPM2_RH_LOCKOUT:
            if ( !(flags & TPM2_HIERARCHY_FLAGS_L) ) {
                LOG_ERR("Unexpected handle - TPM2_RH_LOCKOUT");
                return false;
            }
            break;
        default: //If specified a random offset to the permanent handle range
            if (flags == TPM2_HANDLES_ALL ||
                flags == TPM2_HIERARCHY_FLAGS_NONE) {
                return true;
            }
            return false;
    }

    return true;
}

static bool filter_handles(TPMI_RH_PROVISION *hierarchy, tpm2_hierarchy_flags flags) {

    bool result = true;
    switch(*hierarchy & TPM2_HR_RANGE_MASK) {
        case 0: //If user simply specifies an index offset
          if (flags & TPM2_HANDLES_FLAGS_NV) {
             *hierarchy += TPM2_HR_NV_INDEX;
          }
        /* fall through */
        case TPM2_HR_NV_INDEX:
            if ( !(flags & TPM2_HANDLES_FLAGS_NV) ) {
                LOG_ERR("NV-Index handle not supported by this command.");
                return false;
            }
            break;
        case TPM2_HR_PERMANENT:
            result = filter_hierarchy_handles(*hierarchy, flags);
            if (!result) {
                return false;
            }
            break;
        case TPM2_HR_TRANSIENT:
            if ( !(flags & TPM2_HANDLES_FLAGS_TRANSIENT) ) {
                LOG_ERR("Transient handles not supported by this command.");
                return false;
            }
            break;
        default: //If specified a random number as tpm handle range
            if (flags == TPM2_HANDLES_ALL ||
                flags == TPM2_HIERARCHY_FLAGS_NONE) {
                return true;
            }
            return false;
    }

    return true;
}

bool tpm2_hierarchy_from_optarg(const char *value,
        TPMI_RH_PROVISION *hierarchy, tpm2_hierarchy_flags flags) {

    if (!value || !value[0]) {
        return false;
    }

    *hierarchy = 0;

    bool is_o = !strncmp(value, "owner", strlen(value));
    if (is_o) {
        *hierarchy = TPM2_RH_OWNER;
    }

    bool is_p = !strncmp(value, "platform", strlen(value));
    if (is_p) {
        *hierarchy = TPM2_RH_PLATFORM;
    }

    bool is_e = !strncmp(value, "endorsement", strlen(value));
    if (is_e) {
        *hierarchy = TPM2_RH_ENDORSEMENT;
    }

    bool is_n = !strncmp(value, "null", strlen(value));
    if (is_n) {
        *hierarchy = TPM2_RH_NULL;
    }

    bool is_l = !strncmp(value, "lockout", strlen(value));
    if (is_l) {
        *hierarchy = TPM2_RH_LOCKOUT;
    }

    bool result = true;
    if (!*hierarchy) {
        /*
         * This branch is executed when hierarchy is specified as a hex handle.
         * The raw hex returned may be a generic (non hierarchy) TPM2_HANDLE.
         */
        result = tpm2_util_string_to_uint32(value, hierarchy);
    }
    if (!result) {

        char msg[256] = { 0 };

        char print_flags[32] = { '[', '\0' };

        if (flags & TPM2_HIERARCHY_FLAGS_O) {
            strncat(print_flags, "o|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HIERARCHY_FLAGS_P) {
            strncat(print_flags, "p|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HIERARCHY_FLAGS_E) {
            strncat(print_flags, "e|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HIERARCHY_FLAGS_N) {
            strncat(print_flags, "n|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HIERARCHY_FLAGS_L) {
            strncat(print_flags, "l|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        size_t len = strlen(print_flags);
        if (print_flags[len -1] == '|') {
            len--;
            print_flags[len] = '\0';
        }

        strncat(print_flags, "]",
                sizeof(print_flags) - strlen(print_flags) - 1);
        len++;

        bool has_print_flags = len > 2;

        if (has_print_flags) {
            snprintf(msg, sizeof(msg), "expected %s or ", print_flags);
        }

        strncat(msg, "a handle number",
                sizeof(msg) - strlen(msg) - 1);

        LOG_ERR("Incorrect handle value, got: \"%s\", expected %s",
                 value, msg);
        return false;
    }

    /*
     * If the caller specifies the expected valid hierarchies, either as string,
     * or hex handles, they are additionally filtered here.
     */

    return filter_handles(hierarchy, flags);
}

tool_rc tpm2_hierarchy_create_primary(ESYS_CONTEXT *ectx,
        tpm2_session *sess,
        tpm2_hierarchy_pdata *objdata) {

    ESYS_TR hierarchy;

    hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(objdata->in.hierarchy);

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx, hierarchy, sess, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Couldn't get shandle for hierarchy");
        return rc;
    }

    return tpm2_create_primary(ectx, hierarchy,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            &objdata->in.sensitive, &objdata->in.public,
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
