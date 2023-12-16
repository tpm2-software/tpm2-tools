/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_yaml.h"

typedef struct tpm_sessionconfig_ctx tpm_sessionconfig_ctx;
struct tpm_sessionconfig_ctx {
    tpm2_session *session;
    const char *session_path;
    TPMA_SESSION bmask;
    TPMA_SESSION flags;
    bool is_policy_session;
};

static tpm_sessionconfig_ctx ctx;

struct {
    TPMA_SESSION attr;
    char *attr_string;
} session_attr_tab[6] =
    { { TPMA_SESSION_CONTINUESESSION, "continuesession" },
      { TPMA_SESSION_AUDITEXCLUSIVE, "auditexclusive" },
      { TPMA_SESSION_AUDITRESET, "auditreset" },
      { TPMA_SESSION_DECRYPT, "decrypt" },
      { TPMA_SESSION_ENCRYPT, "encrypt" },
      { TPMA_SESSION_AUDIT, "audit" }
    };

#define MAX_ATTR_STR_LEN 80

void get_session_attr_str(TPMA_SESSION attrs, char *attr_str, size_t attr_str_size) {
    attr_str[0] = '\0';
    
    for (size_t i = 0; i < ARRAY_LEN(session_attr_tab); i++) {
        if (attrs & session_attr_tab[i].attr) {
            int size = strlen(attr_str);
            if (size == 0) {
                snprintf(attr_str, attr_str_size, "%s",
                          &session_attr_tab[i].attr_string[0]);
            } else {
                snprintf(attr_str + size, attr_str_size - size, "|%s",
                          &session_attr_tab[i].attr_string[0]);
            }
        }
    }
}

static tool_rc process_output(ESYS_CONTEXT *esys_context, tpm2_yaml *y) {

    char session_attr_str[MAX_ATTR_STR_LEN];
    ESYS_TR sessionhandle = tpm2_session_get_handle(ctx.session);
    if (!sessionhandle) {
        LOG_ERR("Session handle cannot be null");
        return tool_rc_general_error;
    }

    if (ctx.bmask) {
        return Esys_TRSess_SetAttributes(esys_context, sessionhandle, ctx.flags,
            ctx.bmask);
    }

    TPM2_HANDLE tpm_handle;
    TSS2_RC rv = Esys_TR_GetTpmHandle(esys_context, sessionhandle, &tpm_handle);
    if (rv != TSS2_RC_SUCCESS) {
        return tool_rc_general_error;
    }

    /*
     * Describe session attributes
     */
    TPMA_SESSION attrs = 0;
    tool_rc rc = tpm2_sess_get_attributes(esys_context, sessionhandle,
        &attrs);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_yaml_add_kv_uintx32("Session-Handle", tpm_handle, y);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not create yaml session handle digest.");
        return rc;
    }

    get_session_attr_str(attrs, session_attr_str, MAX_ATTR_STR_LEN);
    rc = tpm2_yaml_add_kv_str("Session-Attributes" , session_attr_str, y);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not create yaml session attributes digest.");
        return rc;
    }

    if (ctx.is_policy_session) {
        TPM2B_DIGEST *digest = NULL;
        rc = tpm2_policy_get_digest(esys_context, ctx.session, &digest, NULL,
            TPM2_ALG_NULL);
        if (rc != tool_rc_success) {
            LOG_ERR("Cannot read policy digest");
            goto session_digest_out;
        }

        rc = tpm2_yaml_add_kv_tpm2b("Session-Digest", (TPM2B *)digest, y);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not create yaml session digest.");
            return rc;
        }

session_digest_out:
        Esys_Free(digest);
    }

    return rc;
}

static tool_rc process_input(ESYS_CONTEXT *esys_context) {

    tool_rc rc = tpm2_session_restore(esys_context, ctx.session_path, false,
        &ctx.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not restore session from the specified file");
        return rc;
    }

    ctx.is_policy_session =
        (tpm2_session_get_type(ctx.session) == TPM2_SE_POLICY);

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
        case 0:
            ctx.bmask |= TPMA_SESSION_CONTINUESESSION;
            ctx.flags |= TPMA_SESSION_CONTINUESESSION;
            break;
        case 1:
            ctx.bmask |= TPMA_SESSION_CONTINUESESSION;
            break;
        case 2:
            ctx.bmask |= TPMA_SESSION_AUDITEXCLUSIVE;
            ctx.flags |= TPMA_SESSION_AUDITEXCLUSIVE;
            break;
        case 3:
            ctx.bmask |= TPMA_SESSION_AUDITEXCLUSIVE;
            break;
        case 4:
            ctx.bmask |= TPMA_SESSION_AUDITRESET;
            ctx.flags |= TPMA_SESSION_AUDITRESET;
            break;
        case 5:
            ctx.bmask |= TPMA_SESSION_AUDITRESET;
            break;
        case 6:
            ctx.bmask |= TPMA_SESSION_DECRYPT;
            ctx.flags |= TPMA_SESSION_DECRYPT;
            break;
        case 7:
            ctx.bmask |= TPMA_SESSION_DECRYPT;
            break;
        case 8:
            ctx.bmask |= TPMA_SESSION_ENCRYPT;
            ctx.flags |= TPMA_SESSION_ENCRYPT;
            break;
        case 9:
            ctx.bmask |= TPMA_SESSION_ENCRYPT;
            break;
        case 10:
            ctx.bmask |= TPMA_SESSION_AUDIT;
            ctx.flags |= TPMA_SESSION_AUDIT;
            break;
        case 11:
            ctx.bmask |= TPMA_SESSION_AUDIT;
            break;
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Argument takes one file name for session data");
        return false;
    }

    ctx.session_path = argv[0];

    return true;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify session file as an argument.");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "enable-continuesession",  no_argument, NULL, 0  },
        { "disable-continuesession", no_argument, NULL, 1  },
        { "enable-auditexclusive",   no_argument, NULL, 2  },
        { "disable-auditexclusive",  no_argument, NULL, 3  },
        { "enable-auditreset",       no_argument, NULL, 4  },
        { "disable-auditreset",      no_argument, NULL, 5  },
        { "enable-decrypt",          no_argument, NULL, 6  },
        { "disable-decrypt",         no_argument, NULL, 7  },
        { "enable-encrypt",          no_argument, NULL, 8  },
        { "disable-encrypt",         no_argument, NULL, 9  },
        { "enable-audit",            no_argument, NULL, 10 },
        { "disable-audit",           no_argument, NULL, 11 },
    };

    *opts = tpm2_options_new(NULL, ARRAY_LEN(topts), topts, on_option, on_args,
        0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *esys_context,
        tpm2_yaml *doc,
        tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = process_input(esys_context);
    if(rc != tool_rc_success) {
        return rc;
    }

    return process_output(esys_context, doc);
    /*
     * Disabling continuesession should flush the session after use.
     */
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *esys_context) {

    UNUSED(esys_context);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("sessionconfig", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
