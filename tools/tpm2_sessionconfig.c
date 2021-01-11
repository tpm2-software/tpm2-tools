/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

typedef struct tpm_sessionconfig_ctx tpm_sessionconfig_ctx;
struct tpm_sessionconfig_ctx {
    tpm2_session *session;
    const char *session_path;
    TPMA_SESSION bmask;
    TPMA_SESSION flags;
    bool session_describe;
};

static tpm_sessionconfig_ctx ctx;

/*
 * IESYS_METADATA structures copied from esys_types.h since these are not
 * accessible through esys header/ library.
 */
typedef UINT32 IESYSC_RESOURCE_TYPE_CONSTANT;
typedef UINT32 IESYSC_PARAM_ENCRYPT;
typedef UINT32 IESYSC_PARAM_DECRYPT;
typedef UINT32 IESYSC_TYPE_POLICY_AUTH;
typedef struct {
    TPM2B_NAME                             bound_entity;
    TPM2B_ENCRYPTED_SECRET                encryptedSalt;
    TPM2B_DATA                                     salt;
    TPMT_SYM_DEF                              symmetric;
    TPMI_ALG_HASH                              authHash;
    TPM2B_DIGEST                             sessionKey;
    TPM2_SE                                 sessionType;
    TPMA_SESSION                      sessionAttributes;
    TPMA_SESSION                  origSessionAttributes;
    TPM2B_NONCE                             nonceCaller;
    TPM2B_NONCE                                nonceTPM;
    IESYSC_PARAM_ENCRYPT                        encrypt;
    IESYSC_PARAM_DECRYPT                        decrypt;
    IESYSC_TYPE_POLICY_AUTH         type_policy_session;
    UINT16                             sizeSessionValue;
    BYTE                 sessionValue [2*sizeof(TPMU_HA)];
    UINT16                                sizeHmacValue;
} IESYS_SESSION;

typedef UINT32                  IESYSC_RESOURCE_TYPE;
typedef union {
    TPM2B_PUBLIC                           rsrc_key_pub;
    TPM2B_NV_PUBLIC                         rsrc_nv_pub;
    IESYS_SESSION                          rsrc_session;
    TPMS_EMPTY                               rsrc_empty;
} IESYS_RSRC_UNION;
typedef struct {
    TPM2_HANDLE                                  handle;
    TPM2B_NAME                                     name;
    IESYSC_RESOURCE_TYPE                       rsrcType;
    IESYS_RSRC_UNION                               misc;
} IESYS_RESOURCE;
typedef struct {
    UINT16                                         size;
    IESYS_RESOURCE                                 data;
} IESYS_METADATA;

#define FORMAT_NEWLINE(SZ, BUF, OFFST) \
do { \
    for(i = 0; i < SZ; i++) { \
        if (i && !(i % 32)) { \
            tpm2_tool_output("\n\t\t\t"); \
        } \
        tpm2_tool_output("%02x", BUF[i + OFFST]); \
    } \
    tpm2_tool_output("\n"); \
} while(false)

static void print_session_info(    UINT32 session_version, TPM2_SE session_type,
TPMI_ALG_HASH session_hash_algorithm, UINT32 context_version,
TPMS_CONTEXT context, const char *hierarchy, UINT32 iesys_reserved,
UINT16 tpm2context_size, TPM2B_DIGEST tpm2bcontext_integrity_data,
UINT8 *tpm2context_data_buffer, IESYS_METADATA iesys_metadata) {

    tpm2_tool_output("session-version:\t%d\n", session_version);

    tpm2_tool_output("session-type:\t\t%d\n", session_type);

    tpm2_tool_output("session_hash_algorithm:\t%04x\n", session_hash_algorithm);

    tpm2_tool_output("context-version:\t%d\n", context_version);
    tpm2_tool_output("hierarchy:\t\t%s\n", hierarchy);

    tpm2_tool_output("handle:\t\t\t%x\n", context.savedHandle);

    tpm2_tool_output("sequence:\t\t%"PRIu64"\n", context.sequence);

    //tpm2_tool_output("size: %d\n", context.contextBlob.size);
    tpm2_tool_output("iesys-reserved:\t\t%08x\n", iesys_reserved);

    //tpm2_tool_output("size: %d\n", tpm2context_size);
    tpm2_tool_output("integrity-size:\t\t%d\n",
    tpm2bcontext_integrity_data.size);
    tpm2_tool_output("integrity-buffer:\t");
    UINT16 i;
    FORMAT_NEWLINE(tpm2bcontext_integrity_data.size,
    tpm2bcontext_integrity_data.buffer, 0);

    UINT16 tpm2bcontext_encrypted_data_size =
    tpm2context_size - tpm2bcontext_integrity_data.size;
    tpm2_tool_output("encrypted-session-data-size: %d\n",
    tpm2bcontext_encrypted_data_size);

    tpm2_tool_output("encrypted-session-data: ");
    FORMAT_NEWLINE(tpm2bcontext_encrypted_data_size, tpm2context_data_buffer,
    tpm2bcontext_integrity_data.size);

    tpm2_tool_output("iesys-resource-handle:\t%08x\n",
    iesys_metadata.data.handle);

    tpm2_tool_output("iesys-resource-name:\t");
    FORMAT_NEWLINE(iesys_metadata.data.name.size,
    iesys_metadata.data.name.name, 0);

    tpm2_tool_output("iesys-resource-type:\t%d\n", iesys_metadata.data.rsrcType);

    tpm2_tool_output("bound_entity:\t\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.bound_entity.size,
    iesys_metadata.data.misc.rsrc_session.bound_entity.name, 0);

    tpm2_tool_output("encryptedSalt:\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.encryptedSalt.size,
    iesys_metadata.data.misc.rsrc_session.encryptedSalt.secret, 0);

    tpm2_tool_output("salt:\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.salt.size,
    iesys_metadata.data.misc.rsrc_session.salt.buffer, 0);

    tpm2_tool_output("symmetric-algorithm:\t%02x\n",
        iesys_metadata.data.misc.rsrc_session.symmetric.algorithm);
    tpm2_tool_output("symmetric-keybits:\t%02x\n",
        iesys_metadata.data.misc.rsrc_session.symmetric.keyBits.sym);
    tpm2_tool_output("symmetric-mode:\t\t%02x\n",
        iesys_metadata.data.misc.rsrc_session.symmetric.mode.sym);

    tpm2_tool_output("authHash:\t\t%02x\n",
    iesys_metadata.data.misc.rsrc_session.authHash);

    tpm2_tool_output("sessionKey:\t\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.sessionKey.size,
    iesys_metadata.data.misc.rsrc_session.sessionKey.buffer, 0);

    tpm2_tool_output("sessionType:\t\t%02x\n",
    iesys_metadata.data.misc.rsrc_session.sessionType);

    tpm2_tool_output("sessionAttributes:\t%02x\n",
    iesys_metadata.data.misc.rsrc_session.sessionAttributes);

    /*
     * It appears origSessionAttributes was not marshalled.
     *
     * tpm2_tool_output("origSessionAttributes:\t%02x\n",
     * iesys_metadata.data.misc.rsrc_session.origSessionAttributes);
     */

    tpm2_tool_output("nonceCaller:\t\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.nonceCaller.size,
    iesys_metadata.data.misc.rsrc_session.nonceCaller.buffer, 0);

    tpm2_tool_output("nonceTPM:\t\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.nonceTPM.size,
    iesys_metadata.data.misc.rsrc_session.nonceTPM.buffer, 0);

    tpm2_tool_output("encrypt:\t\t%d\n",
    iesys_metadata.data.misc.rsrc_session.encrypt);

    tpm2_tool_output("decrypt:\t\t%d\n",
    iesys_metadata.data.misc.rsrc_session.decrypt);

    tpm2_tool_output("type_policy_session:\t%d\n",
    iesys_metadata.data.misc.rsrc_session.type_policy_session);

    tpm2_tool_output("sizeSessionValue:\t%04x\n",
    iesys_metadata.data.misc.rsrc_session.sizeSessionValue);

    tpm2_tool_output("sessionValue:\t\t");
    FORMAT_NEWLINE(iesys_metadata.data.misc.rsrc_session.sizeSessionValue,
    iesys_metadata.data.misc.rsrc_session.sessionValue, 0);

    tpm2_tool_output("sizeHmacValue:\t\t%04x\n",
    iesys_metadata.data.misc.rsrc_session.sizeHmacValue);
}

#define ERRCHK_IESYS_UNMARSHAL(rval, result, type, buffer, size, offset, name) \
do { \
    rval = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, &name); \
    if (rval != TSS2_RC_SUCCESS) { \
        LOG_ERR("Failed unmarshalling iesys metadata."); \
        result = false; \
        goto out; \
    } \
} while(false)

static bool populate_iesys_session_info(FILE *fstream,
IESYS_METADATA *iesys_metadata) {

    /*
     * Since we are reading the file stream at an offset, existing file read
     * functions cannot return actual bytes read.
     */
    bool result = true;
    uint8_t buffer[sizeof(IESYS_METADATA)] = { 0 };
    uint16_t size = fread(buffer, 1, sizeof(IESYS_METADATA), fstream);
    if (!size) {
        LOG_ERR("Cannot read iesys_metadata from file.");
        goto out;
    }

    size_t offset = 0;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT16, buffer, size, offset,
    iesys_metadata->size);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2_HANDLE, buffer, size, offset,
    iesys_metadata->data.handle);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_NAME, buffer, size, offset,
    iesys_metadata->data.name);

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT32, buffer, size, offset,
    iesys_metadata->data.rsrcType);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_NAME, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.bound_entity);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_ENCRYPTED_SECRET, buffer, size,
    offset, iesys_metadata->data.misc.rsrc_session.encryptedSalt);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_DATA, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.salt);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPMT_SYM_DEF, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.symmetric);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPMI_ALG_HASH, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.authHash);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_DIGEST, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.sessionKey);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2_SE, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.sessionType);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPMA_SESSION, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.sessionAttributes);

    /*
     * It appears that origSessionAttributes is not marshalled
     *
     * ERRCHK_IESYS_UNMARSHAL(rval, result, TPMA_SESSION, buffer, size, offset,
       iesys_metadata->data.misc.rsrc_session.origSessionAttributes);
    */

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_NONCE, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.nonceCaller);

    ERRCHK_IESYS_UNMARSHAL(rval, result, TPM2B_NONCE, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.nonceTPM);

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT32, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.encrypt);

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT32, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.decrypt);

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT32, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.type_policy_session);

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT16, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.sizeSessionValue);

    size_t sessionval_size =
    iesys_metadata->data.misc.rsrc_session.sizeSessionValue;
    memcpy(&iesys_metadata->data.misc.rsrc_session.sessionValue[0],
    buffer + offset, sessionval_size);
    offset += sessionval_size;

    ERRCHK_IESYS_UNMARSHAL(rval, result, UINT16, buffer, size, offset,
    iesys_metadata->data.misc.rsrc_session.sizeHmacValue);

out:
    return result;
}

static tool_rc populate_tpm2_session_info(FILE *fstream,
UINT16 *tpm2context_size, TPM2B_DIGEST *tpm2bcontext_integrity_data,
UINT8 **tpm2context_data_buffer) {

    bool result = files_read_16(fstream, tpm2context_size);
    if (!result) {
        LOG_ERR("Error reading tpm2 context size!");
        return false;
    }

    *tpm2context_data_buffer = malloc(*tpm2context_size + sizeof(UINT16));
    result = files_read_bytes(fstream, *tpm2context_data_buffer,
    *tpm2context_size);
    if (!result) {
        LOG_ERR("Error reading tpm2 context data!");
        return false;
    }

    /*
     * Cannot use Tss2_MU_TPMS_CONTEXT_DATA_Unmarshal because SESSION structure
     * created by the TPM does not give the size of the encrypted member of the
     * TPMS_CONTEXT_DATA
     */
    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPM2B_DIGEST_Unmarshal(*tpm2context_data_buffer,
    *tpm2context_size, &offset, tpm2bcontext_integrity_data);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Error reading TPMS_CONTEXT_DATA.");
        LOG_PERR(Tss2_MU_TPM2B_DIGEST_Unmarshal, rval);
        return false;
    }

    return true;
}

static bool populate_tpm2_tools_session_info(FILE *fstream,
UINT32 *session_version, TPM2_SE *session_type,
TPMI_ALG_HASH *session_hash_algorithm, UINT32 *context_version,
TPMS_CONTEXT *context, const char *hierarchy, UINT32 *iesys_reserved) {

    bool result = files_read_header(fstream, session_version);
    if (!result) {
        LOG_ERR("Session data does not have a proper header.");
        return false;
    }

    result = files_read_bytes(fstream, session_type, sizeof(TPM2_SE));
    if (!result) {
        LOG_ERR("Session type information not available.");
        return false;
    }

    result = files_read_16(fstream, session_hash_algorithm);
    if (!result) {
        LOG_ERR("Session hash algorithm information not available.");
        return false;
    }

    result = files_read_header(fstream, context_version);
    if (!result) {
        /* Only latest version of session context format supported */
        LOG_ERR("Session data does not have a proper header.");
        return false;
    }

    result = files_read_32(fstream, &context->hierarchy);
    if (!result) {
        LOG_ERR("Error reading hierarchy!");
        return false;
    }
    switch (context->hierarchy) {
    case TPM2_RH_OWNER:
        hierarchy = "owner";
        break;
    case TPM2_RH_PLATFORM:
        hierarchy = "platform";
        break;
    case TPM2_RH_ENDORSEMENT:
        hierarchy = "endorsement";
        break;
    case TPM2_RH_NULL:
    default:
        hierarchy = "null";
        break;
    }
    /*
     * The assignment of a string to hierarchy is complete with the switch above
     * and it is being referenced in the final step of printing out the session
     * information. However, clang assumes that the value assigned to hierarchy
     * is never used; hence the redundant check below.
     */
    if (!hierarchy) {
        return false;
    }

    result = files_read_32(fstream, &context->savedHandle);
    if (!result) {
        LOG_ERR("Error reading savedHandle!");
        return false;
    }

    result = files_read_64(fstream, &context->sequence);
    if (!result) {
        LOG_ERR("Error reading sequence!");
        return false;
    }

    result = files_read_16(fstream, &context->contextBlob.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        return false;
    }

    if (context->contextBlob.size > sizeof(context->contextBlob.buffer)) {
        LOG_ERR("Size mismatch found on contextBlob, got %"PRIu16" expected "
                "less than or equal to %zu", context->contextBlob.size,
                sizeof(context->contextBlob.buffer));
        return false;
    }

    result = files_read_32(fstream, iesys_reserved);
    if (!result) {
        LOG_ERR("Error reading iesys reserved area!");
        return false;
    }

    return true;
}

/*
 * Note:
 *
 * esys adds meta information to the context blob in addition to what
 * the TPM already specifies.
 *
 * esys data from file has been deserialized @ tpm2_session_restore
 * But we will parse the file to evaluate the session structure in the file.
 *
 * Only latest version of session/ context format supported
 */
static tool_rc describe_session(void) {

    FILE *fstream = fopen(ctx.session_path, "rb");
    if (!fstream) {
        LOG_ERR("Couldn't open session file.");
        return tool_rc_general_error;
    }

    /* Populate session info from tpm2-tools */
    UINT32 session_version;
    TPM2_SE session_type;
    TPMI_ALG_HASH session_hash_algorithm;
    UINT32 context_version;
    TPMS_CONTEXT context;
    const char *hierarchy = "null";
    UINT32 iesys_reserved;
    bool result = populate_tpm2_tools_session_info(fstream, &session_version,
    &session_type, &session_hash_algorithm, &context_version, &context,
    hierarchy, &iesys_reserved);
    if (!result) {
        goto out2;
    }

    /* Populate session info from tpm2-sim */
    UINT16 tpm2context_size;
    TPM2B_DIGEST tpm2bcontext_integrity_data = {0};
    UINT8 *tpm2context_data_buffer = 0;
    result = populate_tpm2_session_info(fstream, &tpm2context_size,
    &tpm2bcontext_integrity_data, &tpm2context_data_buffer);
    if (!result) {
        goto out1;
    }

    /* Populate session info from iesys */
    IESYS_METADATA iesys_metadata = { 0 };
    result = populate_iesys_session_info(fstream, &iesys_metadata);
    if (!result) {
        goto out1;
    }

    print_session_info(session_version, session_type, session_hash_algorithm,
    context_version, context, hierarchy, iesys_reserved, tpm2context_size,
    tpm2bcontext_integrity_data, tpm2context_data_buffer, iesys_metadata);

out1:
    free(tpm2context_data_buffer);
out2:
    fclose(fstream);
    return result ? tool_rc_success : tool_rc_general_error;
}

static tool_rc process_output(ESYS_CONTEXT *esys_context) {

    /* bmask is set when modifying session attributes */
    if (ctx.bmask) {
        ESYS_TR sessionhandle = tpm2_session_get_handle(ctx.session);
        if (!sessionhandle) {
            LOG_ERR("Session handle cannot be null");
            return tool_rc_general_error;
        }

        return Esys_TRSess_SetAttributes(esys_context, sessionhandle, ctx.flags,
        ctx.bmask);
    }

    return describe_session();
}

static tool_rc process_input(ESYS_CONTEXT *esys_context) {

    /*
     * Inferring session info before/ after changing the attributes can be a
     * subjective choice. So allowing only one operation at a time.
     */
    if (ctx.bmask && ctx.session_describe) {
        LOG_ERR("Specify option to describe session or modify it, not both.");
        return tool_rc_option_error;
    }

    /* If no options are specified default to describing the session */
    if (!ctx.bmask && !ctx.session_describe) {
        ctx.session_describe = true;
    }

    tool_rc rc = tpm2_session_restore(esys_context, ctx.session_path, false,
    &ctx.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not restore session from the specified file");
        return rc;
    }

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
        case 12:
            ctx.session_describe = true;
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

    return process_output(esys_context);
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
