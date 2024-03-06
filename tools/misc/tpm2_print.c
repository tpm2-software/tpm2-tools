/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "object.h"

typedef bool (*print_fn)(FILE *f);

#define FLAG_FMT (1 << 0)

typedef struct tpm2_print_ctx tpm2_print_ctx;
struct tpm2_print_ctx {
    struct {
        const char *path;
        print_fn handler;
    } file;
    bool format_set;
    tpm2_convert_pubkey_fmt format;
};

#define TCTI_FAKE_MAGIC 0x46414b454d414700ULL

static tpm2_print_ctx ctx = {
        .format = pubkey_format_tss
};

static void print_clock_info(TPMS_CLOCK_INFO *clock_info, size_t indent_count) {

    print_yaml_indent(indent_count);
    tpm2_tool_output("clock: %"PRIu64"\n", clock_info->clock);

    print_yaml_indent(indent_count);
    tpm2_tool_output("resetCount: %"PRIu32"\n", clock_info->resetCount);

    print_yaml_indent(indent_count);
    tpm2_tool_output("restartCount: %"PRIu32"\n", clock_info->restartCount);

    print_yaml_indent(indent_count);
    tpm2_tool_output("safe: %u\n", clock_info->safe);
}

static bool print_TPMS_QUOTE_INFO(TPMS_QUOTE_INFO *info, size_t indent_count) {

    print_yaml_indent(indent_count);
    tpm2_tool_output("pcrSelect:\n");

    print_yaml_indent(indent_count + 1);
    tpm2_tool_output("count: %"PRIu32"\n", info->pcrSelect.count);

    print_yaml_indent(indent_count + 1);
    tpm2_tool_output("pcrSelections:\n");

    // read TPML_PCR_SELECTION array (of size count)
    UINT32 i;
    for (i = 0; i < info->pcrSelect.count; ++i) {
        print_yaml_indent(indent_count + 2);
        tpm2_tool_output("%"PRIu32":\n", i);

        // print hash type (TPMI_ALG_HASH)
        const char* const hash_name = tpm2_alg_util_algtostr(
                info->pcrSelect.pcrSelections[i].hash,
                tpm2_alg_util_flags_hash);
        if (!hash_name) {
            LOG_ERR("Invalid hash type in quote");
            return false;
        }
        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("hash: %"PRIu16" (%s)\n",
                info->pcrSelect.pcrSelections[i].hash,
                hash_name);

        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("sizeofSelect: %"PRIu8"\n",
                info->pcrSelect.pcrSelections[i].sizeofSelect);

        // print PCR selection in hex
        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("pcrSelect: ");
        tpm2_util_hexdump((BYTE *)&info->pcrSelect.pcrSelections[i].pcrSelect,
                info->pcrSelect.pcrSelections[i].sizeofSelect);
        tpm2_tool_output("\n");
    }

    // print digest in hex (a TPM2B object)
    print_yaml_indent(indent_count);
    tpm2_tool_output("pcrDigest: ");
    tpm2_util_print_tpm2b(&info->pcrDigest);
    tpm2_tool_output("\n");

    return true;
}

static void print_TPMS_CERTIFY_INFO(TPMS_CERTIFY_INFO *certify_info, size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("name: ");
    tpm2_util_print_tpm2b(&certify_info->name);
    tpm2_tool_output("\n");
    print_yaml_indent(indent_count);
    tpm2_tool_output("qualifiedName: ");
    tpm2_util_print_tpm2b(&certify_info->qualifiedName);
    tpm2_tool_output("\n");
}

static void print_TPMS_CREATION_INFO(TPMS_CREATION_INFO *creation_info, size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("objectName: ");
    tpm2_util_print_tpm2b(&creation_info->objectName);
    tpm2_tool_output("\n");
    print_yaml_indent(indent_count);
    tpm2_tool_output("creationHash: ");
    tpm2_util_print_tpm2b(&creation_info->creationHash);
    tpm2_tool_output("\n");
}

static void print_TPMS_COMMAND_AUDIT_INFO(TPMS_COMMAND_AUDIT_INFO *command_audit_info,
                                          size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("auditCounter:  %"PRIu64"\n", command_audit_info->auditCounter);
    print_yaml_indent(indent_count);
    tpm2_tool_output("digestAlg: %s\n", tpm2_alg_util_algtostr(command_audit_info->digestAlg,
                                                               tpm2_alg_util_flags_hash));
    print_yaml_indent(indent_count);
    tpm2_tool_output("auditDigest: ");
    tpm2_util_print_tpm2b(&command_audit_info->auditDigest);
    tpm2_tool_output("\n");
    print_yaml_indent(indent_count);
    tpm2_tool_output("commandDigest: ");
    tpm2_util_print_tpm2b(&command_audit_info->commandDigest);
    tpm2_tool_output("\n");
}

static void print_TPMS_SESSION_AUDIT_INFO(TPMS_SESSION_AUDIT_INFO *session_audit_info,
                                          size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("exclusiveSession: %s\n", session_audit_info->exclusiveSession ? "yes" : "no"); 
    print_yaml_indent(indent_count);
    tpm2_tool_output("sessionDigest: ");
    tpm2_util_print_tpm2b(&session_audit_info->sessionDigest);
    tpm2_tool_output("\n");
}

static void print_TPMS_CLOCK_INFO(TPMS_CLOCK_INFO *clock_info, size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("clock:  %"PRIu64"\n", clock_info->clock);
    print_yaml_indent(indent_count);
    tpm2_tool_output("resetCount:  %"PRIu32"\n", clock_info->resetCount);
    print_yaml_indent(indent_count);
    tpm2_tool_output("restartCount:  %"PRIu32"\n", clock_info->restartCount);
    print_yaml_indent(indent_count);
    tpm2_tool_output("safe: %s\n", clock_info->safe ? "yes" : "no"); 
}

static void print_TPMS_TIME_INFO(TPMS_TIME_INFO *time_info, size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("time:  %"PRIu64"\n", time_info->time);
     print_yaml_indent(indent_count);
    tpm2_tool_output("clockInfo:\n");
    print_TPMS_CLOCK_INFO(&time_info->clockInfo, indent_count + 1);
}

static void print_TPMS_TIME_ATTEST_INFO(TPMS_TIME_ATTEST_INFO *time_info, size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("time:\n");
    print_TPMS_TIME_INFO(&time_info->time, indent_count + 1);
    print_yaml_indent(indent_count);
    tpm2_tool_output("firmwareVersion:  %"PRIu64"\n", time_info->firmwareVersion);
    tpm2_tool_output("\n");
}

static void print_TPMS_NV_CERTIFY_INFO(TPMS_NV_CERTIFY_INFO *nv_certify_info,
                                          size_t indent_count) {
    print_yaml_indent(indent_count);
    tpm2_tool_output("indexName: ");
    tpm2_util_print_tpm2b(&nv_certify_info->indexName);
    tpm2_tool_output("\n");
    print_yaml_indent(indent_count);
    tpm2_tool_output("offset:  %"PRIu32"\n", nv_certify_info->offset);
    print_yaml_indent(indent_count);
    tpm2_tool_output("nvContents: ");
    tpm2_util_print_tpm2b(&nv_certify_info->nvContents);
    tpm2_tool_output("\n");
}

static bool print_TPMS_ATTEST(FILE* fd) {

    TPMS_ATTEST attest = { 0 };
    bool res = files_load_attest_file(fd, ctx.file.path, &attest);
    if (!res) {
        LOG_ERR("Could not parse TPMS_ATTEST file: \"%s\"", ctx.file.path);
        return false;
    }

    tpm2_tool_output("magic: ");
    /* dump these in TPM endianess (big-endian) */
    typeof(attest.magic) be_magic = tpm2_util_hton_32(attest.magic);
    tpm2_util_hexdump((const UINT8*) &be_magic,
            sizeof(attest.magic));
    tpm2_tool_output("\n");

    // check magic
    if (attest.magic != TPM2_GENERATED_VALUE) {
        LOG_ERR("Bad magic, got: 0x%x, expected: 0x%x",
                attest.magic, TPM2_GENERATED_VALUE);
        return false;
    }

    tpm2_tool_output("type: ");
    /* dump these in TPM endianess (big-endian) */
    typeof(attest.type) be_type = tpm2_util_hton_16(attest.type);
    tpm2_util_hexdump((const UINT8*) &be_type,
            sizeof(attest.type));
    tpm2_tool_output("\n");

    tpm2_tool_output("qualifiedSigner: ");
    tpm2_util_print_tpm2b(&attest.qualifiedSigner);
    tpm2_tool_output("\n");

    tpm2_tool_output("extraData: ");
    tpm2_util_print_tpm2b(&attest.extraData);
    tpm2_tool_output("\n");

    tpm2_tool_output("clockInfo:\n");
    print_clock_info(&attest.clockInfo, 1);

    tpm2_tool_output("firmwareVersion: ");
    tpm2_util_hexdump((BYTE *)&attest.firmwareVersion,
            sizeof(attest.firmwareVersion));
    tpm2_tool_output("\n");

    tpm2_tool_output("attested:\n");
    print_yaml_indent(1);

    switch (attest.type) {
    case TPM2_ST_ATTEST_QUOTE:
        tpm2_tool_output("quote:\n");
        return print_TPMS_QUOTE_INFO(&attest.attested.quote, 2);
        break;
    case TPM2_ST_ATTEST_CERTIFY:
        tpm2_tool_output("certify:\n");
        print_TPMS_CERTIFY_INFO(&attest.attested.certify, 2);
        return true;
        break;
    case TPM2_ST_ATTEST_CREATION:
        tpm2_tool_output("creation:\n");
        print_TPMS_CREATION_INFO(&attest.attested.creation, 2);
        return true;
        break;
    case TPM2_ST_ATTEST_COMMAND_AUDIT:
        tpm2_tool_output("commandAudit:\n");
        print_TPMS_COMMAND_AUDIT_INFO(&attest.attested.commandAudit, 2);
        return true;
        break;
    case TPM2_ST_ATTEST_SESSION_AUDIT:
        tpm2_tool_output("sessiondAudit:\n");
        print_TPMS_SESSION_AUDIT_INFO(&attest.attested.sessionAudit, 2);
        return true;
        break;
    case TPM2_ST_ATTEST_TIME:
        tpm2_tool_output("time:\n");
        print_TPMS_TIME_ATTEST_INFO(&attest.attested.time, 2);
        return true;
        break;
    case TPM2_ST_ATTEST_NV :
        tpm2_tool_output("nv:\n");
        print_TPMS_NV_CERTIFY_INFO(&attest.attested.nv, 2);
        return true;
        break;
    default:
        LOG_ERR("Cannot print unsupported type 0x%" PRIx16, attest.type);
        return false;
    }

    /* Should be unreachable */
    return false;
}

static bool print_TPMS_CONTEXT(FILE *fstream) {

    /*
     * Reading the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hierarchy
     * U32 savedHandle
     * U64 sequence
     * U16 contextBlobLength
     * BYTE[] contextBlob
     */
    UINT32 version;
    TPMS_CONTEXT context;
    bool result = files_read_header(fstream, &version);
    if (!result) {
        LOG_WARN("The loaded tpm context does not appear to be in the proper "
                 "format, assuming old format.");
        rewind(fstream);
        result = files_read_bytes(fstream, (UINT8 *) &context, sizeof(context));
        if (!result) {
            LOG_ERR("Could not load tpm context file");
            goto out;
        } else {
            goto print_context;
        }
    }

    result = files_read_32(fstream, &context.hierarchy);
    if (!result) {
        LOG_ERR("Error reading hierarchy!");
        goto out;
    }

    result = files_read_32(fstream, &context.savedHandle);
    if (!result) {
        LOG_ERR("Error reading savedHandle!");
        goto out;
    }

    result = files_read_64(fstream, &context.sequence);
    if (!result) {
        LOG_ERR("Error reading sequence!");
        goto out;
    }

    result = files_read_16(fstream, &context.contextBlob.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

    if (context.contextBlob.size > sizeof(context.contextBlob.buffer)) {
        LOG_ERR("Size mismatch found on contextBlob, got %"PRIu16" expected "
                "less than or equal to %zu", context.contextBlob.size,
                sizeof(context.contextBlob.buffer));
        result = false;
        goto out;
    }

    result = files_read_bytes(fstream, context.contextBlob.buffer,
            context.contextBlob.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

    print_context:
    tpm2_tool_output("version: %d\n", version);
    const char *hierarchy;
    switch (context.hierarchy) {
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
    tpm2_tool_output("hierarchy: %s\n", hierarchy);
    tpm2_tool_output("handle: 0x%X (%u)\n", context.savedHandle,
            context.savedHandle);
    tpm2_tool_output("sequence: %"PRIu64"\n", context.sequence);
    tpm2_tool_output("contextBlob: \n");
    tpm2_tool_output("\tsize: %d\n", context.contextBlob.size);
    result = true;

out:
    return result;
}

static bool print_TPMT_PUBLIC(FILE *fstream) {

    TPMT_PUBLIC public = { 0 };
    bool res = files_load_template_file(fstream, ctx.file.path, &public);
    if (!res) {
        return res;
    }

    if (ctx.format_set) {
        TPM2B_PUBLIC tpm2b_public = {
                .publicArea = public
        };
        return tpm2_convert_pubkey_save(&tpm2b_public, ctx.format, NULL);
    }

    tpm2_util_tpmt_public_to_yaml(&public, NULL);

    return true;
}

static bool print_TPM2B_PUBLIC(FILE *fstream) {

    TPM2B_PUBLIC public = { 0 };
    bool res = files_load_public_file(fstream, ctx.file.path, &public);
    if (!res) {
        return res;
    }

    if (ctx.format_set) {
        return tpm2_convert_pubkey_save(&public, ctx.format, NULL);
    }

    tpm2_util_public_to_yaml(&public, NULL);

    return true;
}

static bool print_TSSPRIVKEY_OBJ(FILE *fstream) {

    UNUSED(fstream);

    TPM2B_PUBLIC pub = { 0 };
    TPM2B_PRIVATE priv = { 0 };
    tool_rc rc = tpm2_util_object_fetch_priv_pub_from_tpk(ctx.file.path, &pub,
        &priv);
    if (rc != tool_rc_success) {
        LOG_ERR("Unable to fetch public/private portion of tss privkey");
        return false;
    }

    if (ctx.format_set) {
        return tpm2_convert_pubkey_save(&pub, ctx.format, NULL);
    }

    tpm2_util_public_to_yaml(&pub, NULL);

    return true;
}

typedef struct TSS2_TCTI_FAKE_CONTEXT TSS2_TCTI_FAKE_CONTEXT;
struct TSS2_TCTI_FAKE_CONTEXT {
    TSS2_TCTI_CONTEXT_COMMON_V2 common;
};

static TSS2_RC tcti_fake_transmit (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t size,
    const uint8_t *cmd_buf)
{
    UNUSED(size);
    UNUSED(cmd_buf);
    UNUSED(tcti_ctx);
    return TSS2_RC_SUCCESS;
}
static TSS2_RC tcti_fake_receive (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t *size,
    unsigned char *resp_buf,
    int32_t timeout)
{
    UNUSED(size);
    UNUSED(resp_buf);
    UNUSED(tcti_ctx);
    UNUSED(timeout);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
Tss2_Tcti_Fake_Init (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t *size)
{
    if (size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (tcti_ctx == NULL) {
        *size = sizeof (TSS2_TCTI_FAKE_CONTEXT);
        return TSS2_RC_SUCCESS;
    }
    if (*size != sizeof (TSS2_TCTI_FAKE_CONTEXT)) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    TSS2_TCTI_FAKE_CONTEXT *t = (TSS2_TCTI_FAKE_CONTEXT *)tcti_ctx;
    TSS2_TCTI_CONTEXT_COMMON_V2 *tcti_common = &t->common;

    TSS2_TCTI_MAGIC (tcti_common) = TCTI_FAKE_MAGIC;
    TSS2_TCTI_VERSION (tcti_common) = 2;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_fake_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_fake_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = NULL;
    TSS2_TCTI_CANCEL (tcti_common) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = NULL;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = NULL;
    TSS2_TCTI_MAKE_STICKY (tcti_common) = NULL;

    return TSS2_RC_SUCCESS;
}

static bool print_ESYS_TR(FILE* fd) {


    uint8_t *buffer = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    TPM2B_NAME *name = NULL;

    unsigned long size = 0;
    bool result = files_get_file_size(fd, &size, NULL);
    if (!result) {
        LOG_ERR("Failed to get file size: %s", strerror(ferror(fd)));
        return false;
    }

    if (size < 1) {
        LOG_ERR("Invalid serialized ESYS_TR size, got: %lu", size);
        return false;
    }

    buffer = calloc(1, size);
    if (!buffer) {
        LOG_ERR("oom");
        return false;
    }

    result = files_read_bytes(fd, buffer, size);
    if (!result) {
        LOG_ERR("Could not read serialized ESYS_TR from disk");
        goto error;
    }

    uint8_t tcti_buf[sizeof(TSS2_TCTI_FAKE_CONTEXT)] = { 0 };
    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT *)tcti_buf;
    size_t tcti_size = sizeof(tcti_buf);
    TSS2_RC rc = Tss2_Tcti_Fake_Init(tcti_ctx, &tcti_size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Tss2_Tcti_Fake_Init: %s", Tss2_RC_Decode(rc));
        goto error;
    }

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Esys_Initialize: %s", Tss2_RC_Decode(rc));
        goto error;
    }

    ESYS_TR handle;
    result = tpm2_tr_deserialize(esys_ctx, buffer, size, &handle) == tool_rc_success;
    if (!result) {
        LOG_ERR("Was the handle for a transient object?");
        goto error;
    }

    rc = Esys_TR_GetName(esys_ctx, handle, &name);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Esys_TR_GetName: %s", Tss2_RC_Decode(rc));
        goto error;
    }

    TPM2_HANDLE tpm_handle = 0;
    rc = Esys_TR_GetTpmHandle(esys_ctx, handle, &tpm_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Esys_TR_GetTpmHandle: %s", Tss2_RC_Decode(rc));
        goto error;
    }

    tpm2_tool_output("tpm-handle: 0x%x\n", tpm_handle);
    tpm2_tool_output("name: ");
    tpm2_util_hexdump(name->name, name->size);
    tpm2_tool_output("\n");

    result = true;

out:
    free(buffer);
    Esys_Free(name);
    Esys_Finalize(&esys_ctx);

    return result;
error:
    result = false;
    goto out;
}

#define ADD_HANDLER(type) { .name = #type, .flags = 0, .fn = print_##type }
#define ADD_HANDLER_FMT(type) { .name = #type, .flags = FLAG_FMT, .fn = print_##type }


static bool handle_type(const char *name) {

    static const struct {
        const char *name;
        unsigned flags;
        print_fn fn;
    } handlers[] = {
        ADD_HANDLER(TPMS_ATTEST),
        ADD_HANDLER(TPMS_CONTEXT),
        ADD_HANDLER_FMT(TPM2B_PUBLIC),
        ADD_HANDLER_FMT(TPMT_PUBLIC),
        ADD_HANDLER_FMT(TSSPRIVKEY_OBJ),
        ADD_HANDLER(ESYS_TR)
    };

    size_t i;
    for (i=0; i < ARRAY_LEN(handlers); i++) {

        if (!strcmp(name, handlers[i].name)) {

            if (ctx.format_set && !(handlers[i].flags & FLAG_FMT)) {
                LOG_ERR("Cannot specify --format/-f with handler for type \"%s\"", name);
                return false;
            }

            ctx.file.handler = handlers[i].fn;
            return true;
        }
    }

    LOG_ERR("Unknown file type, got: \"%s\"", name);

    return false;
}

static bool on_option(char key, char *value) {
    switch (key) {
    case 't':
        return handle_type(value);
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.format_set = true;
        break;
    default:
        LOG_ERR("Invalid option %c", key);
        return false;
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected single file path argument");
        return false;
    }

    ctx.file.path = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    static const struct option topts[] = {
        { "type",   required_argument, NULL, 't' },
        { "format", required_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("t:f:", ARRAY_LEN(topts), topts, on_option, on_arg,
            TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(ectx);
    UNUSED(flags);

    FILE* fd = stdin;

    if (!ctx.file.handler) {
        /*
         * TODO: This could be automated by each
         * type having an interrogation function. If it passes,
         * then use the associated handler. For now, make -t
         * mandatory.
         */
        LOG_ERR("Must specify -t/--type");
        return tool_rc_general_error;
    }

    if (ctx.file.path) {
        LOG_INFO("Reading from file %s", ctx.file.path);
        fd = fopen(ctx.file.path, "rb");
        if (!fd) {
            LOG_ERR("Could not open file %s", ctx.file.path);
            return tool_rc_general_error;
        }
    } else {
        LOG_INFO("Reading from stdin");
    }

    bool res = ctx.file.handler(fd);

    LOG_INFO("Read %ld bytes from file %s", ftell(fd), ctx.file.path);

    if (fd != stdin) {
        fclose(fd);
    }

    return res ? tool_rc_success : tool_rc_general_error;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("print", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
