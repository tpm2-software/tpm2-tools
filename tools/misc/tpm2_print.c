/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef bool (*print_fn)(FILE *f);

typedef struct tpm2_print_ctx tpm2_print_ctx;
struct tpm2_print_ctx {
    struct {
        const char *path;
        print_fn handler;
    } file;
};

static tpm2_print_ctx ctx;

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

    switch (attest.type) {
    case TPM2_ST_ATTEST_QUOTE:
        tpm2_tool_output("attested:\n");
        print_yaml_indent(1);
        tpm2_tool_output("quote:\n");
        return print_TPMS_QUOTE_INFO(&attest.attested.quote, 2);
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

    tpm2_util_tpmt_public_to_yaml(&public, NULL);

    return true;
}

static bool print_TPM2B_PUBLIC(FILE *fstream) {

    TPM2B_PUBLIC public = { 0 };
    bool res = files_load_public_file(fstream, ctx.file.path, &public);
    if (!res) {
        return res;
    }

    tpm2_util_public_to_yaml(&public, NULL);

    return true;
}

#define ADD_HANDLER(type) { .name = #type, .fn = print_##type }

static bool handle_type(const char *name) {

    static const struct {
        const char *name;
        print_fn fn;
    } handlers[] = {
        ADD_HANDLER(TPMS_ATTEST),
        ADD_HANDLER(TPMS_CONTEXT),
        ADD_HANDLER(TPM2B_PUBLIC),
        ADD_HANDLER(TPMT_PUBLIC)
    };

    size_t i;
    for (i=0; i < ARRAY_LEN(handlers); i++) {

        if (!strcmp(name, handlers[i].name)) {
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
    case 'i':
        ctx.file.path = value;
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
        { "type",  required_argument, NULL, 't' },
    };

    *opts = tpm2_options_new("t:", ARRAY_LEN(topts), topts, on_option, on_arg,
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
