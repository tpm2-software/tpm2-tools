//**********************************************************************;
// Copyright (c) 2017, National Instruments
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdio.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef enum {
    file_type_unknown = 0,
    file_type_TPMS_ATTEST
} file_type_id;

typedef struct tpm2_print_ctx tpm2_print_ctx;
struct tpm2_print_ctx {
    struct {
        const char *path;
        file_type_id type;
    } file;
};

static tpm2_print_ctx ctx;

static bool print_clock_info(FILE* fd, size_t indent_count) {
    union {
        UINT8  u8;
        UINT32 u32;
        UINT64 u64;
    } numb;

    bool res = files_read_64(fd, &numb.u64);
    if (!res) {
        goto read_error;
    }
    print_yaml_indent(indent_count);
    tpm2_tool_output("clock: %llu\n", (long long unsigned int)numb.u64);

    res = files_read_32(fd, &numb.u32);
    if (!res) {
        goto read_error;
    }
    print_yaml_indent(indent_count);
    tpm2_tool_output("resetCount: %lu\n", (long unsigned int)numb.u32);

    res = files_read_32(fd, &numb.u32);
    if (!res) {
        goto read_error;
    }
    print_yaml_indent(indent_count);
    tpm2_tool_output("restartCount: %lu\n", (long unsigned int)numb.u32);

    res = files_read_bytes(fd, &numb.u8, 1);
    if (!res) {
        goto read_error;
    }
    print_yaml_indent(indent_count);
    tpm2_tool_output("safe: %u\n", (unsigned int)numb.u8);

    return true;

read_error:
    LOG_ERR("File too short");
    return false;
}

static bool print_TPMS_QUOTE_INFO(FILE* fd, size_t indent_count) {
    // read TPML_PCR_SELECTION count (UINT32)
    UINT32 pcr_selection_count;
    bool res = files_read_32(fd, &pcr_selection_count);
    if (!res) {
        goto read_error;
    }
    print_yaml_indent(indent_count);
    tpm2_tool_output("pcrSelect:\n");

    print_yaml_indent(indent_count + 1);
    tpm2_tool_output("count: %lu\n", (long unsigned int)pcr_selection_count);

    print_yaml_indent(indent_count + 1);
    tpm2_tool_output("pcrSelections:\n");

    // read TPML_PCR_SELECTION array (of size count)
    UINT32 i;
    for (i = 0; i < pcr_selection_count; ++i) {
        print_yaml_indent(indent_count + 2);
        tpm2_tool_output("%lu:\n", (long unsigned int)i);

        // print hash type (TPMI_ALG_HASH)
        UINT16 hash_type;
        res = files_read_16(fd, &hash_type);
        if (!res) {
            goto read_error;
        }
        res = tpm2_alg_util_is_hash_alg(hash_type);
        if (!res) {
            LOG_ERR("Invalid hash type in quote");
            goto error;
        }
        const char* const hash_name = tpm2_alg_util_algtostr(hash_type);
        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("hash: %u (%s)\n", (unsigned int)hash_type, hash_name);

        UINT8 sizeofSelect;
        res = files_read_bytes(fd, &sizeofSelect, 1);
        if (!res) {
            goto read_error;
        }
        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("sizeofSelect: %u\n", (unsigned int)sizeofSelect);

        // print PCR selection in hex
        print_yaml_indent(indent_count + 3);
        tpm2_tool_output("pcrSelect: ");
        res = tpm2_util_hexdump_file(fd, sizeofSelect, true);
        tpm2_tool_output("\n");
        if (!res) {
            goto read_error;
        }
    }

    // print digest in hex (a TPM2B object)
    print_yaml_indent(indent_count);
    tpm2_tool_output("pcrDigest: ");
    res = tpm2_util_print_tpm2b_file(fd);
    tpm2_tool_output("\n");
    if (!res) {
        goto read_error;
    }

    return true;

read_error:
    LOG_ERR("File too short");
error:
    return false;
}

static bool print_TPMS_ATTEST_yaml(FILE* fd) {
    // print magic without converting endianness
    UINT32 magic;
    bool res = files_read_bytes(fd, (UINT8*)&magic, sizeof(UINT32));
    if (!res) {
        goto read_error;
    }
    tpm2_tool_output("magic: ");
    tpm2_util_hexdump((const UINT8*)&magic, sizeof(UINT32), true);
    tpm2_tool_output("\n");
    magic = tpm2_util_ntoh_32(magic); // finally, convert endianness

    // check magic
    if (magic != TPM2_GENERATED_VALUE) {
        LOG_ERR("Bad magic");
        goto error;
    }

    UINT16 type;
    res = files_read_bytes(fd, (UINT8*)&type, sizeof(UINT16));
    if (!res) {
        goto read_error;
    }
    tpm2_tool_output("type: ");
    tpm2_util_hexdump((const UINT8*)&type, sizeof(UINT16), true);
    tpm2_tool_output("\n");
    type = tpm2_util_ntoh_16(type); // finally, convert endianness

    tpm2_tool_output("qualifiedSigner: ");
    res = tpm2_util_print_tpm2b_file(fd);
    tpm2_tool_output("\n");
    if (!res) {
        goto read_error;
    }

    tpm2_tool_output("extraData: ");
    res = tpm2_util_print_tpm2b_file(fd);
    tpm2_tool_output("\n");
    if (!res) {
        goto read_error;
    }

    tpm2_tool_output("clockInfo:\n");
    res = print_clock_info(fd, 1);
    if (!res) {
        goto error;
    }

    tpm2_tool_output("firmwareVersion: ");
    res = tpm2_util_hexdump_file(fd, sizeof(UINT64), true);
    tpm2_tool_output("\n");
    if (!res) {
        goto read_error;
    }

    switch(type) {
    case TPM2_ST_ATTEST_QUOTE:
        tpm2_tool_output("attested:\n");
        print_yaml_indent(1);
        tpm2_tool_output("quote:\n");
        res = print_TPMS_QUOTE_INFO(fd, 2);
        if (!res) {
            goto error;
        }
        break;

    default:
        LOG_ERR("Cannot print unsupported type 0x%x", (unsigned int)type);
        goto error;
    }

    return true;

read_error:
    LOG_ERR("File too short");
error:
    return false;
}

static bool on_option(char key, char *value) {
    switch (key) {
    case 't':
        if (strcmp(value, "TPMS_ATTEST") != 0) {
            LOG_ERR("Invalid type specified. Only TPMS_ATTEST is presently supported.");
            return false;
        }
        ctx.file.type = file_type_TPMS_ATTEST;
        break;
    case 'f':
        ctx.file.path = value;
        break;
    default:
        LOG_ERR("Invalid option %c", key);
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {
    static const struct option topts[] = {
        { "type",        required_argument, NULL, 't' },
        { "file",        optional_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("t:f:", ARRAY_LEN(topts), topts,
        on_option, NULL, TPM2_OPTIONS_SHOW_USAGE|TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {
    UNUSED(sapi_context);
    UNUSED(flags);

    bool (*print_fn)(FILE*) = NULL;

    switch (ctx.file.type) {
    case file_type_TPMS_ATTEST:
        print_fn = print_TPMS_ATTEST_yaml;
        break;
    default:
        LOG_ERR("Must specify a file type with -t option");
        return 1;
    }

    FILE* fd = stdin;

    if (ctx.file.path) {
        LOG_INFO("Reading from file %s", ctx.file.path);
        fd = fopen(ctx.file.path, "rb");
        if(!fd) {
            LOG_ERR("Could not open file %s", ctx.file.path);
            return 1;
        }
    }
    else {
        LOG_INFO("Reading from stdin");
    }

    bool res = print_fn(fd);

    LOG_INFO("Read %ld bytes from file %s", ftell(fd), ctx.file.path);

    if (fd != stdin) {
        fclose(fd);
    }

    return res ? 0 : 1;
}
