//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "tpm2_util.h"
#include "log.h"
#include "files.h"

#define SAPI_CONTEXT ((TSS2_SYS_CONTEXT *)0xDEADBEEF)

/*
 * NOTE: very much a copy/paste/edit from files_load_tpm_context_from_file()
 * in files.c -- should possibly be factored out and reused?
 */
static bool save_tpm_context(TPMS_CONTEXT context, const char *path) {
    bool result;
    FILE *stream = fopen(path, "w+b");
    if (!stream) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return false;
    }

    result = files_write_32(stream, context.hierarchy);
    if (!result) {
        LOG_ERR("Could not write hierarchy");
        goto out;
    }

    result = files_write_32(stream, context.savedHandle);
    if (!result) {
        LOG_ERR("Could not write savedHandle");
        goto out;
    }

    // UINT64
    result = files_write_64(stream, context.sequence);
    if (!result) {
        LOG_ERR("Could not write sequence");
        goto out;
    }

    // U16 LENGTH
    result = files_write_16(stream, context.contextBlob.size);
    if (!result) {
        LOG_ERR("Could not write contextBob size");
        goto out;
    }

    // BYTE[] contextBlob
    result = files_write_bytes(stream, context.contextBlob.buffer,
            context.contextBlob.size);
    if (!result) {
        LOG_ERR("Could not write contextBlob buffer");
    }
    /* result is set by file_write_bytes() */

out:
    fclose(stream);
    return result;
}

static void test_tpm2_create_dummy_context(TPMS_CONTEXT *context) {
    context->hierarchy = TPM2_RH_ENDORSEMENT;
    context->savedHandle = 2147483648;
    context->sequence = 10;
    context->contextBlob.size = 200;
    memset(context->contextBlob.buffer, '\0', context->contextBlob.size);
}

static void test_tpm2_util_object_load(void **state) {

    UNUSED(state);

    TPMS_CONTEXT context;
    test_tpm2_create_dummy_context(&context);
    save_tpm_context(context, "0x123");

    tpm2_loaded_object ctx_obj;
    // We ignore the return value -- there isn't a real SAPI context and thus
    // the load will fail, however the path should have been parsed and we can
    // test that it has been done correctly.
    tpm2_util_object_load_sapi(SAPI_CONTEXT, "file:0x123", &ctx_obj);
    assert_string_equal(ctx_obj.path, "0x123");
    int rc = remove("0x123");
    assert_return_code(rc, errno);

    // Parses as uint32, a handle, thus path should be unset
    tpm2_util_object_load_sapi(SAPI_CONTEXT, "0x123", &ctx_obj);
    assert_true(ctx_obj.path == NULL);

    // Doesn't parse as uint32, therefore assumed to be a file path.
    // Path should match.
    save_tpm_context(context, "foobar");
    tpm2_util_object_load_sapi(SAPI_CONTEXT, "foobar", &ctx_obj);
    rc = remove("foobar");
    assert_return_code(rc, errno);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tpm2_util_object_load),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
