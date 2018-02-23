//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <sapi/tpm20.h>
#include <sapi/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_util.h"

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            LOG_ERR("Error getting current file offset for file \"%s\" error: %s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            LOG_ERR("Error seeking to end of file \"%s\" error: %s", path, strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            LOG_ERR("ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            LOG_ERR("Could not restore initial stream position for file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long)size;
    return true;
}

static bool read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
                                 const char *path) {
    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on UINT16 */
    if (file_size > *size) {
        if (path) {
            LOG_ERR(
                    "File \"%s\" size is larger than buffer, got %lu expected less than %u",
                    path, file_size, *size);
        }
        return false;
    }

    result = files_read_bytes(f, buf, file_size);
    if (!result) {
        if (path) {
            LOG_ERR("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    *size = file_size;

    return true;
}

bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {
    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\" error %s", path, strerror(errno));
        return false;
    }

    bool result = read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size) {

    if (!path || !buf) {
        return false;
    }

    FILE *fp = fopen(path, "wb+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\", error: %s", path, strerror(errno));
        return false;
    }

    bool result = files_write_bytes(fp, buf, size);
    if (!result) {
        LOG_ERR("Could not write data to file \"%s\"", path);
    }
    fclose(fp);
    return result;
}

/*
 * Current version to write TPMS_CONTEXT to disk.
 */
#define CONTEXT_VERSION 1

bool files_save_tpm_context_to_file(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE handle,
        FILE *stream) {

    TPMS_CONTEXT context;

    TSS2_RC rval = Tss2_Sys_ContextSave(sysContext, handle, &context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextSave, rval);
        return false;
    }

    /*
     * Saving the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hiearchy
     * U32 savedHandle
     * U64 sequence
     * U16 contextBlobLength
     * BYTE[] contextBlob
     */
    bool result = files_write_header(stream, CONTEXT_VERSION);
    if (!result) {
        LOG_ERR("Could not write context file header");
        goto out;
    }

    // UINT32
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
    return result;
}

bool files_save_tpm_context_to_path(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE handle,
        const char *path) {

    FILE *f = fopen(path, "w+b");
    if (!f) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return false;
    }

    bool result = files_save_tpm_context_to_file(sysContext, handle, f);
    fclose(f);
    return result;
}


bool files_load_tpm_context_from_file(TSS2_SYS_CONTEXT *sapi_context,
        TPM2_HANDLE *handle, FILE *fstream) {

    TSS2_RC rval;

    /*
     * Reading the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hiearchy
     * U32 savedHandle
     * U64 sequence
     * U16 contextBlobLength
     * BYTE[] contextBlob
     */
    UINT32 version;
    TPMS_CONTEXT context;
    bool result = files_read_header(fstream, &version);
    if (!result) {
        LOG_WARN(
            "The loaded tpm context does not appear to be in the proper format,"
            "assuming old format, this will be converted on the next save.");
        rewind(fstream);
        result = files_read_bytes(fstream, (UINT8 *) &context, sizeof(context));
        if (!result) {
            LOG_ERR("Could not load tpm context file");
            goto out;
        }
        /* Success load the context into the TPM */
        goto load_to_tpm;
    }

    if (version != CONTEXT_VERSION) {
        LOG_ERR("Unsupported context file format version found, got: %"PRIu32,
                version);
        result = false;
        goto out;
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
        LOG_ERR(
                "Size mismatch found on contextBlob, got %"PRIu16" expected less than or equal to %zu",
                context.contextBlob.size,
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

load_to_tpm:
    rval = Tss2_Sys_ContextLoad(sapi_context, &context, handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        result = false;
        goto out;
    }

    result = true;

out:
    return result;
}

bool files_load_tpm_context_from_path(TSS2_SYS_CONTEXT *sapi_context,
        TPM2_HANDLE *handle, const char *path) {

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return false;
    }

    bool result = files_load_tpm_context_from_file(sapi_context, handle, f);

    fclose(f);
    return result;
}

bool files_does_file_exist(const char *path) {

    if (!path) {
        LOG_ERR("Path cannot be NULL");
        return false;
    }

    FILE *fp = fopen(path,"rb");
    if (fp) {
        fclose(fp);
        LOG_ERR("Path: %s already exists. Please rename or delete the file!",
                path);
        return true;
    }
    return false;
}

bool files_get_file_size_path(const char *path, unsigned long *file_size) {

    bool result = false;

    if (!path) {
        LOG_ERR("Must specify a path argument, cannot be NULL!");
        return false;
    }

    if (!file_size) {
        LOG_ERR("Must specify a file size argument, cannot be NULL!");
        return false;
    }

    FILE *fp = fopen(path,"rb");
    if(!fp) {
        LOG_ERR("Could not open file: \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    result = files_get_file_size(fp, file_size, path);

    fclose(fp);
    return result;
}

/**
 * This is the magic for the file header. The header is organized
 * as a big endian U32 (BEU32) of MAGIC followed by a BEU32 of the
 * version number. Tools can define their own, individual file
 * formats as they make sense, but they should always have the header.
 */
static const UINT32 MAGIC = 0xBADCC0DE;

/**
 * Writes size bytes to a file, continuing on EINTR short writes.
 * @param f
 *  The file to write to.
 * @param data
 *  The data to write.
 * @param size
 *  The size, in bytes, of that data.
 * @return
 *  True on success, False otherwise.
 */
static bool writex(FILE *f, UINT8 *data, size_t size) {

    size_t wrote = 0;
    size_t index = 0;
    do {
        wrote = fwrite(&data[index], 1, size, f);
        if (wrote != size) {
            if (errno != EINTR) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= wrote;
        index += wrote;
    } while (size > 0);

    return true;
}

/**
 * Reads size bytes from a file, continuing on EINTR short reads.
 * @param f
 *  The file to read from.
 * @param data
 *  The data buffer to read into.
 * @param size
 *  The size of the buffer, which is also the amount of bytes to read.
 * @return
 *  True on success, False otherwise.
 */
static bool readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    size_t index = 0;
    do {
        bread = fread(&data[index], 1, size, f);
        if (bread != size) {
            if (feof(f) || (errno != EINTR)) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= bread;
        index += bread;
    } while (size > 0);

    return true;
}

#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            LOG_ERR(param" must be specified"); \
            return false; \
        } \
    } while(0)

#define BE_CONVERT(value, size) \
    do { \
        if (!tpm2_util_is_big_endian()) { \
            value = tpm2_util_endian_swap_##size(value); \
        } \
    } while (0)

#define FILE_WRITE(size) \
    bool files_write_##size(FILE *out, UINT##size data) { \
        BAIL_ON_NULL("FILE", out); \
        BE_CONVERT(data, size); \
        return writex(out, (UINT8 *)&data, sizeof(data)); \
    }

#define FILE_READ(size) \
    bool files_read_##size(FILE *out, UINT##size *data) { \
	    BAIL_ON_NULL("FILE", out); \
	    BAIL_ON_NULL("data", data); \
        bool res = readx(out, (UINT8 *)data, sizeof(*data)); \
        if (res) { \
            BE_CONVERT(*data, size); \
        } \
        return res; \
    }

/*
 * all the files_read|write_bytes_16|32|64 functions
 */
FILE_READ(16);
FILE_WRITE(16)

FILE_READ(32);
FILE_WRITE(32)

FILE_READ(64)
FILE_WRITE(64)

bool files_read_bytes(FILE *out, UINT8 bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return readx(out, bytes, len);
}

bool files_write_bytes(FILE *out, uint8_t bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return writex(out, bytes, len);
}

bool files_write_header(FILE *out, UINT32 version) {

    BAIL_ON_NULL("FILE", out);

    bool res = files_write_32(out, MAGIC);
    if (!res) {
        return false;
    }
    return files_write_32(out, version);
}

bool files_read_header(FILE *out, uint32_t *version) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("version", version);

    UINT32 magic;
    bool res = files_read_32(out, &magic);
    if (!res) {
        return false;
    }

    if (magic != MAGIC) {
        LOG_ERR("Found magic 0x%x did not match expected magic of 0x%x!",
                magic, MAGIC);
        return false;
    }

    return files_read_32(out, version);
}

bool files_load_bytes_from_file_or_stdin(const char *path, UINT16 *size, BYTE *buf) {

    FILE *file =  path ? fopen(path, "rb") : stdin;
    path = file != stdin ? path : "<stdin>";
    if (!file) {
        LOG_ERR("Could not open file: \"%s\", error: %s", path,
                strerror(errno));
        return false;
    }

    /*
     * Attempt to accurately read the file based on the file size.
     * This may fail on stdin when it's a pipe.
     */
    if (file == stdin) {
        path = NULL;
    }

    UINT16 original_size = *size;
    bool res = files_load_bytes_from_path(path, buf,
            size);
    if (!res) {
        res = true;
        *size = fread(buf, 1,
                *size, file);
        if (!feof(file)) {
            LOG_ERR("Data to be sealed larger than expected. Got %u expected %u",
                    original_size, res);
            res = false;
        }
        else if (ferror(file)) {
            LOG_ERR("Error reading sealed data from \"<stdin>\"");
            res = false;
        }
    }

    if (file != stdin) {
        fclose(file);
    }

    return res;
}

#define SAVE_TYPE(type, name) \
    bool files_save_##name(type *name, const char *path) { \
    \
        size_t offset = 0; \
        UINT8 buffer[sizeof(*name)]; \
        TSS2_RC rc = Tss2_MU_##type##_Marshal(name, buffer, sizeof(buffer), &offset); \
        if (rc != TSS2_RC_SUCCESS) { \
            LOG_ERR("Error serializing "str(name)" structure: 0x%x", rc); \
            return false; \
        } \
    \
        return files_save_bytes_to_file(path, buffer, offset); \
    }

#define LOAD_TYPE(type, name) \
    bool files_load_##name(const char *path, type *name) { \
    \
        UINT8 buffer[sizeof(*name)]; \
        UINT16 size = sizeof(buffer); \
        bool res = files_load_bytes_from_path(path, buffer, &size); \
        if (!res) { \
            return false; \
        } \
        \
        size_t offset = 0; \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name); \
        if (rc != TSS2_RC_SUCCESS) { \
            LOG_ERR("Error serializing "str(name)" structure: 0x%x", rc); \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

SAVE_TYPE(TPM2B_PUBLIC, public)
LOAD_TYPE(TPM2B_PUBLIC, public)

SAVE_TYPE(TPMT_SIGNATURE, signature)
LOAD_TYPE(TPMT_SIGNATURE, signature)

SAVE_TYPE(TPMT_TK_VERIFIED, ticket)
LOAD_TYPE(TPMT_TK_VERIFIED, ticket)

SAVE_TYPE(TPM2B_SENSITIVE, sensitive)
LOAD_TYPE(TPM2B_SENSITIVE, sensitive)

SAVE_TYPE(TPMT_TK_HASHCHECK, validation)
LOAD_TYPE(TPMT_TK_HASHCHECK, validation)

SAVE_TYPE(TPM2B_PRIVATE, private)
LOAD_TYPE(TPM2B_PRIVATE, private)
