/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

/**
 * This is the magic for the file header. The header is organized
 * as a big endian U32 (BEU32) of MAGIC followed by a BEU32 of the
 * version number. Tools can define their own, individual file
 * formats as they make sense, but they should always have the header.
 */
static const UINT32 MAGIC = 0xBADCC0DE;

#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            LOG_ERR(param" must be specified"); \
            return false; \
        } \
    } while(0)

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
static bool writex(FILE *f, const UINT8 *data, size_t size) {

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
 *  The number of bytes that have been read.
 */
static size_t readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    do {
        bread += fread(&data[bread], 1, size-bread, f);
    } while (bread < size && !feof(f) && errno == EINTR);

    return bread;
}

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            LOG_ERR("Error getting current file offset for file \"%s\" error: "
                    "%s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            LOG_ERR("Error seeking to end of file \"%s\" error: %s", path,
                    strerror(errno));
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
            LOG_ERR(
                    "Could not restore initial stream position for file \"%s\" "
                    "failed: %s", path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long) size;
    return true;
}

bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path) {

    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on *size */
    if (file_size > *size) {
        if (path) {
            LOG_ERR(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u", path, file_size, *size);
        }
        return false;
    }

    /* The reported file size is not always correct, e.g. for sysfs files
       generated on the fly by the kernel when they are read, which appear as
       having size 0. Read as many bytes as we can until EOF is reached or the
       provided buffer is full. As a small sanity check, fail if the number of
       bytes read is smaller than the reported file size. */
    *size = readx(f, buf, *size);
    if (*size < file_size) {
        if (path) {
            LOG_ERR("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    return true;
}

TEST_WEAK bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {

    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\" error %s", path, strerror(errno));
        return false;
    }

    bool result = file_read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size) {

    if (!buf) {
        return false;
    }

    if (!path && !output_enabled) {
        return true;
    }

    FILE *fp = path ? fopen(path, "wb+") : stdout;
    if (!fp) {
        LOG_ERR("Could not open file \"%s\", error: %s", path, strerror(errno));
        return false;
    }

    bool result = files_write_bytes(fp, buf, size);
    if (!result) {
        LOG_ERR("Could not write data to file \"%s\"", path ? path : "<stdout>");
    }

    if (fp != stdout) {
        fclose(fp);
    }

    return result;
}

/*
 * Current version to write TPMS_CONTEXT to disk.
 */
#define CONTEXT_VERSION 1

bool files_save_context(TPMS_CONTEXT *context, FILE *stream) {

    /*
     * Saving the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hierarchy
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
    result = files_write_32(stream, context->hierarchy);
    if (!result) {
        LOG_ERR("Could not write hierarchy");
        goto out;
    }

    result = files_write_32(stream, context->savedHandle);
    if (!result) {
        LOG_ERR("Could not write savedHandle");
        goto out;
    }
    LOG_INFO("Save TPMS_CONTEXT->savedHandle: 0x%x", context->savedHandle);

    // UINT64
    result = files_write_64(stream, context->sequence);
    if (!result) {
        LOG_ERR("Could not write sequence");
        goto out;
    }

    // U16 LENGTH
    result = files_write_16(stream, context->contextBlob.size);
    if (!result) {
        LOG_ERR("Could not write contextBob size");
        goto out;
    }

    // BYTE[] contextBlob
    result = files_write_bytes(stream, context->contextBlob.buffer,
            context->contextBlob.size);
    if (!result) {
        LOG_ERR("Could not write contextBlob buffer");
    }
    /* result is set by file_write_bytes() */

out:
    return result;
}

tool_rc files_save_tpm_context_to_file(ESYS_CONTEXT *ectx, ESYS_TR handle,
        FILE *stream, bool autoflush) {

    TPMS_CONTEXT *context = NULL;

    tool_rc rc = tpm2_context_save(ectx, handle, autoflush, &context);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_context(context, stream);
    free(context);
    return result ? tool_rc_success : tool_rc_general_error;
}

tool_rc files_save_tpm_context_to_path(ESYS_CONTEXT *context, ESYS_TR handle,
        const char *path, bool autoflush) {

    FILE *f = fopen(path, "w+b");
    if (!f) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return tool_rc_general_error;
    }

    tool_rc rc = files_save_tpm_context_to_file(context, handle, f, autoflush);
    fclose(f);
    return rc;
}

static bool load_tpm_context_file(FILE *fstream, TPMS_CONTEXT *context) {

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
    bool result = files_read_header(fstream, &version);
    if (!result) {
        LOG_WARN("The loaded tpm context does not appear to be in the proper "
                "format, assuming old format, this will be converted on the "
                "next save.");
        rewind(fstream);
        result = files_read_bytes(fstream, (UINT8 *) context, sizeof(*context));
        if (!result) {
            LOG_ERR("Could not load tpm context file");
            goto out;
        }
        /* Success load the context into the TPM */
        goto out;
    }

    if (version != CONTEXT_VERSION) {
        LOG_ERR("Unsupported context file format version found, got: %"PRIu32,
                version);
        result = false;
        goto out;
    }

    result = files_read_32(fstream, &context->hierarchy);
    if (!result) {
        LOG_ERR("Error reading hierarchy!");
        goto out;
    }

    result = files_read_32(fstream, &context->savedHandle);
    if (!result) {
        LOG_ERR("Error reading savedHandle!");
        goto out;
    }
    LOG_INFO("load: TPMS_CONTEXT->savedHandle: 0x%x", context->savedHandle);

    result = files_read_64(fstream, &context->sequence);
    if (!result) {
        LOG_ERR("Error reading sequence!");
        goto out;
    }

    result = files_read_16(fstream, &context->contextBlob.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

    if (context->contextBlob.size > sizeof(context->contextBlob.buffer)) {
        LOG_ERR("Size mismatch found on contextBlob, got %"PRIu16" expected "
                "less than or equal to %zu", context->contextBlob.size,
                sizeof(context->contextBlob.buffer));
        result = false;
        goto out;
    }

    result = files_read_bytes(fstream, context->contextBlob.buffer,
            context->contextBlob.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

out:
    return result;
}

static bool check_magic(FILE *fstream, bool seek_reset) {

    BAIL_ON_NULL("FILE", fstream);
    UINT32 magic = 0;
    bool res = files_read_32(fstream, &magic);
    if (!res) {
        return false;
    }

    bool match = magic == MAGIC;

    if (seek_reset) {
        int rc = fseek(fstream, -sizeof(magic), SEEK_CUR);
        if (rc != 0) {
            LOG_ERR("fseek failed: %s", strerror(errno));
            return false;
        }
        return match;
    }

    if (!match) {
        LOG_ERR("Found magic 0x%x did not match expected magic of 0x%x!", magic,
                MAGIC);
    }

    return match;
}

tool_rc files_load_tpm_context_from_file(ESYS_CONTEXT *context,
        ESYS_TR *tr_handle, FILE *fstream) {

    TPMS_CONTEXT tpms_context;
    tool_rc rc = tool_rc_general_error;

    bool result = check_magic(fstream, true);
    if (result) {
        LOG_INFO("Assuming tpm context file");
        result = load_tpm_context_file(fstream, &tpms_context);
        if (!result) {
            LOG_ERR("Failed to load_tpm_context_file()");
            goto out;
        }

        return tpm2_context_load(context, &tpms_context, tr_handle);
    }

    ESYS_TR loaded_handle;
    LOG_INFO("Assuming tpm context file");
    /* try ESYS TR deserialize */
    unsigned long size = 0;
    result = files_get_file_size(fstream, &size, NULL);
    if (!result) {
        LOG_ERR("Failed to get file size: %s", strerror(ferror(fstream)));
        goto out;
    }

    if (size < 1) {
        LOG_ERR("Invalid serialized ESYS_TR size, got: %lu", size);
        goto out;
    }

    uint8_t *buffer = calloc(1, size);
    if (!buffer) {
        LOG_ERR("oom");
        goto out;
    }

    result = files_read_bytes(fstream, buffer, size);
    if (!result) {
        LOG_ERR("Could not read serialized ESYS_TR from disk");
        free(buffer);
        goto out;
    }

    rc = tpm2_tr_deserialize(context, buffer, size, &loaded_handle);
    free(buffer);
    if (rc == tool_rc_success) {
        *tr_handle = loaded_handle;
    }
    out: return rc;
}

tool_rc files_load_tpm_context_from_path(ESYS_CONTEXT *context,
        ESYS_TR *tr_handle, const char *path) {

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_WARN("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return false;
    }

    tool_rc rc = files_load_tpm_context_from_file(context, tr_handle, f);

    fclose(f);
    return rc;
}

bool files_does_file_exist(const char *path) {

    if (!path) {
        LOG_ERR("Path cannot be NULL");
        return false;
    }

    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        LOG_WARN("Path: %s already exists. Please rename or delete the file!",
                path);
        return true;
    }
    return false;
}

TEST_WEAK bool files_get_file_size_path(const char *path, unsigned long *file_size) {

    bool result = false;

    if (!path) {
        LOG_ERR("Must specify a path argument, cannot be NULL!");
        return false;
    }

    if (!file_size) {
        LOG_ERR("Must specify a file size argument, cannot be NULL!");
        return false;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERR("Could not open file: \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    result = files_get_file_size(fp, file_size, path);

    fclose(fp);
    return result;
}

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
        bool res = (readx(out, (UINT8 *)data, sizeof(*data)) == sizeof(*data)); \
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
    return (readx(out, bytes, len) == len);
}

bool files_read_bytes_chunk(FILE *out, UINT8 bytes[], size_t len, size_t *read_len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    size_t chunk_len = readx(out, bytes, len);
    *read_len += chunk_len;
    return (chunk_len == len);
}

bool files_write_bytes(FILE *out, const uint8_t *bytes, size_t len) {

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

    bool result = check_magic(out, false);
    if (!result) {
        return false;
    }

    return files_read_32(out, version);
}

bool files_load_bytes_from_buffer_or_file_or_stdin(const char *input_buffer,
        const char *path, UINT16 *size, BYTE *buf) {

    UINT16 upper_bound = *size;
    if (!upper_bound) {
        return true;
    }

    bool retval = true;
    /* Read from stdin */
    if (!input_buffer && !path) {
        UINT16 read_bytes = 0;
        while (1) {
            read_bytes += fread(buf, 1, upper_bound, stdin);
            if (feof(stdin)) {
                *size = read_bytes;
                return true;
            }
            if (ferror(stdin)) {
                LOG_ERR("Failed read from stdin.");
                return false;
            }
        }
        /* read from a buffer */
    } else if (input_buffer) {
        size_t input_buffer_size = strlen(input_buffer);
        if (path) {
            LOG_ERR("Specify either the input buffer or file path to load data,"
                    " not both");
        }
        if (input_buffer_size != (size_t) upper_bound) {
            LOG_ERR("Unexpected data size. Got %u expected %u", upper_bound,
                    (unsigned )input_buffer_size);
            return false;
        } else {
            memcpy(buf, input_buffer, input_buffer_size);
            return true;
        }
    } else if (path) {
        retval = files_load_bytes_from_path(path, buf, size);
    }

    return retval;
}

tool_rc files_save_ESYS_TR(ESYS_CONTEXT *ectx, ESYS_TR handle, const char *path) {

    size_t size;
    uint8_t *buffer;
    tool_rc rc = tpm2_tr_serialize(ectx, handle, &buffer, &size);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_bytes_to_file(path, buffer, size);
    free(buffer);
    return result ? tool_rc_success : tool_rc_general_error;
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
            LOG_ERR("Error deserializing "str(name)" structure: 0x%x", rc); \
            LOG_ERR("The input file needs to be a valid "xstr(type)" data structure"); \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

#define LOAD_TYPE_FILE(type, name) \
    bool files_load_##name##_file(FILE *f, const char *path, type *name) { \
    \
        UINT8 buffer[sizeof(*name)]; \
        UINT16 size = sizeof(buffer); \
        bool res = file_read_bytes_from_file(f, buffer, &size, path); \
        if (!res) { \
            return false; \
        } \
        \
        size_t offset = 0; \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name); \
        if (rc != TSS2_RC_SUCCESS) { \
            LOG_ERR("Error deserializing "str(name)" structure: 0x%x", rc); \
            LOG_ERR("The input file needs to be a valid "xstr(type)" data structure"); \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

#define LOAD_TYPE_SILENT(type, name) \
    bool files_load_##name##_silent(const char *path, type *name) { \
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
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
    }

SAVE_TYPE(TPM2B_PUBLIC, public)
LOAD_TYPE(TPM2B_PUBLIC, public)
LOAD_TYPE_FILE(TPM2B_PUBLIC, public)
LOAD_TYPE_SILENT(TPM2B_PUBLIC, public)

SAVE_TYPE(TPMT_PUBLIC, template)
LOAD_TYPE(TPMT_PUBLIC, template)
LOAD_TYPE_FILE(TPMT_PUBLIC, template)
LOAD_TYPE_SILENT(TPMT_PUBLIC, template)

SAVE_TYPE(TPMT_SIGNATURE, signature)
LOAD_TYPE(TPMT_SIGNATURE, signature)
LOAD_TYPE_SILENT(TPMT_SIGNATURE, signature)

SAVE_TYPE(TPMT_TK_VERIFIED, ticket)
LOAD_TYPE(TPMT_TK_VERIFIED, ticket)

SAVE_TYPE(TPMT_TK_AUTH, authorization_ticket)
LOAD_TYPE(TPMT_TK_AUTH, authorization_ticket)

SAVE_TYPE(TPMT_TK_CREATION, creation_ticket)
LOAD_TYPE(TPMT_TK_CREATION, creation_ticket)

SAVE_TYPE(TPM2B_DIGEST, digest)
LOAD_TYPE(TPM2B_DIGEST, digest)

SAVE_TYPE(TPM2B_CREATION_DATA, creation_data)
LOAD_TYPE(TPM2B_CREATION_DATA, creation_data)

SAVE_TYPE(TPM2B_SENSITIVE, sensitive)
LOAD_TYPE(TPM2B_SENSITIVE, sensitive)

SAVE_TYPE(TPMT_TK_HASHCHECK, validation)
LOAD_TYPE(TPMT_TK_HASHCHECK, validation)

SAVE_TYPE(TPM2B_PRIVATE, private)
LOAD_TYPE(TPM2B_PRIVATE, private)

SAVE_TYPE(TPM2B_ENCRYPTED_SECRET, encrypted_seed)
LOAD_TYPE(TPM2B_ENCRYPTED_SECRET, encrypted_seed)

SAVE_TYPE(TPMS_ALGORITHM_DETAIL_ECC, ecc_details)

SAVE_TYPE(TPM2B_ECC_POINT, ecc_point)
LOAD_TYPE(TPM2B_ECC_POINT, ecc_point)

LOAD_TYPE(TPM2B_ECC_PARAMETER, ecc_parameter)

LOAD_TYPE_FILE(TPMS_ATTEST, attest)

tool_rc files_tpm2b_attest_to_tpms_attest(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest) {

    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData,
            quoted->size, &offset, attest);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_MU_TPM2B_ATTEST_Unmarshal, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc files_load_unique_data(const char *file_path, TPM2B_PUBLIC *public_data) {
    /*
     * When loading from a file_path (as opposed to stdin), we are
     * reading the raw TPMU_PUBLIC_ID union contents, aka the
     * whole publicArea.unique field.
     *
     * When loading from stdin, we're reading a subset of the
     * TPMU_PUBLIC_ID union fields, varying according to the
     * key type.
     */
    UINT16 unique_size = sizeof(public_data->publicArea.unique);
    uint8_t file_data[sizeof(public_data->publicArea.unique)];
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
    file_path, &unique_size, file_data);
    if (!result) {
        LOG_ERR("Failed to load unique data from file/ stdin.");
        return tool_rc_general_error;
    }

    /*
     * If the data is specified as a file, the user is responsible for ensuring
     * that that this buffer is formatted as TPMU_PUBLIC_ID union.
     */
    if (file_path) {
        memcpy(&public_data->publicArea.unique, file_data, unique_size);
        return tool_rc_success;
    }

    /* Unstructured stdin unique data paired with a RSA object */
    if (public_data->publicArea.type == TPM2_ALG_RSA) {
        if (unique_size > TPM2_MAX_RSA_KEY_BYTES) {
            LOG_ERR("Unique data too big for RSA object's allowed unique size");
            return tool_rc_general_error;
        }
        public_data->publicArea.unique.rsa.size = unique_size;
        memcpy(&public_data->publicArea.unique.rsa.buffer, file_data,
        unique_size);
    }

    /* Unstructured stdin unique data paired with an ECC object */
    if (public_data->publicArea.type == TPM2_ALG_ECC) {
        /* The size limitation is TPM implementation dependent. */
        if((unique_size / 2) > TPM2_MAX_ECC_KEY_BYTES) {
            LOG_ERR("Unique data too big for ECC object's allowed unique size");
            return tool_rc_general_error;
        }
        /* Copy data into X and Y coordinates unique buffers */
        public_data->publicArea.unique.ecc.x.size = (unique_size / 2);
        memcpy(&public_data->publicArea.unique.ecc.x.buffer, file_data,
        (unique_size / 2));
        /* Copy the rest of buffer to y and also adjust size if input is odd */
        public_data->publicArea.unique.ecc.y.size = (unique_size / 2) +
        (unique_size % 2);
        memcpy(&public_data->publicArea.unique.ecc.y.buffer,
        file_data + (unique_size / 2), (unique_size / 2));
    }

    /* Unstructured stdin unique data paired with an Keyedhash object */
    if (public_data->publicArea.type == TPM2_ALG_KEYEDHASH) {
        /* The size limitation is TPM implementation dependent. */
        if (unique_size > sizeof(TPMU_HA)) {
            LOG_ERR("Unique data too big for keyedhash object's allowed unique "
            "size.");
            return tool_rc_general_error;
        }
        public_data->publicArea.unique.keyedHash.size = unique_size;
        memcpy(&public_data->publicArea.unique.keyedHash.buffer, file_data,
        unique_size);
    }

    /* Unstructured stdin unique data paired with an Symcipher object */
    if (public_data->publicArea.type == TPM2_ALG_SYMCIPHER) {
        /* The size limitation is TPM implementation dependent. */
        if (unique_size > sizeof(TPMU_HA)) {
            LOG_ERR("Unique data too big for TPM2_ALG_SYMCIPHER object's "
                    "allowed unique size.");
            return tool_rc_general_error;
        }
        public_data->publicArea.unique.sym.size = unique_size;
        memcpy(&public_data->publicArea.unique.sym.buffer, file_data,
        unique_size);
    }

    return tool_rc_success;
}
