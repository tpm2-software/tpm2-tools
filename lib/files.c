#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "files.h"
#include "log.h"
#include "tpm2_util.h"

static bool get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        LOG_ERR("Error getting current file offset for file \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        LOG_ERR("Error seeking to end of file \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        LOG_ERR("ftell on file \"%s\" failed: %s", path, strerror(errno));
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        LOG_ERR("Could not restore initial stream position for file \"%s\" failed: %s", path, strerror(errno));
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long)size;
    return true;
}

static bool read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
                                 const char *path) {
    unsigned long file_size;
    bool result = get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on UINT16 */
    if (file_size > *size) {
        LOG_ERR(
                "File \"%s\" size is larger than buffer, got %lu expected less than %u",
                path, file_size, *size);
        return false;
    }

    result = files_read_bytes(f, buf, file_size);
    if (!result) {
        LOG_ERR("Could not read data from file \"%s\"", path);
        return false;
    }

    *size = file_size;

    return true;
}

bool files_load_bytes_from_file(const char *path, UINT8 *buf, UINT16 *size) {
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

bool files_load_bytes_from_stdin(UINT8 *buf, UINT16 *size) {
    if (!buf || !size) {
        return false;
    }

    return read_bytes_from_file(stdin, buf, size, "stdin");
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

bool files_save_tpm_context_to_file(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle,
        const char *path) {

    TPMS_CONTEXT context;

    TPM_RC rval = Tss2_Sys_ContextSave(sysContext, handle, &context);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR(
                "Tss2_Sys_ContextSave: Saving handle 0x%x context failed. TPM Error:0x%x",
                handle, rval);
        return false;
    }

    FILE *f = fopen(path, "w+b");
    if (!f) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
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
    bool result = files_write_header(f, CONTEXT_VERSION);
    if (!result) {
        LOG_ERR("Could not write header for file: \"%s\"", path);
        goto out;
    }

    // UINT32
    result = files_write_32(f, context.hierarchy);
    if (!result) {
        LOG_ERR("Could not write hierarchy for file: \"%s\"", path);
        goto out;
    }

    result = files_write_32(f, context.savedHandle);
    if (!result) {
        LOG_ERR("Could not write savedHandle for file: \"%s\"", path);
        goto out;
    }

    // UINT64
    result = files_write_64(f, context.sequence);
    if (!result) {
        LOG_ERR("Could not write sequence for file: \"%s\"", path);
        goto out;
    }

    // U16 LENGTH
    result = files_write_16(f, context.contextBlob.t.size);
    if (!result) {
        LOG_ERR("Could not write contextBob size file: \"%s\"", path);
        goto out;
    }

    // BYTE[] contextBlob
    result = files_write_bytes(f, context.contextBlob.t.buffer,
            context.contextBlob.t.size);
    if (!result) {
        LOG_ERR("Could not write contextBlob buffer for file: \"%s\"", path);
    }
    /* result is set by file_write_bytes() */

out:
    fclose(f);
    return result;
}

bool file_load_tpm_context_from_file(TSS2_SYS_CONTEXT *sapi_context,
        TPM_HANDLE *handle, const char *path) {

    TPM_RC rval;

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Error opening file \"%s\" due to error: %s", path,
                strerror(errno));
        return false;
    }

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
    bool result = files_read_header(f, &version);
    if (!result) {
        LOG_WARN(
                "The tpm context file \"%s\" does not appear in the proper format, assuming old format, this will be converted on the next save.",
                path);
        rewind(f);
        result = files_read_bytes(f, (UINT8 *) &context, sizeof(context));
        if (!result) {
            LOG_ERR("Could not load file \"%s\" into tpm context", path);
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

    result = files_read_32(f, &context.hierarchy);
    if (!result) {
        LOG_ERR("Error reading hierarchy!");
        goto out;
    }

    result = files_read_32(f, &context.savedHandle);
    if (!result) {
        LOG_ERR("Error reading savedHandle!");
        goto out;
    }

    result = files_read_64(f, &context.sequence);
    if (!result) {
        LOG_ERR("Error reading sequence!");
        goto out;
    }

    result = files_read_16(f, &context.contextBlob.t.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

    if (context.contextBlob.t.size > sizeof(context.contextBlob.t.buffer)) {
        LOG_ERR(
                "Size mismatch found on contextBlob, got %"PRIu16" expected less than or equal to %zu",
                context.contextBlob.t.size,
                sizeof(context.contextBlob.t.buffer));
        result = false;
        goto out;
    }

    result = files_read_bytes(f, context.contextBlob.t.buffer,
            context.contextBlob.t.size);
    if (!result) {
        LOG_ERR("Error reading contextBlob.size!");
        goto out;
    }

load_to_tpm:
    rval = Tss2_Sys_ContextLoad(sapi_context, &context, handle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("ContextLoad Error. TPM Error:0x%x", rval);
        result = false;
        goto out;
    }

    result = true;

out:
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

bool files_get_file_size(const char *path, unsigned long *file_size) {

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

    result = get_file_size(fp, file_size, path);

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
