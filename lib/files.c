#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "files.h"
#include "log.h"
#include "string-bytes.h"

int loadDataFromFile(const char *fileName, UINT8 *buf, UINT16 *size)
{
    UINT16 count = 1, left;
    FILE *f;
    if ( size == NULL || buf == NULL || fileName == NULL )
        return -1;

    f = fopen(fileName, "rb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    left = *size;
    *size = 0;
    while( left > 0 && count > 0 )
    {
        count = fread(buf, 1, left, f);
        *size += count;
        left -= count;
        buf += count;
    }

    if( *size == 0 )
    {
        printf("File read error\n");
        fclose(f);
        return -3;
    }
    fclose(f);
    return 0;
}

int saveDataToFile(const char *fileName, UINT8 *buf, UINT16 size)
{
    FILE *f;
    UINT16 count = 1;
    if( fileName == NULL || buf == NULL || size == 0 )
        return -1;

    f = fopen(fileName, "wb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    while( size > 0 && count > 0 )
    {
        count = fwrite(buf, 1, size, f);
        size -= count;
        buf += count;
    }

    if( size > 0 )
    {
        printf("File write error\n");
        fclose(f);
        return -3;
    }

    fclose(f);
    return 0;
}

int saveTpmContextToFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle, const char *fileName)
{
    TPM_RC rval;
    TPMS_CONTEXT context;

    rval = Tss2_Sys_ContextSave( sysContext, handle, &context);
    if( rval == TPM_RC_SUCCESS &&
        saveDataToFile(fileName, (UINT8 *)&context, sizeof(TPMS_CONTEXT)) )
        rval = TPM_RC_FAILURE;

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextSave:Save handle 0x%x context failed. TPM Error:0x%x......\n", handle, rval);
        return -1;
    }

    return 0;
}

int loadTpmContextFromFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE *handle, const char *fileName)
{
    TPM_RC rval = TPM_RC_SUCCESS;
    UINT16 size = sizeof(TPMS_CONTEXT);
    TPMS_CONTEXT context;

    if( loadDataFromFile(fileName, (UINT8 *)&context, &size) )
        rval = TPM_RC_FAILURE;
    if( rval == TPM_RC_SUCCESS )
        rval = Tss2_Sys_ContextLoad(sysContext, &context, handle);

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextLoad Error. TPM Error:0x%x......\n", rval);
        return -1;
    }

    return 0;
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

bool files_get_file_size(const char *path, long *file_size) {

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

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        LOG_ERR("Error seeking to end of file \"%s\" error: %s", path, strerror(errno));
        goto err;
    }

    long size = ftell(fp);
    if (size < 0) {
        LOG_ERR("ftell on file \"%s\" failed: %s", path, strerror(errno));
        goto err;
    }

    *file_size = size;
    result = true;

err:
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
    do {
        wrote = fwrite(&data[wrote], 1, size, f);
        if (wrote != size) {
            if (errno != EINTR) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= wrote;
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
    do {
        bread = fread(&data[bread], 1, size, f);
        if (bread != size) {
            if (feof(f) || (errno != EINTR)) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= bread;
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
        if (!string_bytes_is_host_big_endian()) { \
            value = string_bytes_endian_convert_##size(value); \
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
