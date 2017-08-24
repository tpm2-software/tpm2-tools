#ifndef FILES_H
#define FILES_H

#include <stdbool.h>
#include <stdio.h>

#include <sapi/tpm20.h>

/**
 * Reads a series of bytes from a file as a byte array. This is similar to files_read_bytes(),
 * but opens and closes the FILE for the caller. Size is both an input and output value where
 * the size value is the max buffer size on call and the returned size is how much was read.
 *
 * This interface could be cleaned up in a later revision.
 * @param path
 *  The path to the file to open.
 * @param buf
 *  The buffer to read the data into
 * @param size
 *  The max size of the buffer on call, and the size of the data read on return.
 * @return
 *  True on success, false otherwise.
 */
bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size);

/**
 * Reads a series of bytes from a stdio FILE object.
 * @param file
 *  The file to read from.
 * @param buf
 *  The buffer to read into.
 * @param size
 *  The size of the buffer to read into.
 * @param path
 *  A path used for error reporting.
 * @return
 *  True on success, False otherwise.
 */
bool files_load_bytes_from_file(FILE *file, UINT8 *buf, UINT16 *size, const char *path);

/**
 * Reads a series of bytes from the standard input as a byte array. This is similar to
 * files_read_bytes(), but it calculates the size to read for the caller. Size is both
 * an input and output value where the size value is the max buffer size on call and
 * the returned size is how much was read.
 *
 * @param buf
 *  The buffer to read the data into
 * @param size
 *  The max size of the buffer on call, and the size of the data read on return.
 * @return
 *  True on success, false otherwise.
 */
static inline bool files_load_bytes_from_stdin(UINT8 *buf, UINT16 *size) {
    return files_load_bytes_from_file(stdin, buf, size, "<stdin>");
}

/**
 * Similar to files_write_bytes(), in that it writes an array of bytes to disk,
 * but this routine opens and closes the file on the callers behalf.
 * @param path
 *  The path to the file to write the data to.
 * @param buf
 *  The buffer of data to write
 * @param size
 *  The size of the data to write in bytes.
 * @return
 *  True on success, false otherwise.
 */
bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size);

/**
 * Saves the TPM context for an object handle to disk by calling Tss2_Sys_ContextSave() and serializing the
 * resulting TPMS_CONTEXT structure to disk.
 * @param sapi_context
 *  The system api context
 * @param handle
 *  The object handle for the object to save.
 * @param path
 *  The output path of the file.
 *
 * @return
 *  True on success, False on error.
 */
bool files_save_tpm_context_to_file(TSS2_SYS_CONTEXT *sapi_context, TPM_HANDLE handle, const char *path);

/**
 * Loads a TPM object context from disk.
 * @param sapi_context
 *  The system API context
 * @param handle
 *  The object handle that was saved.
 * @param path
 *  The path to the input file.
 * @return
 *  True on Success, false on error.
 */
bool files_load_tpm_context_from_file(TSS2_SYS_CONTEXT *sapi_context, TPM_HANDLE *handle, const char *path);

/**
 * Checks a file for existence.
 * @param path
 *  The file to check for existence.
 * @return
 * true if a file exists with read permissions, false if it doesn't exist or an error occurs.
 *
 */
bool files_does_file_exist(const char *path);

/**
 * Retrieves a files size given a file path.
 * @param path
 *  The path of the file to retreive the size of.
 * @param file_size
 *  A pointer to an unsigned long to return the file size. The
 *  pointed to value is valid only on a true return.
 *
 * @return
 *  True for success or False for error.
 */
bool files_get_file_size_path(const char *path, unsigned long *file_size);

/**
 * Similar to files_get_file_size_path(), but uses an already opened FILE object.
 * @param fp
 *  The file pointer to query the size of.
 * @param file_size
 *  Output of the file size.
 * @param path
 *  A path used for error reporting.
 * @return
 *  True on success, False otherwise.
 */
bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path);

/**
 * Writes a TPM2.0 header to a file.
 * @param f
 *  The file to write to.
 * @param version
 *  The version number of the format of the file.
 * @return
 *  True on success, false on error.
 */
bool files_write_header(FILE *f, UINT32 version);

/**
 * Reads a TPM2.0 header from a file.
 * @param f
 *  The file to read.
 * @param version
 *  The version that was found.
 * @return
 *  True on Success, False on error.
 */
bool files_read_header(FILE *f, UINT32 *version);

/**
 * Writes a 16 bit value to the file in big endian, converting
 * if needed.
 * @param out
 *  The file to write.
 * @param data
 *  The 16 bit value to write.
 * @return
 *  True on success, False on error.
 */
bool files_write_16(FILE *out, UINT16 data);

/**
 * Same as files_write_16 but for 32 bit values.
 */
bool files_write_32(FILE *out, UINT32 data);

/**
 * Same as files_write_16 but for 64 bit values.
 */
bool files_write_64(FILE *out, UINT64 data);

/**
 * Writes a byte array out to a file.
 * @param out
 *  The file to write to.
 * @param data
 *  The data to write.
 * @param size
 *  The size of the data to write in bytes.
 * @return
 *  True on success, False otherwise.
 */
bool files_write_bytes(FILE *out, UINT8 data[], size_t size);

/**
 * Reads a 16 bit value from a file converting from big endian to host
 * endianess.
 * @param out
 *  The file to read from.
 * @param data
 *  The data that is read, valid on a true return.
 * @return
 *  True on success, False on error.
 */
bool files_read_16(FILE *out, UINT16 *data);

/**
 * Same as files_read_16 but for 32 bit values.
 */
bool files_read_32(FILE *out, UINT32 *data);

/**
 * Same as files_read_16 but for 64 bit values.
 */
bool files_read_64(FILE *out, UINT64 *data);

/**
 * Reads len bytes from a file.
 * @param out
 *  The file to read from.
 * @param data
 *  The buffer to read into, only valid on a True return.
 * @param size
 *  The number of bytes to read.
 * @return
 *  True on success, False otherwise.
 */
bool files_read_bytes(FILE *out, UINT8 data[], size_t size);

#endif /* FILES_H */
