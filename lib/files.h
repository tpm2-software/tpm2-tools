#ifndef FILES_H
#define FILES_H

#include <stdbool.h>
#include <stdio.h>

#include <sapi/tpm20.h>

/*
 * These old routines are not aware of endianess and lack the tpm2 tools file header,
 * the should be updated and replaced with something using the new files_write_* api
 * documented below. Mark all of them as deprecated as a constant reminder this needs
 * to be done.
 */
int loadDataFromFile(const char *fileName, UINT8 *buf, UINT16 *size) __attribute__ ((deprecated));
int saveDataToFile(const char *fileName, UINT8 *buf, UINT16 size) __attribute__ ((deprecated));
int saveTpmContextToFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle, const char *fileName) __attribute__ ((deprecated));
int loadTpmContextFromFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE *handle, const char *fileName) __attribute__ ((deprecated));

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
 *  A pointer to a long to return the file size. The
 *  pointed to value is valid only on a true return.
 *
 * @return
 *  True for success or False for error.
 */
bool files_get_file_size(const char *path, long *file_size);

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
