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
 * Loads data from a file path or stdin enforcing an upper bound on size.
 * @param path
 *  The path to load data from, NULL means stdin.
 * @param size
 *  The maximum size.
 * @param buf
 *  The buffer to write the data into.
 * @return
 *  True on success or false otherwise.
 */
bool files_load_bytes_from_file_or_stdin(const char *path, UINT16 *size, BYTE *buf);

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
bool files_save_tpm_context_to_path(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE handle, const char *path);

/**
 * Like files_save_tpm_context_to_path() but saves a tpm session to a FILE stream.
 * @param sapi_context
 *  The system api context
 * @param handle
 *  The object handle for the object to save.
 * @param stream
 *  The FILE stream to save too.
 * @return
 *  True on success, False on error.
 */
bool files_save_tpm_context_to_file(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE handle,
        FILE *stream);

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
bool files_load_tpm_context_from_path(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE *handle, const char *path);

/**
 * Like files_load_tpm_context_from_path() but loads the context from a FILE stream.
 * @param sapi_context
 *  The system API context
 * @param handle
 *  The object handle that was saved.
 * @param stream
 *  The FILE stream to read from.
 * @return
 *  True on success, False on error.
 */
bool files_load_tpm_context_from_file(TSS2_SYS_CONTEXT *sapi_context,
        TPM2_HANDLE *handle, FILE *stream);

/**
 * Serializes a TPM2B_PUBLIC to the file path provided.
 * @param public
 *  The TPM2B_PUBLIC to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_public(TPM2B_PUBLIC *public, const char *path);

/**
 * Loads a TPM2B_PUBLIC from disk that was saved with files_save_pubkey()
 * @param path
 *  The path to load from.
 * @param public
 *  The TPM2B_PUBLIC to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_public(const char *path, TPM2B_PUBLIC *public);

/**
 * Serializes a TPMT_SIGNATURE to the file path provided.
 * @param signature
 *  The TPMT_SIGNATURE to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_signature(TPMT_SIGNATURE *signature, const char *path);

/**
 * Loads a TPMT_SIGNATURE from disk that was saved with files_save_signature()
 * @param path
 *  The path to load from.
 * @param signature
 *  The TPMT_SIGNATURE to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_signature(const char *path, TPMT_SIGNATURE *signature);

/**
 * Serializes a TPMT_TK_VERIFIED to the file path provided.
 * @param signature
 *  The TPMT_SIGNATURE to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_ticket(TPMT_TK_VERIFIED *ticket, const char *path);

/**
 * Loads a TPMT_TK_VERIFIED from disk that was saved with files_save_ticket()
 * @param path
 *  The path to load from.
 * @param signature
 *  The TPMT_TK_VERIFIED to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_ticket(const char *path, TPMT_TK_VERIFIED *ticket);

/**
 * Loads a TPM2B_SENSITIVE from disk.
 * @param path
 *  The path to load from.
 * @param signature
 *  The TPM2B_SENSITIVE to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_sensitive(const char *path, TPM2B_SENSITIVE *sensitive);

/**
 * Serializes a TPM2B_SENSITIVE to the file path provided.
 * @param sensitive
 *  The TPM2B_SENSITIVE to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_sensitive(TPM2B_SENSITIVE *sensitive, const char *path);
/**
 * Serializes a TPMT_TK_HASHCHECK to the file path provided.
 * @param validation
 *  The TPMT_TK_HASHCHECK to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_validation(TPMT_TK_HASHCHECK *validation, const char *path);

/**
 * Loads a TPMT_TK_HASHCHECK from disk.
 * @param path
 *  The path to load from.
 * @param validation
 *  The TPMT_TK_HASHCHECK to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_validation(const char *path, TPMT_TK_HASHCHECK *validation);

/**
 * Serializes a TPM2B_PRIVATE to the file path provided.
 * @param private
 *  The TPM2B_PRIVATE to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_private(TPM2B_PRIVATE *private, const char *path);

/**
 * Loads a TPM2B_PRIVATE from disk.
 * @param private
 *  The path to load from.
 * @param validation
 *  The TPM2B_PRIVATE to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_private(const char *path, TPM2B_PRIVATE *private);

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
 *  An optional path used for error reporting, a NULL path disables error logging.
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
