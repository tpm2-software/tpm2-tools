/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef FILES_H
#define FILES_H

#include <stdbool.h>
#include <stdio.h>

#include <tss2/tss2_esys.h>

#include "tool_rc.h"

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
 * Like files_load_bytes_from_path() but uses a FILE pointer.
 * @param f
 *  The FILE pointer to read from.
 * @param buf
 *  The buffer to store the data.
 * @param size
 *  On input the max size of the buffer, on success the actual count of bytes read.
 * @param path
 *  A possible path for error reporting, can be NULL to silence error reporting.
 * @return
 *  True on success, false otherwise.
 */
bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path);

/**
 * Loads data from an input buffer or file path or stdin enforcing an upper bound on size.
 * @param input_buffer
 *   The buffer to read the input data from, NULL means either specified by path or stdin
 * @param path
 *  The path to load data from, NULL means stdin.
 * @param size
 *  The maximum size.
 * @param buf
 *  The buffer to write the data into.
 * @return
 *  True on success or false otherwise.
 */
bool files_load_bytes_from_buffer_or_file_or_stdin(const char *input_buffer,
        const char *path, UINT16 *size, BYTE *buf);

/**
 * Similar to files_write_bytes(), in that it writes an array of bytes to disk,
 * but this routine opens and closes the file on the callers behalf. If the path
 * is NULL and silent output has not been enabled, then stdout is used.
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
 * Saves the TPM ESAPI context for an object handle to disk by calling
 * ContextSave() and serializing the resulting TPMS_CONTEXT structure
 * to disk.
 * @param context
 *  The Enhances System API (ESAPI) context
 * @param handle
 *  The object handle for the object to save.
 * @param path
 *  The output path of the file.
 *
 * @return
 *  tool_rc indicating status.
 */
tool_rc files_save_tpm_context_to_path(ESYS_CONTEXT *context, ESYS_TR handle,
        const char *path);

/**
 * Like files_save_tpm_context_to_path() but saves a tpm session to a FILE stream.
 * @param context
 *  The Enhances System API (ESAPI) context
 * @param handle
 *  The object handle for the object to save.
 * @param stream
 *  The FILE stream to save too.
 * @return
 *  tool_rc indicating status.
 */
tool_rc files_save_tpm_context_to_file(ESYS_CONTEXT *context, ESYS_TR handle,
        FILE *stream);

/**
 * Loads a ESAPI TPM object context from disk or an ESAPI serialized ESYS_TR object.
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param tr_handle
 *  Optional. The Esys handle for the TPM2 object.
 * @param path
 *  The path to the input file.
 * @return
 *  tool_rc status indicating success.
 */
tool_rc files_load_tpm_context_from_path(ESYS_CONTEXT *context,
        ESYS_TR *tr_handle, const char *path);

/**
 * Like files_load_tpm_context_from_path() but loads the context from a FILE stream.
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param tr_handle
 *  Optional. The Esys handle for the TPM2 object
 * @param stream
 *  The FILE stream to read from.
 * @return
 *  tool_rc status indicating success.
 */
tool_rc files_load_tpm_context_from_file(ESYS_CONTEXT *context,
        ESYS_TR *tr_handle, FILE *stream);

/**
 * Save an ESYS_TR to disk.
 * @param ectx
 *  The ESAPI context
 * @param handle
 *  The handle to serialize.
 * @param path
 *  The path to save to.
 * @return
 *  A tool_rc indicating status.
 */
tool_rc files_save_ESYS_TR(ESYS_CONTEXT *ectx, ESYS_TR handle, const char *path);

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
 * Serializes a TPMT_PUBLIC to the file path provided.
 * @param template
 *  The TPMT_PUBLIC to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_template(TPMT_PUBLIC *template, const char *path);

/**
 * Like files_load_template(), but doesn't report errors.
 * @param path
 *  The path containing the TPMT_PUBLIC to load from.
 * @param public
 *  The destination for the TPMT_PUBLIC.
 * @return
 *  true on success, false otherwise.
 */
bool files_load_template_silent(const char *path, TPMT_PUBLIC *public);

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
 * Like files_load_public(), but doesn't report errors.
 * @param path
 *  The path containing the TP2B_PUBLIC to load from.
 * @param public
 *  The destination for the TP2B_PUBLIC.
 * @return
 *  true on success, false otherwise.
 */
bool files_load_public_file(FILE *f, const char *path, TPM2B_PUBLIC *public);

bool files_load_template(const char *path, TPMT_PUBLIC *public);

bool files_load_template_file(FILE *f, const char *path, TPMT_PUBLIC *public);

/**
 * Like files_load_public(), but doesn't report errors.
 * @param path
 *  The path containing the TP2B_PUBLIC to load from.
 * @param public
 *  The destination for the TP2B_PUBLIC.
 * @return
 *  true on success, false otherwise.
 */
bool files_load_public_silent(const char *path, TPM2B_PUBLIC *public);

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
 * Like files_save)signature() but doesn't complain about libmu failures.
 * Useful if you're trying to probe if its a plain or tss format signature.
 * @param path
 *  The path to load from.
 * @param signature
 *  The TPMT_SIGNATURE to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_signature_silent(const char *path, TPMT_SIGNATURE *signature);

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
 * Serializes a TPMT_TK_AUTH to the file path provided.
 * @param signature
 *  The TPMT_SIGNATURE to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_authorization_ticket(TPMT_TK_AUTH *authorization_ticket,
    const char *path);

/**
 * Loads a TPMT_TK_AUTH from disk that was saved with
 * files_save_authorization_ticket()
 * @param path
 *  The path to load from.
 * @param signature
 *  The TPMT_TK_AUTH to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_authorization_ticket(const char *path,
    TPMT_TK_AUTH *authorization_ticket);

bool files_load_creation_data(const char *path,
    TPM2B_CREATION_DATA *creation_data);

bool files_save_creation_data(TPM2B_CREATION_DATA *creation_data,
    const char *path);

bool files_load_creation_ticket(const char *path,
    TPMT_TK_CREATION *creation_ticket);

bool files_save_creation_ticket(TPMT_TK_CREATION *creation_ticket,
    const char *path);

bool files_load_digest(const char *path, TPM2B_DIGEST *digest);

bool files_save_digest(TPM2B_DIGEST *digest, const char *path);

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
 * Serializes a TPM2B_ENCRYPTED_SECRET to the file path provided.
 * @param encrypted_seed
 *  The TPM2B_ENCRYPTED_SECRET to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_encrypted_seed(TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        const char *path);

/**
 * Serializes a TPM2B_ECC_POINT to the file path provided.
 * @param Q
 *  The TPM2B_ECC_POINT to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_ecc_point(TPM2B_ECC_POINT *Q, const char *path);

/**
 * Loads a TPM2B_ECC_POINT from disk.
 * @param path
 *  The path to load from.
 * @param Q
 *  The TPM2B_ECC_POINT data to load.
 */
bool files_load_ecc_point(const char *path, TPM2B_ECC_POINT *Q);

/**
 * Loads a TPM2B_ECC_PARAMETER from disk
 * @param path
 *  The path to load from.
 * @param parameter
 *  The TPM2B_ECC_PARAMETER data to load.
 */
bool files_load_ecc_parameter(const char *path, TPM2B_ECC_PARAMETER *parameter);

/**
 * Loads a TPM2B_ENCRYPTED_SECRET from disk.
 * @param encrypted_seed
 *  The path to load from.
 * @param validation
 *  The TPM2B_ENCRYPTED_SECRET to load.
 * @return
 *  true on success, false on error.
 */
bool files_load_encrypted_seed(const char *path,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed);

/**
 * Serializes a TPMS_ALGORITHM_DETAIL_ECC to the file path provided.
 * @param parameters
 *  The TPMS_ALGORITHM_DETAIL_ECC to save to disk.
 * @param path
 *  The path to save to.
 * @return
 *  true on success, false on error.
 */
bool files_save_ecc_details(TPMS_ALGORITHM_DETAIL_ECC *parameters,
    const char *path);

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
 *  The path of the file to retrieve the size of.
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
bool files_write_bytes(FILE *out, const UINT8 *data, size_t size);

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

/**
 * Reads len bytes from a file and set the read length.
 * @param out
 *  The file to read from.
 * @param data
 *  The buffer to read into, only valid on a True return.
 * @param size
 *  The number of bytes to read.
 * @param read_size
 *  Total number of bytes read.
 * @return
 *  True on success, False otherwise.
 */
bool files_read_bytes_chunk(FILE *out, UINT8 data[], size_t size, size_t *read_size);

/**
 * Converts a TPM2B_ATTEST to a TPMS_ATTEST using libmu.
 * @param quoted
 *  The attestation quote structure.
 * @param attest
 *  The TPMS_ATTEST to populate.
 * @return
 *  tool_rc_success on success, false otherwise.
 */
tool_rc files_tpm2b_attest_to_tpms_attest(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest);

/**
 * Loads a TPMS_ATTEST from disk.
 * @param f
 *  The file to load.
 * @param path
 *  The path to load from.
 * @param attest
 *  The attest structure to fill up.
 * @return
 *  True on success, false otherwise.
 */
bool files_load_attest_file(FILE *f, const char *path, TPMS_ATTEST *attest);

/**
 * @brief
 * Parse the key type and load the unique data in the object's
 * TPM2B_PUBLIC area.
 *
 * @param file_path
 * The file to read the unique data from. This can be NULL to indicate stdin
 * @param public_data
 * The TPM2B public structure to parse the object type and also to update the
 * unique data as read from the file or stdin.
 *
 * @return
 * tool_rc type signaling the status at the end of read attempt.
 *
 */
tool_rc files_load_unique_data(const char *file_path,
TPM2B_PUBLIC *public_data);

#endif /* FILES_H */
