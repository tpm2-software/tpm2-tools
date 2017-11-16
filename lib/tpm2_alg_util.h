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
#ifndef LIB_TPM2_ALG_UTIL_H_
#define LIB_TPM2_ALG_UTIL_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

/**
 * Iterator callback routine for iterating over known algorithm name and value
 * pairs.
 * @param id
 *  The algorithm id.
 * @param name
 *  The associated "nice-name".
 * @param userdata
 *  A user supplied data pointer.
 * @return
 *  True to stop iterating, false to keep iterating.
 */
typedef bool (*tpm2_alg_util_alg_iteraror)(TPM2_ALG_ID id, const char *name, void *userdata);

/**
 * Iterate over the algorithm name-value pairs calling the iterator callback for each pair.
 * @param iterator
 *  The iterator callback function.
 * @param userdata
 *  A pointer to user supplied data, this is passed to the iterator for each call.
 */
void tpm2_alg_util_for_each_alg(tpm2_alg_util_alg_iteraror iterator, void *userdata);

/**
 * Convert a "nice-name" string to an algorithm id.
 * @param name
 *  The "nice-name" to convert.
 * @return
 *  TPM2_ALG_ERROR on error, or a valid algorithm identifier.
 */
TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name);

/**
 * Convert an id to a nice-name.
 * @param id
 *  The id to convert.
 * @return
 *  The nice-name.
 */
const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id);

/**
 * Converts either a string from algrotithm number or algorithm nice-name to
 * an algorithm id.
 * @param optarg
 *  The string to convert from an algorithm number or nice name.
 * @return
 *  TPM2_ALG_ERROR on error or the algorithm id.
 */
TPM2_ALG_ID tpm2_alg_util_from_optarg(char *optarg);

/**
 * Detects if an algorithm is considered a hashing algorithm.
 * @param id
 *  The algorithm id to check.
 * @return
 *  True if it is a hash algorithm, False otherwise.
 */
bool tpm2_alg_util_is_hash_alg(TPM2_ALG_ID id);

/**
 * Contains the information from parsing an argv style vector of strings for
 * pcr digest language specifications.
 */
typedef struct tpm2_pcr_digest_spec tpm2_pcr_digest_spec;
struct tpm2_pcr_digest_spec {
    TPML_DIGEST_VALUES digests;
    TPMI_DH_PCR pcr_index;
};

/**
 * Parses an argv array that contains a digest specification at each location
 * within argv.
 *
 * The digest specification is as follows:
 *   - A pcr identifier as understood by strtoul with 0 as the base.
 *   - A colon followed by the algorithm hash specification.
 *   - The algorithm hash specification is as follows:
 *       - The algorithm friendly name or raw numerical as understood by
 *         strtoul with a base of 0.
 *       - An equals sign
 *       - The hex hash value,
 *
 *   This all distills to a string that looks like this:
 *   <pcr index>:<hash alg id>=<hash value>
 *
 *   Example:
 *   "4:sha=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"
 *
 *   Note:
 *   Multiple specifications of PCR and hash are OK. Multiple hashes
 *   cause the pcr to be extended with both hashes. Multiple same PCR
 *   values cause the PCR to be extended multiple times. Extension
 *   is done in order from left to right as specified.
 *
 *   At most 5 hash extensions per PCR entry are supported. This
 *   is to keep the parser simple.
 *
 * @param sapi_context
 *  The system API context for hashing files with the tpm. This can
 *  be NULL if the argument vector doesn't have a file spec for the hash.
 * @param argv
 *  The argv of digest specifications to parse.
 * @param len
 *  The number of digest specifications to parse.
 * @param digests
 *  An array of tpm2_pcr_digest_spec big enough to hold len items.
 * @return
 *  True if parsing was successful, False otherwise.
 *  @note
 *  This function logs errors via LOG_ERR.
 */
bool pcr_parse_digest_list(char **argv, int len,
        tpm2_pcr_digest_spec *digest_spec);

/**
 * Retrieves the size of a hash in bytes for a given hash
 * algorithm or 0 if unknown/not found.
 * @param id
 *  The HASH algorithm identifier.
 * @return
 *  0 on failure or the size of the hash bytes.
 */
UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id);

/**
 * Extracts the plain signature data without any headers
 *
 * Communicates errors via LOG_ERR.
 *
 * @param size
 *  Will receive the number of bytes stored in buffer.
 * @signature The actual signature struct to extract the plain signature from.
 * @return
 *  Returns a buffer filled with the extracted signature or NULL on error.
 *  Needs to be free()'d by the caller.
 */
UINT8* tpm2_extract_plain_signature(UINT16 *size, TPMT_SIGNATURE *signature);

/**
 * Retrieves an approproate signature scheme (scheme) signable by
 * specified key (keyHandle) and hash algorithm (halg).
 * @param sapi_context
 *  System API context for tpm
 * @param keyHandle
 *  Handle to key used in signing operation
 * @param halg
 *  Hash algoritm for message
 * @param scheme
 *  Signature scheme output
 * @return
 *  True if successful
 *  False otherwise, and scheme is left unmodified
 */
bool get_signature_scheme(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle, TPMI_ALG_HASH halg,
        TPMT_SIG_SCHEME *scheme);

#endif /* LIB_TPM2_ALG_UTIL_H_ */
