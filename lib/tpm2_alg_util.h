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
typedef bool (*tpm2_alg_util_alg_iteraror)(TPM_ALG_ID id, const char *name, void *userdata);

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
 *  TPM_ALG_ERROR on error, or a valid algorithm identifier.
 */
TPM_ALG_ID tpm2_alg_util_strtoalg(const char *name);

/**
 * Convert an id to a nice-name.
 * @param id
 *  The id to convert.
 * @return
 *  The nice-name.
 */
const char *tpm2_alg_util_algtostr(TPM_ALG_ID id);

/**
 * Converts either a string from algrotithm number or algorithm nice-name to
 * an algorithm id.
 * @param optarg
 *  The string to convert from an algorithm number or nice name.
 * @return
 *  TPM_ALG_ERROR on error or the algorithm id.
 */
TPM_ALG_ID tpm2_alg_util_from_optarg(char *optarg);

/**
 * Detects if an algorithm is considered a hashing algorithm.
 * @param id
 *  The algorithm id to check.
 * @return
 *  True if it is a hash algorithm, False otherwise.
 */
bool tpm2_alg_util_is_hash_alg(TPM_ALG_ID id);

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
 * @param size
 *  Will receive the number of bytes stored in buffer.
 * @signature The actual signature struct to extract the plain signature from.
 * @return
 *  Returns a buffer filled with the extracted signature or NULL on error.
 *  Needs to be free()'d by the caller.
 */
UINT8* tpm2_extract_plain_signature(UINT16 *size, TPMT_SIGNATURE *signature);

#endif /* LIB_TPM2_ALG_UTIL_H_ */
