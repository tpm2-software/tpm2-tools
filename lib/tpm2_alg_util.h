#ifndef LIB_TPM2_ALG_UTIL_H_
#define LIB_TPM2_ALG_UTIL_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

/*
 * The TSS has a bug where it was missing algs 0x27 trough 0x29.
 * see: https://github.com/01org/TPM2.0-TSS/issues/476
 * per https://trustedcomputinggroup.org/wp-content/uploads/TCG_Algorithm_Registry_Rev_1.24.pdf
 * FIXME: https://github.com/01org/tpm2.0-tools/issues/375
 */
#ifndef ALG_SHA3_256_VALUE
#define ALG_SHA3_256_VALUE 0x27
#endif
#ifndef ALG_SHA3_384_VALUE
#define ALG_SHA3_384_VALUE 0x28
#endif
#ifndef ALG_SHA3_512_VALUE
#define ALG_SHA3_512_VALUE 0x29
#endif

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

#endif /* LIB_TPM2_ALG_UTIL_H_ */
