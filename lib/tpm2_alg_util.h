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

#endif /* LIB_TPM2_ALG_UTIL_H_ */
