/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "tool_rc.h"

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm {
    int count;
    TPMI_ALG_HASH alg[TPM2_NUM_PCR_BANKS];
};

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    size_t count;
    TPML_DIGEST pcr_values[TPM2_MAX_PCRS];
};

typedef struct tpm2_forward {
    TPMS_PCR_SELECTION pcr_selection;
    TPMU_HA pcrs[TPM2_MAX_PCRS];
} tpm2_forward;

typedef struct tpm2_forwards {
    size_t count;
    struct tpm2_forward bank[TPM2_NUM_PCR_BANKS];
} tpm2_forwards;

/**
 * Echo out all PCR banks according to g_pcrSelection & g_pcrs->.
 * @param pcrSelect
 *  Description of which PCR registers are selected.
 * @param pcrs
 *  Struct containing PCR digests.
 * @return
 *  True on success, false otherwise.
 */
bool pcr_print_pcr_struct(TPML_PCR_SELECTION *pcrSelect, tpm2_pcrs *pcrs);

/**
 * Echo out all PCR banks according to g_pcrSelection & g_pcrs->.
 * Assume that data structures are all little endian.
 * @param pcrSelect
 *  Description of which PCR registers are selected.
 * @param pcrs
 *  Struct containing PCR digests.
 * @return
 *  True on success, false otherwise.
 */
bool pcr_print_pcr_struct_le(TPML_PCR_SELECTION *pcrSelect, tpm2_pcrs *pcrs);

/**
 * Set the PCR value into pcrId if string in arg is a valid PCR index.
 * @param arg
 *  PCR index as string
 * @param pcrId
 *  Caller-allocated PCR index as integer
 * @return
 *  True on success, false otherwise.
 */
bool pcr_get_id(const char *arg, UINT32 *pcr_id);

bool pcr_print_pcr_selections(TPML_PCR_SELECTION *pcr_selections);

/**
 * Prints the selected PCR values.
 *
 * @param pcr_select the selected pcrs to be printed
 * @param pcrs the pcrs digests
 * @return true on success; false otherwise
 */
bool pcr_print_values(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *pcrs);

/**
 * Writes the selected PCR values to a file.
 *
 * @param pcr_select the selected pcrs to be written
 * @param pcrs the pcrs digests
 * @param output_file file to output the pcr values
 * @return true on success; false otherwise
 */
bool pcr_fwrite_values(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *pcrs, FILE *output_file);
/**
 * Writes the selected PCR values to a file in serialized format.
 *
 * @param pcr_select the selected pcrs to be written
 * @param pcrs the pcrs digests
 * @param output_file file to output the pcr values in serialized format
 * @return true on success; false otherwise
 */
bool pcr_fwrite_serialized(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *pcrs, FILE *output_file);

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_selections,
                          tpm2_forwards *forwards);

tool_rc pcr_get_banks(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs);

bool pcr_init_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_selections, TPMI_ALG_HASH alg_id);

bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_selections);

tool_rc pcr_read_pcr_values(ESYS_CONTEXT *esys_context,
        TPML_PCR_SELECTION *pcr_selections, tpm2_pcrs *pcrs,
        TPM2B_DIGEST *cp_hash, TPMI_ALG_HASH parameter_hash_algorithm);

#endif /* SRC_PCR_H_ */
