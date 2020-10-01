/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_PCR_H_
#define SRC_PCR_H_

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

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_selections);

tool_rc pcr_get_banks(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs);

bool pcr_init_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_selections, TPMI_ALG_HASH alg_id);

bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_selections);

tool_rc pcr_read_pcr_values(ESYS_CONTEXT *esys_context,
        TPML_PCR_SELECTION *pcr_selections, tpm2_pcrs *pcrs);

#endif /* SRC_PCR_H_ */
