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
#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <stdbool.h>

#include <tss2/tss2_sys.h>

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

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel);
TSS2_RC get_max_supported_pcrs(TSS2_SYS_CONTEXT *sapi_context, UINT32 *max_pcrs);
bool pcr_get_banks(TSS2_SYS_CONTEXT *sapi_context, TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs);
bool pcr_init_pcr_selection(TPMS_CAPABILITY_DATA *cap_data, TPML_PCR_SELECTION *pcr_sel, TPMI_ALG_HASH alg_id);
bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data, TPML_PCR_SELECTION *pcr_sel);
bool pcr_read_pcr_values(TSS2_SYS_CONTEXT *sapi_context, TPML_PCR_SELECTION *pcrSelections, tpm2_pcrs *pcrs);

#endif /* SRC_PCR_H_ */
