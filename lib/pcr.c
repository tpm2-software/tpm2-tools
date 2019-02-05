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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>
#include <stdbool.h>

#include "pcr.h"
#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"

static inline void set_pcr_select_size(TPMS_PCR_SELECTION *pcr_selection,
        UINT8 size) {

    pcr_selection->sizeofSelect = size;
}

static int pcr_get_id(const char *arg, UINT32 *pcrId)
{
    UINT32 n = 0;

    if(arg == NULL || pcrId == NULL)
        return -1;

    if(!tpm2_util_string_to_uint32(arg, &n))
        return -2;

    if(n > 23)
        return -3;

    *pcrId = n;

    return 0;
}

static bool pcr_parse_selection(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel) {
    const char *strLeft;
    char buf[7];

    if (str == NULL || len == 0 || strlen(str) == 0)
        return false;

    strLeft = memchr(str, ':', len);

    if (strLeft == NULL) {
        return false;
    }

    if ((size_t)(strLeft - str) > sizeof(buf) - 1) {
        return false;
    }

    snprintf(buf, strLeft - str + 1, "%s", str);

    pcrSel->hash = tpm2_alg_util_from_optarg(buf, tpm2_alg_util_flags_hash);

    if (pcrSel->hash == TPM2_ALG_ERROR) {
        return false;
    }

    strLeft++;

    if ((size_t)(strLeft - str) >= len) {
        return false;
    }

    if (!pcr_parse_list(strLeft, str + len - strLeft, pcrSel)) {
        return false;
    }

    return true;
}

static void shrink_pcr_selection(TPML_PCR_SELECTION *s) {

    UINT32 i, j;

    //seek for the first empty item
    for (i = 0; i < s->count; i++)
        if (!s->pcrSelections[i].hash)
            break;
    j = i + 1;

    for (; i < s->count; i++) {
        if (!s->pcrSelections[i].hash) {
            for (; j < s->count; j++)
                if (s->pcrSelections[j].hash)
                    break;
            if (j >= s->count)
                break;

            memcpy(&s->pcrSelections[i], &s->pcrSelections[j], sizeof(s->pcrSelections[i]));
            s->pcrSelections[j].hash = 0;
            j++;
        }
    }

    s->count = i;
}

static void pcr_update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2) {
    UINT32 i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++) {
        for (i1 = 0; i1 < s1->count; i1++) {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                        ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

static bool pcr_unset_pcr_sections(TPML_PCR_SELECTION *s) {
    UINT32 i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return false;
            }
        }
    }

    return true;
}

bool pcr_print_pcr_struct(TPML_PCR_SELECTION *pcrSelect, tpm2_pcrs *pcrs) {

    UINT32 vi = 0, di = 0, i;
    bool result = true;

    tpm2_tool_output("pcrs:\n");

    // Loop through all PCR/hash banks 
    for (i = 0; i < pcrSelect->count; i++) {
        const char *alg_name = tpm2_alg_util_algtostr(
                pcrSelect->pcrSelections[i].hash, 
                tpm2_alg_util_flags_hash);

        tpm2_tool_output("  %s:\n", alg_name);

        // Loop through all PCRs in this bank
        UINT8 pcr_id;
        for (pcr_id = 0; pcr_id < pcrSelect->pcrSelections[i].sizeofSelect * 8; pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcrSelect->pcrSelections[i],
                    pcr_id)) {
                // skip non-selected banks
                continue;
            }
            if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            // Print out PCR ID
            tpm2_tool_output("    %-2d: 0x", pcr_id);

            // Print out current PCR digest value
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            int k;
            for (k = 0; k < b->size; k++) {
                tpm2_tool_output("%02X", b->buffer[k]);
            }
            tpm2_tool_output("\n");

            if (++di < pcrs->pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < pcrs->count) {
                continue;
            }
        }
    }

    return result;
}


bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels) {
    const char *strLeft = arg;
    const char *strCurrent = arg;
    int lenCurrent = 0;

    if (arg == NULL || pcrSels == NULL) {
        return false;
    }

    pcrSels->count = 0;

    do {
        strCurrent = strLeft;

        strLeft = strchr(strCurrent, '+');
        if (strLeft) {
            lenCurrent = strLeft - strCurrent;
            strLeft++;
        } else
            lenCurrent = strlen(strCurrent);

        if (!pcr_parse_selection(strCurrent, lenCurrent,
                &pcrSels->pcrSelections[pcrSels->count]))
            return false;

        pcrSels->count++;
    } while (strLeft);

    if (pcrSels->count == 0) {
        return false;
    }
    return true;
}

bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel) {
    char buf[4];
    const char *strCurrent;
    int lenCurrent;
    UINT32 pcr;

    if (str == NULL || len == 0 || strlen(str) == 0) {
        return false;
    }

    pcrSel->sizeofSelect = 3;
    pcrSel->pcrSelect[0] = 0;
    pcrSel->pcrSelect[1] = 0;
    pcrSel->pcrSelect[2] = 0;

    do {
        strCurrent = str;
        str = memchr(strCurrent, ',', len);
        if (str) {
            lenCurrent = str - strCurrent;
            str++;
            len -= lenCurrent + 1;
        } else {
            lenCurrent = len;
            len = 0;
        }

        if ((size_t)lenCurrent > sizeof(buf) - 1) {
            return false;
        }

        snprintf(buf, lenCurrent + 1, "%s", strCurrent);

        if (pcr_get_id(buf, &pcr) != 0) {
            return false;
        }

        pcrSel->pcrSelect[pcr / 8] |= (1 << (pcr % 8));
    } while (str);

    return true;
}

bool pcr_get_banks(ESYS_CONTEXT *esys_context, TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capdata_ret;
    UINT32 rval;

    rval = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, TPM2_CAP_PCRS, no_argument, required_argument,
            &more_data, &capdata_ret);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetCapability, rval);
        return false;
    }
    
    *capability_data = *capdata_ret;

    unsigned i;
    for (i = 0; i < capability_data->data.assignedPCR.count; i++) {
        algs->alg[i] =
                capability_data->data.assignedPCR.pcrSelections[i].hash;
    }
    algs->count = capability_data->data.assignedPCR.count;

    free(capdata_ret);
    return true;
}

bool pcr_init_pcr_selection(TPMS_CAPABILITY_DATA *cap_data, TPML_PCR_SELECTION *pcr_sel, TPMI_ALG_HASH alg_id) {

    UINT32 i, j;

    pcr_sel->count = 0;

    for (i = 0; i < cap_data->data.assignedPCR.count; i++) {
        if (alg_id && (cap_data->data.assignedPCR.pcrSelections[i].hash != alg_id))
            continue;
        pcr_sel->pcrSelections[pcr_sel->count].hash = cap_data->data.assignedPCR.pcrSelections[i].hash;
        set_pcr_select_size(&pcr_sel->pcrSelections[pcr_sel->count], cap_data->data.assignedPCR.pcrSelections[i].sizeofSelect);
        for (j = 0; j < pcr_sel->pcrSelections[pcr_sel->count].sizeofSelect; j++)
            pcr_sel->pcrSelections[pcr_sel->count].pcrSelect[j] = cap_data->data.assignedPCR.pcrSelections[i].pcrSelect[j];
        pcr_sel->count++;
    }

    if (pcr_sel->count == 0)
        return false;

    return true;
}

bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data, TPML_PCR_SELECTION *pcr_sel) {

    UINT32 i, j, k;

    for (i = 0; i < pcr_sel->count; i++) {
        for (j = 0; j < cap_data->data.assignedPCR.count; j++) {
            if (pcr_sel->pcrSelections[i].hash == cap_data->data.assignedPCR.pcrSelections[j].hash) {
                for (k = 0; k < pcr_sel->pcrSelections[i].sizeofSelect; k++)
                    pcr_sel->pcrSelections[i].pcrSelect[k] &= cap_data->data.assignedPCR.pcrSelections[j].pcrSelect[k];
                break;
            }
        }

        if (j >= cap_data->data.assignedPCR.count) {
            const char *alg_name = tpm2_alg_util_algtostr(pcr_sel->pcrSelections[i].hash, tpm2_alg_util_flags_hash);
            LOG_WARN("Ignore unsupported bank/algorithm: %s(0x%04x)", alg_name, pcr_sel->pcrSelections[i].hash);
            pcr_sel->pcrSelections[i].hash = 0; //mark it as to be removed
        }
    }

    shrink_pcr_selection(pcr_sel);
    if (pcr_sel->count == 0)
        return false;

    return true;
}

bool pcr_read_pcr_values(ESYS_CONTEXT *esys_context, TPML_PCR_SELECTION *pcrSelections, tpm2_pcrs *pcrs) {

    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION *pcr_selection_out;
    UINT32 pcr_update_counter;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, pcrSelections, sizeof(pcr_selection_tmp));

    //2. call pcr_read
    pcrs->count = 0;
    do {
        TPML_DIGEST *v;
        UINT32 rval = Esys_PCR_Read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pcr_selection_tmp,
                &pcr_update_counter, &pcr_selection_out, &v);

        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PCR_Read, rval);
            return false;
        }

        pcrs->pcr_values[pcrs->count] = *v;

        free(v);

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        pcr_update_pcr_selections(&pcr_selection_tmp, pcr_selection_out);

        free(pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++pcrs->count < 24 && !pcr_unset_pcr_sections(&pcr_selection_tmp));

    if (pcrs->count >= 24 && !pcr_unset_pcr_sections(&pcr_selection_tmp)) {
        LOG_ERR("too much pcrs to get! try to split into multiple calls...");
        return false;
    }

    return true;
}
