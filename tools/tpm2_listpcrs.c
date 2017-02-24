//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "log.h"
#include "main.h"
#include "options.h"
#include "string-bytes.h"

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm {
    int count;
    TPMI_ALG_HASH alg[8]; //XXX Why 8?
};

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    int count;
    TPML_DIGEST pcr_values[24]; //XXX Why 24?
};

typedef struct listpcr_context listpcr_context;
struct listpcr_context {
    TSS2_SYS_CONTEXT *sapi_context;
    FILE *output_file;
    tpm2_algorithm algs;
    tpm2_pcrs pcrs;
    TPML_PCR_SELECTION pcr_selections;
};

static inline void set_pcr_select_bit(TPMS_PCR_SELECTION *pcr_selection,
        UINT32 pcr) {

    pcr_selection->pcrSelect[((pcr) / 8)] |= (1 << ((pcr) % 8));
}

static inline void clear_pcr_select_bits(TPMS_PCR_SELECTION *pcr_selection) {

    /* XXX Why only the first 3? */
    pcr_selection->pcrSelect[0] = 0;
    pcr_selection->pcrSelect[1] = 0;
    pcr_selection->pcrSelect[2] = 0;
}

static inline void set_pcr_select_size(TPMS_PCR_SELECTION *pcr_selection,
        UINT8 size) {

    pcr_selection->sizeofSelect = size;
}

static bool is_pcr_select_bit_set(TPMS_PCR_SELECTION *pcr_selection, UINT32 pcr) {

    return (pcr_selection->pcrSelect[((pcr) / 8)] & (1 << ((pcr) % 8)));
}

static const char *get_algorithm_name(TPMI_ALG_HASH alg_id) {

    static const struct {
        TPMI_ALG_HASH alg;
        const char *desc;
    } g_algs[] = { { TPM_ALG_SHA1, "TPM_ALG_SHA1" }, { TPM_ALG_SHA256,
            "TPM_ALG_SHA256" }, { TPM_ALG_SHA384, "TPM_ALG_SHA384" }, {
            TPM_ALG_SHA512, "TPM_ALG_SHA512" }, { TPM_ALG_SM3_256,
            "TPM_ALG_SM3_256" }, { TPM_ALG_NULL, "TPM_ALG_UNKOWN" } };

    unsigned i;
    for (i = 0; g_algs[i].alg != TPM_ALG_NULL ; i++) {
        if (g_algs[i].alg == alg_id) {
            break;
        }
    }
    return g_algs[i].desc;
}

static void update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2) {

    int i1, i2, j;
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

static bool unset_pcr_sections(TPML_PCR_SELECTION *s) {

    int i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                LOG_ERR("bit %u in pcrSelection array index %d found!", j, i);
                return false;
            }
        }
    }

    return true;
}

static bool read_pcr_values(listpcr_context *context) {

    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION pcr_selection_out;
    UINT32 pcr_update_counter;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, &context->pcr_selections, sizeof(pcr_selection_tmp));

    //2. call pcr_read
    context->pcrs.count = 0;
    do {
        UINT32 rval = Tss2_Sys_PCR_Read(context->sapi_context, 0, &pcr_selection_tmp,
                &pcr_update_counter, &pcr_selection_out,
                &context->pcrs.pcr_values[context->pcrs.count], 0);

        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("read pcr failed. tpm error 0x%0x", rval);
            return -1;
        }

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        update_pcr_selections(&pcr_selection_tmp, &pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++context->pcrs.count < 24 && !unset_pcr_sections(&pcr_selection_tmp));

    if (context->pcrs.count >= 24 && !unset_pcr_sections(&pcr_selection_tmp)) {
        LOG_ERR("too much pcrs to get! try to split into multiple calls...");
        return false;
    }

    return true;
}

static void init_pcr_selection_from_algorithm(TPMI_ALG_HASH alg_id,
        TPML_PCR_SELECTION *pcr_selections) {

    pcr_selections->count = 1;
    pcr_selections->pcrSelections[0].hash = alg_id;
    set_pcr_select_size(&pcr_selections->pcrSelections[0], 3);
    clear_pcr_select_bits(&pcr_selections->pcrSelections[0]);

    UINT32 pcr_id;
    for (pcr_id = 0; pcr_id < 24; pcr_id++) {
        set_pcr_select_bit(&pcr_selections->pcrSelections[0], pcr_id);
    }
}

/* XXX Could this internally call init_pcr_selection_from_algorithm to reduce duplicate code? */
static void init_pcr_selection_all(tpm2_algorithm *algorithm,
        TPML_PCR_SELECTION *pcr_selections) {

    pcr_selections->count = 0;

    int i;
    for (i = 0; i < algorithm->count; i++) {
        pcr_selections->pcrSelections[i].hash = algorithm->alg[i];
        set_pcr_select_size(&pcr_selections->pcrSelections[i], 3);
        clear_pcr_select_bits(&pcr_selections->pcrSelections[i]);

        UINT32 pcr_id;
        for (pcr_id = 0; pcr_id < 24; pcr_id++) {
            set_pcr_select_bit(&pcr_selections->pcrSelections[i], pcr_id);
        }
        pcr_selections->count++;
    }
}

// show all PCR banks according to g_pcrSelection & g_pcrs->
static bool show_pcr_values(listpcr_context *context) {

    int vi = 0, di = 0, i;

    for (i = 0; i < context->pcr_selections.count; i++) {
        const char *alg_name = get_algorithm_name(
                context->pcr_selections.pcrSelections[i].hash);

        printf("\nBank/Algorithm: %s(0x%04x)\n", alg_name,
                context->pcr_selections.pcrSelections[i].hash);

        UINT32 pcr_id;
        for (pcr_id = 0; pcr_id < 24; pcr_id++) {
            if (!is_pcr_select_bit_set(&context->pcr_selections.pcrSelections[i],
                    pcr_id)) {
                continue;
            }
            if (vi >= context->pcrs.count || di >= context->pcrs.pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more\n");
                return false;
            }

            printf("PCR_%02d:", pcr_id);
            int k;
            for (k = 0; k < context->pcrs.pcr_values[vi].digests[di].t.size; k++)
                printf(" %02x", context->pcrs.pcr_values[vi].digests[di].t.buffer[k]);
            printf("\n");

            if (context->output_file != NULL
                    && fwrite(context->pcrs.pcr_values[vi].digests[di].t.buffer,
                            context->pcrs.pcr_values[vi].digests[di].t.size, 1,
                            context->output_file) != 1) {
                LOG_ERR("write to output file failed: %s", strerror(errno));
                return false;
            }

            if (++di < context->pcrs.pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < context->pcrs.count) {
                continue;
            }
        }
    }

    return true;
}

static bool show_selected_pcr_values(listpcr_context *context) {

    if (!read_pcr_values(context))
        return false;

    if (!show_pcr_values(context))
        return false;

    return true;
}

static bool show_all_pcr_values(listpcr_context *context) {

    init_pcr_selection_all(&context->algs, &context->pcr_selections);

    return show_selected_pcr_values(context);
}

static bool show_alg_pcr_values(listpcr_context *context, TPMI_ALG_HASH alg_id) {

    init_pcr_selection_from_algorithm(alg_id, &context->pcr_selections);

    return show_selected_pcr_values(context);
}

static bool get_banks(listpcr_context *context) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA capability_data;
    UINT32 rval;

    rval = Tss2_Sys_GetCapability(context->sapi_context, 0, TPM_CAP_PCRS, 0, 1,
            &more_data, &capability_data, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR(
                "GetCapability: Get PCR allocation status Error. TPM Error:0x%x......\n",
                rval);
        return false;
    }

    unsigned i;
    for (i = 0; i < capability_data.data.assignedPCR.count; i++) {
        context->algs.alg[i] =
                capability_data.data.assignedPCR.pcrSelections[i].hash;
    }
    context->algs.count = capability_data.data.assignedPCR.count;

    return true;
}

static void show_banks(tpm2_algorithm *g_banks) {

    printf("Supported Bank/Algorithm:");
    int i;
    for (i = 0; i < g_banks->count; i++) {
        const char *alg_name = get_algorithm_name(g_banks->alg[i]);
        printf(" %s(0x%04x)", alg_name, g_banks->alg[i]);
    }
    printf("\n");
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    listpcr_context context = {
        .algs = {
            .count = 3,
            .alg = {
                TPM_ALG_SHA1,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384 }
        },
        .output_file = NULL,
        .pcr_selections = { 0 },
        .pcrs = { 0 },
        .sapi_context = sapi_context
    };

    bool success = false;
    TPMI_ALG_HASH selected_algorithm;
    unsigned o_flag = 0, L_flag = 0, s_flag = 0, g_flag = 0;

    static struct option long_options[] = {
        { "algorithm", 1, NULL, 'g' },
        { "output", 1, NULL, 'o' },
        { "algs", 0, NULL, 's' },
        { "selList", 1, NULL, 'L' },
        { NULL, 0, NULL, '\0' }
    };

    /* mark these as unused to prevent compiler warnings/errors */
    (void) opts;

    while (getopt_long(argc, argv, "g:o:L:s", long_options, NULL) != -1) {
        switch (optopt) {
        case 'g':
            if (getSizeUint16Hex(optarg, &selected_algorithm) != 0) {
                showArgError(optarg, argv[0]);
                goto error;
            }
            g_flag = 1;
            break;
        case 'o':
            context.output_file = fopen(optarg, "wb+");
            if (!context.output_file) {
                LOG_ERR("Could not open output file \"%s\" error: \"%s\"",
                        optarg, strerror(errno));
                goto error;
            }
            /* XXX Should o option only print to output file and nothing to stdout? */
            o_flag = 1;
            break;
        case 'L':
            if (pcr_parse_selections(optarg, &context.pcr_selections) != 0) {
                showArgError(optarg, argv[0]);
                goto error;
            }
            L_flag = 1;
            break;
        case 's':
            s_flag = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            goto error;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            goto error;
        }
    }

    int flagCnt = g_flag + L_flag + s_flag;
    if (flagCnt > 1) {
        showArgMismatch(argv[0]);
        goto error;
    }

    success = get_banks(&context);
    if (!success) {
        goto error;
    }

    if (s_flag) {
        show_banks(&context.algs);
    } else if (g_flag) {
        success = show_alg_pcr_values(&context, selected_algorithm);
    } else if (L_flag) {
        success = show_selected_pcr_values(&context);
    } else {
        success = show_all_pcr_values(&context);
    }

error:
    if (context.output_file) {
        fclose(context.output_file);
    }

    /* 0 on success 1 otherwise */
    return !success;
}
