//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// Copyright (c) 2018, Fraunhofer SIT
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

#include <tss2/tss2_esys.h>

#include "tpm2_options.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm {
    int count;
    TPMI_ALG_HASH alg[8]; //XXX Why 8?
};

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    size_t count;
    TPML_DIGEST pcr_values[24]; //XXX Why 24?
};

typedef struct listpcr_context listpcr_context;
struct listpcr_context {
    struct {
        UINT8 L : 1;
        UINT8 s : 1;
        UINT8 g : 1;
        UINT8 o : 1;
        UINT8 unused : 4;
    } flags;
    char *output_file_path;
    FILE *output_file;
    tpm2_algorithm algs;
    tpm2_pcrs pcrs;
    TPML_PCR_SELECTION pcr_selections;
    TPMS_CAPABILITY_DATA cap_data;
    TPMI_ALG_HASH selected_algorithm;
};

static listpcr_context ctx = {
    .algs = {
        .count = 3,
        .alg = {
            TPM2_ALG_SHA1,
            TPM2_ALG_SHA256,
            TPM2_ALG_SHA384
        }
    },
};

static inline void set_pcr_select_size(TPMS_PCR_SELECTION *pcr_selection,
        UINT8 size) {

    pcr_selection->sizeofSelect = size;
}

static bool is_pcr_select_bit_set(TPMS_PCR_SELECTION *pcr_selection, UINT32 pcr) {

    return (pcr_selection->pcrSelect[((pcr) / 8)] & (1 << ((pcr) % 8)));
}

static void update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2) {

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

static bool unset_pcr_sections(TPML_PCR_SELECTION *s) {

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

static bool read_pcr_values(ESYS_CONTEXT *esys_context) {

    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION *pcr_selection_out;
    UINT32 pcr_update_counter;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, &ctx.pcr_selections, sizeof(pcr_selection_tmp));

    //2. call pcr_read
    ctx.pcrs.count = 0;
    do {
        TPML_DIGEST *v;
        UINT32 rval = Esys_PCR_Read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pcr_selection_tmp,
                &pcr_update_counter, &pcr_selection_out, &v);

        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PCR_Read, rval);
            return false;
        }

        ctx.pcrs.pcr_values[ctx.pcrs.count] = *v;

        free(v);

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        update_pcr_selections(&pcr_selection_tmp, pcr_selection_out);

        free(pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++ctx.pcrs.count < 24 && !unset_pcr_sections(&pcr_selection_tmp));

    if (ctx.pcrs.count >= 24 && !unset_pcr_sections(&pcr_selection_tmp)) {
        LOG_ERR("too much pcrs to get! try to split into multiple calls...");
        return false;
    }

    return true;
}

static bool init_pcr_selection(void) {

    TPMS_CAPABILITY_DATA *cap_data = &ctx.cap_data;
    TPML_PCR_SELECTION *pcr_sel = &ctx.pcr_selections;
    UINT32 i, j;

    TPMI_ALG_HASH alg_id = ctx.selected_algorithm;

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

static bool check_pcr_selection(void) {

    TPMS_CAPABILITY_DATA *cap_data = &ctx.cap_data;
    TPML_PCR_SELECTION *pcr_sel = &ctx.pcr_selections;
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

// show all PCR banks according to g_pcrSelection & g_pcrs->
static bool show_pcr_values(void) {

    UINT32 vi = 0, di = 0, i;

    for (i = 0; i < ctx.pcr_selections.count; i++) {
        const char *alg_name = tpm2_alg_util_algtostr(
                ctx.pcr_selections.pcrSelections[i].hash,
                tpm2_alg_util_flags_hash);

        tpm2_tool_output("%s:\n", alg_name);

        UINT8 pcr_id;
        for (pcr_id = 0; pcr_id < ctx.pcr_selections.pcrSelections[i].sizeofSelect * 8; pcr_id++) {
            if (!is_pcr_select_bit_set(&ctx.pcr_selections.pcrSelections[i],
                    pcr_id)) {
                continue;
            }
            if (vi >= ctx.pcrs.count || di >= ctx.pcrs.pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            tpm2_tool_output("  %-2d: 0x", pcr_id);

            int k;
            for (k = 0; k < ctx.pcrs.pcr_values[vi].digests[di].size; k++) {
                tpm2_tool_output("%02X", ctx.pcrs.pcr_values[vi].digests[di].buffer[k]);
            }
            tpm2_tool_output("\n");

            if (ctx.output_file != NULL
                    && fwrite(ctx.pcrs.pcr_values[vi].digests[di].buffer,
                            ctx.pcrs.pcr_values[vi].digests[di].size, required_argument,
                            ctx.output_file) != 1) {
                LOG_ERR("write to output file failed: %s", strerror(errno));
                return false;
            }

            if (++di < ctx.pcrs.pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < ctx.pcrs.count) {
                continue;
            }
        }
    }

    return true;
}

static bool show_selected_pcr_values(ESYS_CONTEXT *esys_context, bool check) {

    if (check && !check_pcr_selection())
        return false;

    if (!read_pcr_values(esys_context))
        return false;

    if (!show_pcr_values())
        return false;

    return true;
}

static bool show_all_pcr_values(ESYS_CONTEXT *esys_context) {

    if (!init_pcr_selection())
        return false;

    return show_selected_pcr_values(esys_context, false);
}

static bool show_alg_pcr_values(ESYS_CONTEXT *esys_context) {

    if (!init_pcr_selection())
        return false;

    return show_selected_pcr_values(esys_context, false);
}

static bool get_banks(ESYS_CONTEXT *esys_context) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    UINT32 rval;

    rval = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, TPM2_CAP_PCRS, no_argument, required_argument,
            &more_data, &capability_data);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetCapability, rval);
        return false;
    }

    ctx.cap_data = *capability_data;

    unsigned i;
    for (i = 0; i < capability_data->data.assignedPCR.count; i++) {
        ctx.algs.alg[i] =
                capability_data->data.assignedPCR.pcrSelections[i].hash;
    }
    ctx.algs.count = capability_data->data.assignedPCR.count;

    free(capability_data);
    return true;
}

static void show_banks(tpm2_algorithm *g_banks) {

    tpm2_tool_output("Supported Bank/Algorithm:");
    int i;
    for (i = 0; i < g_banks->count; i++) {
        const char *alg_name = tpm2_alg_util_algtostr(g_banks->alg[i], tpm2_alg_util_flags_hash);
        tpm2_tool_output(" %s(0x%04x)", alg_name, g_banks->alg[i]);
    }
    tpm2_tool_output("\n");
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'g':
        ctx.selected_algorithm = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.selected_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid algorithm, got: \"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'o':
        ctx.output_file_path = value;
        ctx.flags.o = 1;
        break;
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selections)) {
            LOG_ERR("Could not parse pcr list, got: \"%s\"", value);
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 's':
        ctx.flags.s = 1;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
         { "halg",      required_argument, NULL, 'g' },
         { "out-file",  required_argument, NULL, 'o' },
         { "algs",      no_argument,       NULL, 's' },
         { "sel-list",  required_argument, NULL, 'L' },
         { "format",    required_argument, NULL, 'f' },
     };

    *opts = tpm2_options_new("g:o:L:s", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *esys_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool success = false;

    int flagCnt = ctx.flags.g + ctx.flags.L + ctx.flags.s;
    if (flagCnt > 1) {
        LOG_ERR("Expected only one of -g, -L or -s options, found: \"%s%s%s\"",
                ctx.flags.g ? "-g" : "",
                ctx.flags.L ? "-L" : "",
                ctx.flags.s ? "-s" : ""
        );
        return -1;
    }

    if (ctx.flags.o) {
        ctx.output_file = fopen(ctx.output_file_path, "wb+");
        if (!ctx.output_file) {
            LOG_ERR("Could not open output file \"%s\" error: \"%s\"",
                    ctx.output_file_path, strerror(errno));
            goto error;
        }
    }

    success = get_banks(esys_context);
    if (!success) {
        goto error;
    }

    if (ctx.flags.s) {
        show_banks(&ctx.algs);
    } else if (ctx.flags.g) {
        success = show_alg_pcr_values(esys_context);
    } else if (ctx.flags.L) {
        success = show_selected_pcr_values(esys_context, true);
    } else {
        success = show_all_pcr_values(esys_context);
    }

error:
    if (ctx.output_file) {
        fclose(ctx.output_file);
    }

    /* 0 on success 1 otherwise */
    return !success;
}
