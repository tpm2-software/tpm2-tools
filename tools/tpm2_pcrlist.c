/* SPDX-License-Identifier: BSD-3-Clause */

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
            if (!tpm2_util_is_pcr_select_bit_set(&ctx.pcr_selections.pcrSelections[i],
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

    if (check && !pcr_check_pcr_selection(&ctx.cap_data, &ctx.pcr_selections))
        return false;

    if (!pcr_read_pcr_values(esys_context, &ctx.pcr_selections, &ctx.pcrs))
        return false;

    if (!show_pcr_values())
        return false;

    return true;
}

static bool show_all_pcr_values(ESYS_CONTEXT *esys_context) {

    if (!pcr_init_pcr_selection(&ctx.cap_data, &ctx.pcr_selections, ctx.selected_algorithm))
        return false;

    return show_selected_pcr_values(esys_context, false);
}

static bool show_alg_pcr_values(ESYS_CONTEXT *esys_context) {

    if (!pcr_init_pcr_selection(&ctx.cap_data, &ctx.pcr_selections, ctx.selected_algorithm))
        return false;

    return show_selected_pcr_values(esys_context, false);
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
     };

    *opts = tpm2_options_new("g:o:L:s", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *esys_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool success = false;

    int flagCnt = ctx.flags.g + ctx.flags.L + ctx.flags.s;
    if (flagCnt > 1) {
        LOG_ERR("Expected only one of -g, -L or -s options, found: \"%s%s%s\"",
                ctx.flags.g ? "-g" : "",
                ctx.flags.L ? "-L" : "",
                ctx.flags.s ? "-s" : ""
        );
        return tool_rc_option_error;
    }

    if (ctx.flags.o) {
        ctx.output_file = fopen(ctx.output_file_path, "wb+");
        if (!ctx.output_file) {
            LOG_ERR("Could not open output file \"%s\" error: \"%s\"",
                    ctx.output_file_path, strerror(errno));
            goto error;
        }
    }

    success = pcr_get_banks(esys_context, &ctx.cap_data, &ctx.algs);
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

    return success ? tool_rc_success : tool_rc_general_error;
}
