/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

typedef struct listpcr_context listpcr_context;
struct listpcr_context {
    char *output_file_path;
    FILE *output_file;
    tpm2_algorithm algs;
    tpm2_pcrs pcrs;
    TPML_PCR_SELECTION pcr_selections;
    TPMI_ALG_HASH selected_algorithm;
};

static listpcr_context ctx;

// show all PCR banks according to g_pcrSelection & g_pcrs->
static bool print_pcr_values(void) {

    UINT32 vi = 0, di = 0, i;

    for (i = 0; i < ctx.pcr_selections.count; i++) {
        const char *alg_name = tpm2_alg_util_algtostr(
                ctx.pcr_selections.pcrSelections[i].hash,
                tpm2_alg_util_flags_hash);

        tpm2_tool_output("%s:\n", alg_name);

        unsigned int pcr_id;
        for (pcr_id = 0;
                pcr_id < ctx.pcr_selections.pcrSelections[i].sizeofSelect * 8u;
                pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(
                    &ctx.pcr_selections.pcrSelections[i], pcr_id)) {
                continue;
            }
            if (vi >= ctx.pcrs.count || di >= ctx.pcrs.pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            tpm2_tool_output("  %-2d: 0x", pcr_id);

            int k;
            for (k = 0; k < ctx.pcrs.pcr_values[vi].digests[di].size; k++) {
                tpm2_tool_output("%02X",
                        ctx.pcrs.pcr_values[vi].digests[di].buffer[k]);
            }
            tpm2_tool_output("\n");

            if (ctx.output_file != NULL
                    && fwrite(ctx.pcrs.pcr_values[vi].digests[di].buffer,
                            ctx.pcrs.pcr_values[vi].digests[di].size,
                            required_argument, ctx.output_file) != 1) {
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

static tool_rc show_pcr_list_selected_values(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capdata,
        bool check) {

    if (check && !pcr_check_pcr_selection(capdata, &ctx.pcr_selections)) {
        return tool_rc_general_error;
    }

    tool_rc rc = pcr_read_pcr_values(esys_context, &ctx.pcr_selections,
            &ctx.pcrs);
    if (rc != tool_rc_success) {
        return rc;
    }

    return print_pcr_values() ? tool_rc_success : tool_rc_general_error;
}

static tool_rc show_pcr_alg_or_all_values(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capdata) {

    bool res = pcr_init_pcr_selection(capdata, &ctx.pcr_selections,
            ctx.selected_algorithm);
    if (!res) {
        return tool_rc_general_error;
    }

    return show_pcr_list_selected_values(esys_context, capdata, false);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.output_file_path = value;
        break;
        /* no default */
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected PCR list or algorithm selection");
        return false;
    }

    ctx.selected_algorithm = tpm2_alg_util_from_optarg(argv[0],
            tpm2_alg_util_flags_hash);
    if (ctx.selected_algorithm == TPM2_ALG_ERROR) {
        bool res = pcr_parse_selections(argv[0], &ctx.pcr_selections);
        if (!res) {
            LOG_ERR("Neither algorithm nor pcr list, got: \"%s\"", argv[0]);
            return false;
        }
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
         { "output",         required_argument, NULL, 'o' },
     };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *esys_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.output_file_path) {
        ctx.output_file = fopen(ctx.output_file_path, "wb+");
        if (!ctx.output_file) {
            LOG_ERR("Could not open output file \"%s\" error: \"%s\"",
                    ctx.output_file_path, strerror(errno));
            return tool_rc_general_error;
        }
    }

    TPMS_CAPABILITY_DATA capdata;
    tool_rc rc = pcr_get_banks(esys_context, &capdata, &ctx.algs);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.pcr_selections.count > 0) {
        return show_pcr_list_selected_values(esys_context, &capdata, true);
    }

    return show_pcr_alg_or_all_values(esys_context, &capdata);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *esys_context) {
    UNUSED(esys_context);

    if (ctx.output_file) {
        fclose(ctx.output_file);
    }

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrread", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
