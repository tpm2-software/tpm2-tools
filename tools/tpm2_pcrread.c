/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"

typedef struct listpcr_context listpcr_context;
struct listpcr_context {
    char *output_file_path;
    FILE *output_file;
    tpm2_convert_pcrs_output_fmt format;
    tpm2_algorithm algs;
    tpm2_pcrs pcrs;
    TPML_PCR_SELECTION pcr_selections;
    TPMI_ALG_HASH selected_algorithm;
};

static listpcr_context ctx = {
    .format = pcrs_output_format_values
};

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

    bool success = pcr_print_values(&ctx.pcr_selections, &ctx.pcrs);
    if (success && ctx.output_file) {
        if (ctx.format == pcrs_output_format_values) {
            success = pcr_fwrite_values(&ctx.pcr_selections, &ctx.pcrs,
                                        ctx.output_file);
        } else if (ctx.format == pcrs_output_format_serialized) {
            success = pcr_fwrite_serialized(&ctx.pcr_selections, &ctx.pcrs,
                                            ctx.output_file);
        }
    }

    return success ? tool_rc_success : tool_rc_general_error;
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
    case 'F':
        ctx.format = tpm2_convert_pcrs_output_fmt_from_optarg(value);
        if (ctx.format == pcrs_output_format_err) {
            return false;
        }
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
         { "pcrs_format",    required_argument, NULL, 'F' },
     };

    *opts = tpm2_options_new("o:F:", ARRAY_LEN(topts), topts, on_option, on_arg,
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
