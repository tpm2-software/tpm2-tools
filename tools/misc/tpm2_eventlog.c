/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "efi_event.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_yaml.h"
#include "tpm2_tool.h"

static char *filename = NULL;

static bool on_positional(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected one file name as a positional parameter. Got: %d",
                argc);
        return false;
    }

    filename = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_positional,
                             TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    if (filename == NULL) {
        LOG_ERR("Missing required positional parameter, try -h / --help");
        return tool_rc_option_error;
    }

    unsigned long size = 0;
    bool ret = files_get_file_size_path(filename, &size);
    if (!ret) {
        return tool_rc_general_error;
    }

    if (size > UINT16_MAX) {
        LOG_WARN("event log exceeds %" PRIu16 " and will be truncated",
                 UINT16_MAX);
    }

    UINT16 size_tmp = UINT16_MAX;
    UINT8 *eventlog = calloc(1, size_tmp);
    if (eventlog == NULL){
        LOG_ERR("failed to allocate %lu bytes: %s", size, strerror(errno));
        return tool_rc_general_error;
    }

    tool_rc rc = tool_rc_success;
    ret = files_load_bytes_from_path(filename, eventlog, &size_tmp);
    if (!ret) {
        rc = tool_rc_general_error;
        goto out;
    }

    ret = yaml_eventlog(eventlog, size_tmp);
    if (!ret) {
        LOG_ERR("failed to parse tpm2 eventlog");
        rc = tool_rc_general_error;
    }

out:
    if (eventlog) {
        free(eventlog);
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("eventlog", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
