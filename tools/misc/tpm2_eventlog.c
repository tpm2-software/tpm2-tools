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

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_positional,
                             TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    bool ret = false;
    UINT8 *eventlog;
    unsigned long size = 0;

    if (filename == NULL) {
        LOG_ERR("Missing required positional parameter, try -h / --help");
        return tool_rc_option_error;
    }
    ret = files_get_file_size_path(filename, &size);
    if (!ret) {
        return tool_rc_general_error;
    }

    eventlog = calloc(1, size);
    if (eventlog == NULL){
        LOG_ERR("failed to allocate %lu bytes: %s", size, strerror(errno));
        return tool_rc_general_error;
    }

    if (size > UINT16_MAX) {
        LOG_WARN("event log exceeds %" PRIu16 " and will be truncated",
                 UINT16_MAX);
    }
    UINT16 size_tmp = size;
    ret = files_load_bytes_from_path(filename, eventlog, &size_tmp);
    if (!ret) {
        return tool_rc_general_error;
    }

    ret = yaml_eventlog(eventlog, size_tmp);
    if (eventlog)
        free(eventlog);
    if (ret) {
        return tool_rc_success;
    } else {
        LOG_ERR("failed to parse tpm2 eventlog");
        return tool_rc_general_error;
    }
}
