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

const int allowed_yaml_versions[] = {1, 2};
/* Set the default YAML version */
static int yaml_version = 1;

static bool on_positional(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected one file name as a positional parameter. Got: %d",
                argc);
        return false;
    }

    filename = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    int version;

    switch (key) {
    case 'y':
        version = atoi(value);
        for (unsigned int i = 0; i < sizeof(allowed_yaml_versions)/sizeof(int); i++) {
            if (version == allowed_yaml_versions[i]) {
                yaml_version = version;
                return true;
            }
        }
        LOG_ERR("Unexpected YAML version number: %d\n", version);
        return false;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
         { "yaml-version",         required_argument, NULL, 'y' },
    };

    *opts = tpm2_options_new("y:", ARRAY_LEN(topts), topts, on_option,
                             on_positional, TPM2_OPTIONS_NO_SAPI);

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

    ret = yaml_eventlog(eventlog, size_tmp, yaml_version);
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
