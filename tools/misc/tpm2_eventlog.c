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

/* Set the default YAML version */
static uint32_t eventlog_version = 1;

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

    uint32_t version;

    switch (key) {
    case 0:
        if (!tpm2_util_string_to_uint32(value, &version)) {
            LOG_ERR("Cannot parse eventlog version: %s\n", value);
            return false;
        }
        if (version < MIN_EVLOG_YAML_VERSION || version > MAX_EVLOG_YAML_VERSION) {
            LOG_ERR("Unexpected YAML version number: %u\n", version);
            return false;
        }
        eventlog_version = version;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
         { "eventlog-version",         required_argument, NULL, 0 },
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

    /* Get file size */
    unsigned long size = 0;
    bool ret = files_get_file_size_path(filename, &size);
    if (!ret || !size) {
        return tool_rc_general_error;
    }

    /* Allocate buffer to read file data */
    UINT8 *eventlog = calloc(1, size);
    if (eventlog == NULL){
        LOG_ERR("failed to allocate %lu bytes: %s", size, strerror(errno));
        return tool_rc_general_error;
    }

    /* Load buffer with file data */
    tool_rc rc = tool_rc_success;
    FILE *fileptr = fopen(filename, "rb");
    if (!fileptr) {
        rc = tool_rc_general_error;
        goto out;
    }

    ret = files_read_bytes(fileptr, eventlog, size);
    fclose(fileptr);
    if (!ret) {
        rc = tool_rc_general_error;
        goto out;
    }

    /* Parse eventlog data */
    ret = yaml_eventlog(eventlog, size, eventlog_version);
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
