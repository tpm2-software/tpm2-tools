//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sapi/tpm20.h>

#include "options.h"
#include "log.h"
#include "rc-decode.h"

#define TPM_RC_MAX 0xffffffff

TPM_RC
str_to_tpm_rc (const char *rc_str)
{
    uintmax_t rc_read = 0;
    char *end_ptr = NULL;

    rc_read = strtoumax (rc_str, &end_ptr, 0);
    if (rc_read > TPM_RC_MAX) {
        LOG_ERR("invalid TPM_RC");
        exit (1);
    }
    /* apply the TPM_RC_MAX mask to the possibly larger uintmax_t */
    return rc_read & TPM_RC_MAX;
}

int
process_cmdline (int   argc,
                 char *argv[],
                 char *envp[])
{
    int opt = -1;
    const char *optstring = "hv";
    static struct option long_options[] = {
        { "help", 0 , NULL, 'h' },
        { "version", 0, NULL, 'v' },
        { .name = NULL }
    };

    optind = 0;
    while ((opt = getopt_long (argc, argv, optstring, long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'h':
                execute_man (argv[0], envp);
                exit (0);
            case 'v':
                showVersion (argv[0]);
                exit (0);
            case '?':
                exit (1);
        }
    }
    return optind;
}

/* Dump the hex, identifier and description for the format zero / VER1 error
 * provided in TPM_RC parameter.
 */
int
print_tpm_rc_format_zero (TPM_RC rc)
{
    TPM_RC rc_tmp;
    tpm2_rc_entry_t *entry;

    rc_tmp = tpm2_rc_get_code_7bit (rc);
    if (tpm2_rc_is_vendor_defined (rc)) {
        LOG_ERR("vendor defined TPM_RCs are not supported");
        return -1;
    } else if (tpm2_rc_is_warning_code (rc)) {
        entry = tpm2_get_warn_entry (rc_tmp);
        if (entry)
            printf ("format 0 warning code\n  hex: 0x%02x\n  name: %s\n  "
                    "description: %s\n",
                    rc_tmp, entry->name, entry->description);
        else
            printf ("failed to decode TPM_RC warning: 0x%x\n", rc_tmp);
    } else if (tpm2_rc_is_error_code (rc)) {
        entry = tpm2_get_fmt0_entry (rc_tmp);
        if (entry)
            printf ("format 0 error code\n  hex: 0x%02x\n  name: %s\n  "
                    "description: %s\n",
                    rc_tmp, entry->name, entry->description);
        else
            printf ("failed to decode TPM_RC error: 0x%02x\n", rc_tmp);
    } else if (tpm2_rc_is_tpm12 (rc_tmp)) {
        LOG_ERR("version 1.2 TPM_RCs are not supported");
        return -1;
    } else {
        LOG_ERR("Unknown TPM_RC format");
        return -1;
    }
    /* decode warning / error code */
    return 0;
}
/* Dump the hex, identifier and description for the format one / FMT1 error
 * as well as the parameter, handle or session data.
 */
int
print_tpm_rc_format_one (TPM_RC rc)
{
    TPM_RC rc_tmp;
    tpm2_rc_entry_t *entry;

    printf ("format 1 error code\n");
    rc_tmp = tpm2_rc_get_code_6bit (rc);
    printf ("  hex: 0x%02x\n", rc_tmp);
    /* decode error message */
    entry = tpm2_get_fmt1_entry (rc_tmp);
    if (!entry) {
        printf ("Unknown TPM_RC\n");
        return -1;
    }
    printf ("  identifier: %s\n  description: %s\n",
            entry->name, entry->description);
    /* decode parameter / handle / session number */
    if (tpm2_rc_is_error_code_with_parameter (rc)) {
        rc_tmp = tpm2_rc_get_parameter_number (rc);
        entry = tpm2_get_parameter_entry (rc_tmp);
        if (!entry) {
            printf ("Unknown TPM_RC parameter number: 0x%03x\n", rc_tmp);
            return -1;
        }
        printf ("parameter\n  hex: 0x%03x\n  identifier:  %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    } else if (tpm2_rc_is_error_code_with_handle (rc)) {
        rc_tmp = tpm2_rc_get_handle_number (rc);
        entry = tpm2_get_handle_entry (rc_tmp);
        if (!entry) {
            printf ("Unkonwn TPM_RC handle number: 0x%03x\n", rc_tmp);
            return -1;
        }
        printf ("handle\n  hex:0x%03x\n  identifier:  %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    } else if (tpm2_rc_is_error_code_with_session (rc)) {
        rc_tmp = tpm2_rc_get_session_number (rc);
        entry = tpm2_get_session_entry (rc_tmp);
        if (!entry) {
            printf ("Unknown TPM_RC session number: 0x%03x\n", rc_tmp);
            return -1;
        }
        printf ("session\n  hex: 0x%03x\n  identifier: %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    }

    return 0;
}
/* Dump the hex, identifier and description for the TSS defined layer
 * indicator in the provided TPM_RC.
 */
int
print_tpm_rc_tss_layer (TPM_RC rc)
{
    TPM_RC rc_tmp;
    tpm2_rc_entry_t *entry;
    int ret;

    rc_tmp = tpm2_rc_get_layer (rc);
    /* Currently no entry for 0x0 layer, assume it's directly from the TPM? */
    printf ("error layer\n  hex: 0x%x\n", rc_tmp);
    entry = tpm2_get_layer_entry (rc_tmp);
    if (entry) {
        printf ("  identifier: %s\n  description: %s\n",
                entry->name, entry->description);
        ret = 0;
    } else {
        printf ("failed to decode TPM_RC layer: 0x%x\n", rc_tmp);
        ret = -1;
    }

    return ret;
}
/* Dump the hex, identifier string and description for the TSS defined
 * base error code in the provided TPM_RC.
 */
int
print_tpm_rc_tss_error_code (TPM_RC rc)
{
    TPM_RC rc_tmp;
    tpm2_rc_entry_t *entry;
    int ret;

    entry = tpm2_get_tss_base_rc_entry (rc);
    if (entry) {
        printf ("base error code\n  identifier: %s\n  description: %s\n",
                entry->name, entry->description);
        ret = 0;
    } else {
        rc_tmp = tpm2_rc_get_tss_err_code (rc);
        printf ("failed to decode TPM_RC error code: 0x%x\n", rc_tmp);
        ret = -1;
    }

    return ret;
}
/* Top level function to dump human readable data about TPM_RCs as defined
 * in the TPM2 Part 2: Structures, Table 17..
 */
int
print_tpm_rc_tpm_error_code (TPM_RC rc)
{
    if (tpm2_rc_is_format_zero (rc))
        print_tpm_rc_format_zero (rc);
    else if (tpm2_rc_is_format_one (rc))
        print_tpm_rc_format_one (rc);
    else {
        LOG_ERR("Unknown TPM_RC format");
        return -1;
    }
    return 0;
}
/* Top level function to dump human readable data about TPM_RCs.
 */
int
print_tpm_rc (TPM_RC rc)
{
    int ret;
    TPM_RC rc_tmp;

    /* Determine which layer in the stack produced the error */
    rc_tmp = tpm2_rc_get_layer (rc);
    ret = print_tpm_rc_tss_layer (rc);
    switch (rc_tmp) {
        case TSS2_SYS_ERROR_LEVEL:
        case TSS2_TCTI_ERROR_LEVEL:
            ret = print_tpm_rc_tss_error_code (rc);
            break;
        case TSS2_SYS_PART2_ERROR_LEVEL:
        case TSS2_TPM_ERROR_LEVEL:
            ret = print_tpm_rc_tpm_error_code (rc);
            break;
        default:
            break;
    }

    return ret;
}

int
main (int argc, char *argv[], char *envp[])
{
    TPM_RC rc = 0;
    int pos_ind = -1, ret = -1;

    pos_ind = process_cmdline (argc, argv, envp);
    if (pos_ind + 1 != argc) {
        LOG_ERR ("No error code provided, try --help");
        exit (1);
    }
    rc = str_to_tpm_rc (argv[pos_ind]);
    ret = print_tpm_rc (rc);
    exit (ret);
}
