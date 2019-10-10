/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TSS2_TEMPLATE_H
#define TSS2_TEMPLATE_H
#include <stdbool.h>
#include <tss2/tss2_fapi.h>

#include "lib/tpm2_options.h"
#include "lib/tpm2_util.h"

#define Fapi_Free(x) free(x)

/**
 * An optional interface for tools to specify what options they support.
 * They are concatenated with main's options and passed to getopt_long.
 * @param opts
 *  The callee can choose to set *opts to a tpm_options pointer allocated
 *  via tpm2_options_new(). Setting *opts to NULL is not an error, and
 *  Indicates that no options are specified by the tool.
 *
 * @return
 *  True on success, false on error.
 */
bool tss2_tool_onstart(tpm2_options **opts) __attribute__((visibility("hidden")));

/**
 * This is the main interface for tools, after tcti and fapi initialization
 * is performed.
 * @param fctx
 *  The fapi api context.
 * @return
 *  0 on success
 *  1 on failure
 * -1 to show usage
 */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) __attribute__((weak, visibility("hidden")));

/**
 * Called when the tool is exiting, useful for cleanup.
 */
void tss2_tool_onexit(void) __attribute__((weak, visibility("hidden")));

TSS2_RC policy_auth_callback(FAPI_CONTEXT*, char const*, char**, void*);
int open_write_and_close(const char *path, bool overwrite, const void* output, size_t output_len);
int open_read_and_close(const char *path, void **input, size_t *size);
char* ask_for_password();
void LOG_PERR(const char *func, TSS2_RC rc);
void LOG_ERR(const char *format, ...);
#endif /* TSS2_TEMPLATE_H */
