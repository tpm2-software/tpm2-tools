/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef MAIN_H
#define MAIN_H

#include <tss2/tss2_esys.h>
#include <stdbool.h>

#include "tool_rc.h"
#include "tpm2_options.h"
#include "tpm2_tool_output.h"

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
typedef bool (*tpm2_tool_onstart_t)(tpm2_options **opts);

/**
 * This is the main interface for tools, after tcti and sapi/esapi initialization
 * are performed.
 * @param ectx
 *  The system/esapi api context.
 * @param flags
 *  Flags that tools may wish to respect.
 * @return
 *  A tool_rc indicating status.
 */
typedef tool_rc (*tpm2_tool_onrun_t)(ESYS_CONTEXT *ectx, tpm2_option_flags flags);

/**
 * Called after tpm2_tool_onrun() is invoked. ESAPI context is still valid during this call.
 * @param ectx
 *  The system/esapi api context.
 * @return
 *  A tool_rc indicating status.
 */
typedef tool_rc (*tpm2_tool_onstop_t)(ESYS_CONTEXT *ectx);

/**
 * Called when the tool is exiting, useful for cleanup.
 */
typedef void (*tpm2_tool_onexit_t)(void);


typedef struct {
	const char * name;
	tpm2_tool_onstart_t onstart;
	tpm2_tool_onrun_t onrun;
	tpm2_tool_onstop_t onstop;
	tpm2_tool_onexit_t onexit;
} tpm2_tool;

void tpm2_tool_register(const tpm2_tool * tool);

#define TPM2_TOOL_REGISTER(tool_name,tool_onstart,tool_onrun,tool_onstop,tool_onexit) \
	static const tpm2_tool tool = { \
		.name		= tool_name, \
		.onstart	= tool_onstart, \
		.onrun		= tool_onrun, \
		.onstop		= tool_onstop, \
		.onexit		= tool_onexit, \
	}; \
	static void \
	__attribute__((__constructor__)) \
	__attribute__((__used__)) \
	_tpm2_tool_init(void) \
	{ \
		tpm2_tool_register(&tool); \
	}

#endif /* MAIN_H */
