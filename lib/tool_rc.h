/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TOOL_RC_H_
#define LIB_TOOL_RC_H_

/* do not port to TSS below here */
typedef enum tool_rc tool_rc;
enum tool_rc {
    /* do not reorder or change, part of returned codes to exit */
    /* maps to common/returns.md */
    tool_rc_success = 0,
    tool_rc_general_error,
    tool_rc_option_error,
    tool_rc_auth_error,
    tool_rc_tcti_error,
    tool_rc_unsupported
};

/**
 * Flattens a TSS generated RC into it's error component and converts it to a tool_rc suitable for tool return
 * use.
 * @note
 *  Do not port me to TSS.
 * @param rc
 *  The rc to convert.
 * @return
 *  A valid tool_rc.
 */
tool_rc tool_rc_from_tpm(TSS2_RC rc);

#endif /* LIB_TOOL_RC_H_ */
