/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include <tss2/tss2_tpm2_types.h>

#include "tool_rc.h"

#define UNFMT1(x) (x - TPM2_RC_FMT1)
#define UNVER1(x) (x - TPM2_RC_VER1)

static inline UINT16 tpm2_rc_fmt1_error_get(TPM2_RC rc) {
    return (rc & 0x3F);
}

static inline UINT16 tpm2_rc_fmt0_error_get(TPM2_RC rc) {
    return (rc & 0x7F);
}

static inline UINT8 tss2_rc_layer_format_get(TSS2_RC rc) {
    return ((rc & (1 << 7)) >> 7);
}

static tool_rc flatten_fmt1(TSS2_RC rc) {

    UINT8 errnum = tpm2_rc_fmt1_error_get(rc);
    switch (errnum) {
    case UNFMT1(TPM2_RC_AUTH_FAIL):
        return tool_rc_auth_error;
    default:
        return tool_rc_general_error;
    }
}

static tool_rc flatten_fmt0(TSS2_RC rc) {

    UINT8 errnum = tpm2_rc_fmt0_error_get(rc);
    switch (errnum) {
    case UNVER1(TPM2_RC_COMMAND_CODE):
        return tool_rc_unsupported;
    default:
        return tool_rc_general_error;
    }
}

tool_rc tool_rc_from_tpm(TSS2_RC rc) {

    bool is_fmt_1 = tss2_rc_layer_format_get(rc);
    if (is_fmt_1) {
        return flatten_fmt1(rc);
    }

    return flatten_fmt0(rc);
}
