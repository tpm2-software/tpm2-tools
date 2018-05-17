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

#include "rc-decode.h"

/* Array of RC_VER1 error codes from TPM 2.0, Part 2, Table 17
 * The error code is in the lower 7 bits [06:00] but the identifiers are
 * defined as RC_VER1 + 0xXXX. When looking up values you must include bit
 * 8 in the comparison or mask out bit 8.
 */
struct tpm2_rc_entry tpm2_ver1_entry [] = {
    { /* 0x000 */
        .id          = TPM2_RC_INITIALIZE,
        .name        = "TPM2_RC_INITIALIZE",
        .description = "TPM not initialized",
    },
    { /* 0x001 */
        .id          = TPM2_RC_FAILURE,
        .name        = "TPM2_RC_FAILURE",
        .description = "commands not being accepted because of a TPM failure",
    },
    { /* 0x003 */
        .id          = TPM2_RC_SEQUENCE,
        .name        = "TPM2_RC_SEQUENCE",
        .description = "improper use of a sequence handle",
    },
    { /* 0x00B */
        .id          = TPM2_RC_PRIVATE,
        .name        = "TPM2_RC_PRIVATE",
        .description = NULL,
    },
    { /* 0x019 */
        .id          = TPM2_RC_HMAC,
        .name        = "TPM2_RC_HMAC",
        .description = NULL,
    },
    { /* 0x020 */
        .id          = TPM2_RC_DISABLED,
        .name        = "TPM2_RC_DISABLED",
        .description = NULL,
    },
    { /* 0x021 */
        .id          = TPM2_RC_EXCLUSIVE,
        .name        = "TPM2_RC_EXCLUSIVE",
        .description = "command failed because audit sequence required exclusivity",
    },
    { /* 0x024 */
        .id          = TPM2_RC_AUTH_TYPE,
        .name        = "TPM2_RC_AUTH_TYPE",
        .description = "authorization handle is not correct for command",
    },
    { /* 0x025 */
        .id          = TPM2_RC_AUTH_MISSING,
        .name        = "TPM2_RC_AUTH_MISSING",
        .description = "command requires an authorization session for handle and it is not present.",
    },
    { /* 0x026 */
        .id          = TPM2_RC_POLICY,
        .name        = "TPM2_RC_POLICY",
        .description = "policy Failure In Math Operation or an invalid authPolicy value",
    },
    { /* 0x027 */
        .id          = TPM2_RC_PCR,
        .name        = "TPM2_RC_PCR",
        .description = "PCR check fail",
    },
    { /* 0x028 */
        .id          = TPM2_RC_PCR_CHANGED,
        .name        = "TPM2_RC_PCR_CHANGED",
        .description = "PCR have changed since checked.",
    },
    { /* 0x02D */
        .id          = TPM2_RC_UPGRADE,
        .name        = "TPM2_RC_UPGRADE",
        .description = "for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode",
    },
    { /* 0x02E */
        .id          = TPM2_RC_TOO_MANY_CONTEXTS,
        .name        = "TPM2_RC_TOO_MANY_CONTEXTS",
        .description = "context ID counter is at maximum.",
    },
    { /* 0x02F */
        .id          = TPM2_RC_AUTH_UNAVAILABLE,
        .name        = "TPM2_RC_AUTH_UNAVAILABLE",
        .description = "authValue or authPolicy is not available for selected entity.",
    },
    { /* 0x030 */
        .id          = TPM2_RC_REBOOT,
        .name        = "TPM2_RC_REBOOT",
        .description = "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
    },
    { /* 0x0x031 */
        .id          = TPM2_RC_UNBALANCED,
        .name        = "TPM2_RC_UNBALANCED",
        .description = "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.",
    },
    { /* 0x042 */
        .id          = TPM2_RC_COMMAND_SIZE,
        .name        = "TPM2_RC_COMMAND_SIZE",
        .description = "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
    },
    { /* 0x043 */
        .id          = TPM2_RC_COMMAND_CODE,
        .name        = "TPM2_RC_COMMAND_CODE",
        .description = "command code not supported",
    },
    { /* 0x044 */
        .id          = TPM2_RC_AUTHSIZE,
        .name        = "TPM2_RC_AUTHSIZE",
        .description = "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required",
    },
    { /* 0x045 */
        .id          = TPM2_RC_AUTH_CONTEXT,
        .name        = "TPM2_RC_AUTH_CONTEXT",
        .description = "use of an authorization session with a context command or another command that cannot have an authorization session.",
    },
    { /* 0x046 */
        .id          = TPM2_RC_NV_RANGE,
        .name        = "TPM2_RC_NV_RANGE",
        .description = "NV offset+size is out of range.",
    },
    { /* 0x047 */
        .id          = TPM2_RC_NV_SIZE,
        .name        = "TPM2_RC_NV_SIZE",
        .description = "Requested allocation size is larger than allowed.",
    },
    { /* 0x048 */
        .id          = TPM2_RC_NV_LOCKED,
        .name        = "TPM2_RC_NV_LOCKED",
        .description = "NV access locked.",
    },
    { /* 0x049 */
        .id          = TPM2_RC_NV_AUTHORIZATION,
        .name        = "TPM2_RC_NV_AUTHORIZATION",
        .description = "NV access authorization fails in command actions (this failure does not affect lockout.action)",
    },
    { /* 0x04A */
        .id          = TPM2_RC_NV_UNINITIALIZED,
        .name        = "TPM2_RC_NV_UNINITIALIZED",
        .description = "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored",
    },
    { /* 0x04B */
        .id          = TPM2_RC_NV_SPACE,
        .name        = "TPM2_RC_NV_SPACE",
        .description = "insufficient space for NV allocation",
    },
    { /* 0x04C */
        .id          = TPM2_RC_NV_DEFINED,
        .name        = "TPM2_RC_NV_DEFINED",
        .description = "NV Index or persistend object already defined",
    },
    { /* 0x050 */
        .id          = TPM2_RC_BAD_CONTEXT,
        .name        = "TPM2_RC_BAD_CONTEXT",
        .description = "context in TPM2_ContextLoad() is not valid",
    },
    { /* 0x051 */
        .id          = TPM2_RC_CPHASH,
        .name        = "TPM2_RC_CPHASH",
        .description = "cpHash value already set or not correct for use",
    },
    { /* 0x052 */
        .id          = TPM2_RC_PARENT,
        .name        = "TPM2_RC_PARENT",
        .description = "handle for parent is not a valid parent",
    },
    { /* 0x053 */
        .id          = TPM2_RC_NEEDS_TEST,
        .name        = "TPM2_RC_NEEDS_TEST",
        .description = "some function needs testing.",
    },
    { /* 0x054 */
        .id          = TPM2_RC_NO_RESULT,
        .name        = "TPM2_RC_NO_RESULT",
        .description = "returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.",
    },
    { /* 0x055 */
        .id          = TPM2_RC_SENSITIVE,
        .name        = "TPM2_RC_SENSITIVE",
        .description = "the sensitive area did not unmarshal correctly after decryption – this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred",
    },
    { /* 0x07F */
        .id          = TPM2_RC_MAX_FM0,
        .name        = "TPM2_RC_MAX_FM0",
        .description = "largest version 1 code that is not a warning",
    }
};
/* Array of RC_FMT1 error codes from TPM 2.0, Part 2, Table 17
 * The error code is in the lower 6 bits [05:00] but the identifiers are
 * defined as RC_FMT1 + 0xXXX. When looking up values you must include bit
 * 7 in the comparison or mask it out.
 */
struct tpm2_rc_entry tpm2_fmt1_entry [] = {
    { /* 0x001 */
        .id          = TPM2_RC_ASYMMETRIC,
        .name        = "TPM2_RC_ASYMMETRIC",
        .description = "asymmetric algorithm not supported or not correct",
    },
    { /* 0x002 */
        .id          = TPM2_RC_ATTRIBUTES,
        .name        = "TPM2_RC_ATTRIBUTES",
        .description = "inconsistent attributes",
    },
    { /* 0x003 */
        .id          = TPM2_RC_HASH,
        .name        = "TPM2_RC_HASH",
        .description = "hash algorithm not supported or not appropriate",
    },
    { /* 0x004 */
        .id          = TPM2_RC_VALUE,
        .name        = "TPM2_RC_VALUE",
        .description = "value is out of range or is not correct for the context",
    },
    { /* 0x005 */
        .id          = TPM2_RC_HIERARCHY,
        .name        = "TPM2_RC_HIERARCHY",
        .description = "hierarchy is not enabled or is not correct for the use",
    },
    { /* 0x007 */
        .id          = TPM2_RC_KEY_SIZE,
        .name        = "TPM2_RC_KEY_SIZE",
        .description = "key size is not supported",
    },
    { /* 0x008 */
        .id          = TPM2_RC_MGF,
        .name        = "TPM2_RC_MGF",
        .description = "mask generation function not supported",
    },
    { /* 0x009 */
        .id          = TPM2_RC_MODE,
        .name        = "TPM2_RC_MODE",
        .description = "mode of operation not supported",
    },
    { /* 0x00A */
        .id          = TPM2_RC_TYPE,
        .name        = "TPM2_RC_TYPE",
        .description = "the type of the value is not appropriate for the use",
    },
    { /* 0x00B */
        .id          = TPM2_RC_HANDLE,
        .name        = "TPM2_RC_HANDLE",
        .description = "the handle is not correct for the use",
    },
    { /* 0x00C */
        .id          = TPM2_RC_KDF,
        .name        = "TPM2_RC_KDF",
        .description = "unsupported key derivation function or function not appropriate for use",
    },
    { /* 0x00D */
        .id          = TPM2_RC_RANGE,
        .name        = "TPM2_RC_RANGE",
        .description = "value was out of allowed range.",
    },
    { /* 0x00E */
        .id          = TPM2_RC_AUTH_FAIL,
        .name        = "TPM2_RC_AUTH_FAIL",
        .description = "the authorization HMAC check failed and DA counter incremented",
    },
    { /* 0x00F */
        .id          = TPM2_RC_NONCE,
        .name        = "TPM2_RC_NONCE",
        .description = "invalid nonce size",
    },
    { /* 0x010 */
        .id          = TPM2_RC_PP,
        .name        = "TPM2_RC_PP",
        .description = "authorization requires assertion of PP",
    },
    { /* 0x012 */
        .id          = TPM2_RC_SCHEME,
        .name        = "TPM2_RC_SCHEME",
        .description = "unsupported or incompatible scheme",
    },
    { /* 0x015 */
        .id          = TPM2_RC_SIZE,
        .name        = "TPM2_RC_SIZE",
        .description = "structure is the wrong size",
    },
    { /* 0x016 */
        .id          = TPM2_RC_SYMMETRIC,
        .name        = "TPM2_RC_SYMMETRIC",
        .description = "unsupported symmetric algorithm or key size, or not appropriate for instance",
    },
    { /* 0x017 */
        .id          = TPM2_RC_TAG,
        .name        = "TPM2_RC_TAG",
        .description = "incorrect structure tag",
    },
    { /* 0x018 */
        .id          = TPM2_RC_SELECTOR,
        .name        = "TPM2_RC_SELECTOR",
        .description = "union selector is incorrect",
    },
    { /* 0x01A */
        .id          = TPM2_RC_INSUFFICIENT,
        .name        = "TPM2_RC_INSUFFICIENT",
        .description = "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
    },
    { /* 0x01B */
        .id          = TPM2_RC_SIGNATURE,
        .name        = "TPM2_RC_SIGNATURE",
        .description = "the signature is not valid",
    },
    { /* 0x01C */
        .id          = TPM2_RC_KEY,
        .name        = "TPM2_RC_KEY",
        .description = "key fields are not compatible with the selected use",
    },
    { /* 0x0x01D */
        .id          = TPM2_RC_POLICY_FAIL,
        .name        = "TPM2_RC_POLICY_FAIL",
        .description = "a policy check failed",
    },
    { /* 0x01F */
        .id          = TPM2_RC_INTEGRITY,
        .name        = "TPM2_RC_INTEGRITY",
        .description = "integrity check failed",
    },
    { /* 0x020 */
        .id          = TPM2_RC_TICKET,
        .name        = "TPM2_RC_TICKET",
        .description = "invalid ticket",
    },
    { /* 0x021 */
        .id          = TPM2_RC_RESERVED_BITS,
        .name        = "TPM2_RC_RESERVED_BITS",
        .description = "reserved bits not set to zero as required",
    },
    { /* 0x022 */
        .id          = TPM2_RC_BAD_AUTH,
        .name        = "TPM2_RC_BAD_AUTH",
        .description = "authorization failure without DA implications",
    },
    { /* 0x023 */
        .id          = TPM2_RC_EXPIRED,
        .name        = "TPM2_RC_EXPIRED",
        .description = "the policy has expired",
    },
    { /* 0x024 */
        .id          = TPM2_RC_POLICY_CC,
        .name        = "TPM2_RC_POLICY_CC",
        .description = "the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented",
    },
    { /* 0x025 */
        .id          = TPM2_RC_BINDING,
        .name        = "TPM2_RC_BINDING",
        .description = "public and sensitive portions of an object are not cryptographically bound",
    },
    { /* 0x026 */
        .id          = TPM2_RC_CURVE,
        .name        = "TPM2_RC_CURVE",
        .description = "curve not supported",
    },
    { /* 0x027 */
        .id          = TPM2_RC_ECC_POINT,
        .name        = "TPM2_RC_ECC_POINT",
        .description = "point is not on the required curve.",
    }
};
/* Array of RC_WARN error codes from TPM 2.0, Part 2, Table 17. These are
 * implicitly RC_VER1 codes, but not errors, warnings. Index in this array
 * corresponds to the error code in the lower 6 bits [05:00]. Again, the
 * identifiers in the ID field have a constant added to the error code. This
 * time it's RC_WARN (0x900).
 */
struct tpm2_rc_entry tpm2_warn_entry [] = {
    { /* 0x001 */
        .id          = TPM2_RC_CONTEXT_GAP,
        .name        = "TPM2_RC_CONTEXT_GAP",
        .description = "gap for context ID is too large",
    },
    { /* 0x002 */
        .id          = TPM2_RC_OBJECT_MEMORY,
        .name        = "TPM2_RC_OBJECT_MEMORY",
        .description = "out of memory for object contexts",
    },
    { /* 0x003 */
        .id          = TPM2_RC_SESSION_MEMORY,
        .name        = "TPM2_RC_SESSION_MEMORY",
        .description = "out of memory for session contexts",
    },
    { /* 0x004 */
        .id          = TPM2_RC_MEMORY,
        .name        = "TPM2_RC_MEMORY",
        .description = "out of shared object/session memory or need space for internal operations",
    },
    { /* 0x005 */
        .id          = TPM2_RC_SESSION_HANDLES,
        .name        = "TPM2_RC_SESSION_HANDLES",
        .description = "out of session handles – a session must be flushed before a new session may be created",
    },
    { /* 0x006 */
        .id          = TPM2_RC_OBJECT_HANDLES,
        .name        = "TPM2_RC_OBJECT_HANDLES",
        .description = "out of object handles – the handle space for objects is depleted and a reboot is required NOTE: This cannot occur on the reference implementation. NOTE: There is no reason why an implementation would implement a design that would deplete handle space. Platform specifications are encouraged to forbid it.",
    },
    { /* 0x007 */
        .id          = TPM2_RC_LOCALITY,
        .name        = "TPM2_RC_LOCALITY",
        .description = "bad locality",
    },
    { /* 0x008 */
        .id          = TPM2_RC_YIELDED,
        .name        = "TPM2_RC_YIELDED",
        .description = "the TPM has suspended operation on the command; forward progress was made and the command may be retried. See TPM 2.0 Part 1, “Multi-tasking.” NOTE: This cannot occur on the reference implementation.",
    },
    { /* 0x009 */
        .id          = TPM2_RC_CANCELED,
        .name        = "TPM2_RC_CANCELED",
        .description = "the command was canceled",
    },
    { /* 0x00A */
        .id          = TPM2_RC_TESTING,
        .name        = "TPM2_RC_TESTING",
        .description = "TPM is performing self-tests",
    },
    { /* 0x010 */
        .id          = TPM2_RC_REFERENCE_H0,
        .name        = "TPM2_RC_REFERENCE_H0",
        .description = "the 1st handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x011 */
        .id          = TPM2_RC_REFERENCE_H1,
        .name        = "TPM2_RC_REFERENCE_H1",
        .description = "the 2nd handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x012 */
        .id          = TPM2_RC_REFERENCE_H2,
        .name        = "TPM2_RC_REFERENCE_H2",
        .description = "the 3rd handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x013 */
        .id          = TPM2_RC_REFERENCE_H3,
        .name        = "TPM2_RC_REFERENCE_H3",
        .description = "the 4th handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x014 */
        .id          = TPM2_RC_REFERENCE_H4,
        .name        = "TPM2_RC_REFERENCE_H4",
        .description = "the 5th handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x015 */
        .id          = TPM2_RC_REFERENCE_H5,
        .name        = "TPM2_RC_REFERENCE_H5",
        .description = "the 6th handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x016 */
        .id          = TPM2_RC_REFERENCE_H6,
        .name        = "TPM2_RC_REFERENCE_H6",
        .description = "the 7th handle in the handle area references a transient object or session that is not loaded",
    },
    { /* 0x018 */
        .id          = TPM2_RC_REFERENCE_S0,
        .name        = "TPM2_RC_REFERENCE_S0",
        .description = "the 1st authorization session handle references a session that is not loaded",
    },
    { /* 0x019 */
        .id          = TPM2_RC_REFERENCE_S1,
        .name        = "TPM2_RC_REFERENCE_S1",
        .description = "the 2nd authorization session handle references a session that is not loaded",
    },
    { /* 0x01A */
        .id          = TPM2_RC_REFERENCE_S2,
        .name        = "TPM2_RC_REFERENCE_S2",
        .description = "the 3rd authorization session handle references a session that is not loaded",
    },
    { /* 0x01B */
        .id          = TPM2_RC_REFERENCE_S3,
        .name        = "TPM2_RC_REFERENCE_S3",
        .description = "the 4th authorization session handle references a session that is not loaded",
    },
    { /* 0x01C */
        .id          = TPM2_RC_REFERENCE_S4,
        .name        = "TPM2_RC_REFERENCE_S4",
        .description = "the 5th session handle references a session that is not loaded",
    },
    { /* 0x01D */
        .id          = TPM2_RC_REFERENCE_S5,
        .name        = "TPM2_RC_REFERENCE_S5",
        .description = "the 6th session handle references a session that is not loaded",
    },
    { /* 0x01E */
        .id          = TPM2_RC_REFERENCE_S6,
        .name        = "TPM2_RC_REFERENCE_S6",
        .description = "the 7th authorization session handle references a session that is not loaded",
    },
    { /* 0x020 */
        .id          = TPM2_RC_NV_RATE,
        .name        = "TPM2_RC_NV_RATE",
        .description = "the TPM is rate-limiting accesses to prevent wearout of NV",
    },
    { /* 0x021 */
        .id          = TPM2_RC_LOCKOUT,
        .name        = "TPM2_RC_LOCKOUT",
        .description = "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode",
    },
    { /* 0x022 */
        .id          = TPM2_RC_RETRY,
        .name        = "TPM2_RC_RETRY",
        .description = "the TPM was not able to start the command",
    },
    { /* 0x023 */
        .id          = TPM2_RC_NV_UNAVAILABLE,
        .name        = "TPM2_RC_NV_UNAVAILABLE",
        .description = "the command may require writing of NV and NV is not current accessible",
    },
    { /* 0x7F */
        .id          = TPM2_RC_NOT_USED,
        .name        = "TPM2_RC_NOT_USED",
        .description = "this value is reserved and shall not be returned by the TPM",
    }
};
/* Array of position error codes from TPM 2.0 Part 2, Table 17. These are
 * implicitly associated with RC_FMT1 codes.
 */
tpm2_rc_entry_t tpm2_position_entry [] = {
    { /* 0x100 */
        .id          = TPM2_RC_1,
        .name        = "TPM2_RC_1",
        .description = NULL,
    },
    { /* 0x200 */
        .id          = TPM2_RC_2,
        .name        = "TPM2_RC_2",
        .description = NULL,
    },
    { /* 0x300 */
        .id          = TPM2_RC_3,
        .name        = "TPM2_RC_3",
        .description = NULL,
    },
    { /* 0x400 */
        .id          = TPM2_RC_4,
        .name        = "TPM2_RC_4",
        .description = NULL,
    },
    { /* 0x500 */
        .id          = TPM2_RC_5,
        .name        = "TPM2_RC_5",
        .description = NULL,
    },
    { /* 0x600 */
        .id          = TPM2_RC_6,
        .name        = "TPM2_RC_6",
        .description = NULL,
    },
    { /* 0x700 */
        .id          = TPM2_RC_7,
        .name        = "TPM2_RC_7",
        .description = NULL,
    },
    { /* 0x800 */
        .id          = TPM2_RC_8,
        .name        = "TPM2_RC_8",
        .description = NULL,
    },
    { /* 0x900 */
        .id          = TPM2_RC_9,
        .name        = "TPM2_RC_9",
        .description = NULL,
    },
    { /* 0xA00 */
        .id          = TPM2_RC_A,
        .name        = "TPM2_RC_A",
        .description = NULL,
    },
    { /* 0xB00 */
        .id          = TPM2_RC_B,
        .name        = "TPM2_RC_B",
        .description = NULL,
    },
    { /* 0xC00 */
        .id          = TPM2_RC_C,
        .name        = "TPM2_RC_C",
        .description = NULL,
    },
    { /* 0xD00 */
        .id          = TPM2_RC_D,
        .name        = "TPM2_RC_D",
        .description = NULL,
    },
    { /* 0xE00 */
        .id          = TPM2_RC_E,
        .name        = "TPM2_RC_E",
        .description = NULL,
    },
    { /* 0xF00 */
        .id          = TPM2_RC_F,
        .name        = "TPM2_RC_F",
        .description = NULL,
    }
};
/* Array of tpm2_rc_entrys for layers defined in the TSS spec.
 */
struct tpm2_rc_entry tpm2_tss_layer_entry [] = {
    { /* 0x0
       * The spec calls this TSS2_TPM2_RC_LEVEL and it's defined as bits
       * [15:12] not [23:16] like the error layer / levels.
       */
        .id          = TSS2_TPM_RC_LAYER,
        .name        = "TSS2_TPM_RC_LAYER",
        .description = "Error produced by the TPM",
    },
    { /* 8 << 16 = 0x80000 */
        .id          = TSS2_SYS_RC_LAYER,
        .name        = "TSS2_SYS_RC_LAYER",
        .description = "Error from the SAPI",
    },
    { /* 9 << 16 = 0x90000 */
        .id          = TSS2_MU_RC_LAYER,
        .name        = "TSS2_MU_RC_LAYER",
        .description = "Error from the SAPI duplicating TPM error check"
    },
    { /* 10 << 16 = 0xA0000 */
        .id          = TSS2_TCTI_RC_LAYER,
        .name        = "TSS2_TCTI_RC_LAYER",
        .description = "Error from the TCTI"
    },
    { /* 11 << 16 = 0xB0000 */
        .id          = TSS2_RESMGR_TPM_RC_LAYER,
        .name        = "TSS2_RESMGRTPM_RC_LAYER",
        .description = "Error from the Resource Manager duplicating TPM error check"
    },
    { /* 12 << 16 = 0xC0000 */
        .id          = TSS2_RESMGR_RC_LAYER,
        .name        = "TSS2_RESMGR_ERROR_LEVEL",
        .description = "Error from the Resource Manager"
    }
};
/* Array of TSS2 error codes from TSS System API section 6.1.2.
 * Index in this array corresponds to the error code in the lower 12 bits
 * 11:00]. Undefined error codes will have NULL data in the array.
 */
struct tpm2_rc_entry tpm2_tss_base_rc_entry [] = {
    { /* 0x01 */
        .id          = TSS2_BASE_RC_GENERAL_FAILURE,
        .name        = "TSS2_BASE_RC_GENERAL_FAILURE",
        .description = "Catch all for all errors not otherwise specifed",
    },
    { /* 0x02 */
        .id          = TSS2_BASE_RC_NOT_IMPLEMENTED,
        .name        = "TSS2_BASE_RC_NOT_IMPLEMENTED",
        .description = "If called functionality isn't implemented",
    },
    { /* 0x03 */
        .id          = TSS2_BASE_RC_BAD_CONTEXT,
        .name        = "TSS2_BASE_RC_BAD_CONTEXT",
        .description = "A context structure is bad",
    },
    { /* 0x04 */
        .id          = TSS2_BASE_RC_ABI_MISMATCH,
        .name        = "TSS2_BASE_RC_ABI_MISMATCH",
        .description = "Passed in ABI version doesn't match called module's ABI version",
    },
    { /* 0x05 */
        .id          = TSS2_BASE_RC_BAD_REFERENCE,
        .name        = "TSS2_BASE_RC_BAD_REFERENCE",
        .description = "A pointer is NULL that isn't allowed to be NULL.",
    },
    { /* 0x06 */
        .id          = TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        .name        = "TSS2_BASE_RC_INSUFFICIENT_BUFFER",
        .description = "A buffer isn't large enough",
    },
    { /* 0x07 */
        .id          = TSS2_BASE_RC_BAD_SEQUENCE,
        .name        = "TSS2_BASE_RC_BAD_SEQUENCE",
        .description = "Function called in the wrong order",
    },
    { /* 0x08 */
        .id          = TSS2_BASE_RC_NO_CONNECTION,
        .name        = "TSS2_BASE_RC_NO_CONNECTION",
        .description = "Fails to connect to next lower layer",
    },
    { /* 0x09 */
        .id          = TSS2_BASE_RC_TRY_AGAIN,
        .name        = "TSS2_BASE_RC_TRY_AGAIN",
        .description = "Operation timed out; function must be called again to be completed",
    },
    { /* 0x0A */
        .id          = TSS2_BASE_RC_IO_ERROR,
        .name        = "TSS2_BASE_RC_IO_ERROR",
        .description = "IO failure",
    },
    { /* 0x0B */
        .id          = TSS2_BASE_RC_BAD_VALUE,
        .name        = "TSS2_BASE_RC_BAD_VALUE",
        .description = "A parameter has a bad value",
    },
    { /* 0x0C */
        .id          = TSS2_BASE_RC_NOT_PERMITTED,
        .name        = "TSS2_BASE_RC_NOT_PERMITTED",
        .description = "Operation not permitted.",
    },
    { /* 0x0D */
        .id          = TSS2_BASE_RC_INVALID_SESSIONS,
        .name        = "TSS2_BASE_RC_INVALID_SESSIONS",
        .description = "Session structures were sent, but command doesn't use them or doesn't use the specifed number of them",
    },
    { /* 0x0E */
        .id          = TSS2_BASE_RC_NO_DECRYPT_PARAM,
        .name        = "TSS2_BASE_RC_NO_DECRYPT_PARAM",
        .description = "If function called that uses decrypt parameter, but command doesn't support decrypt parameter.",
    },
    { /* 0x0F */
        .id          = TSS2_BASE_RC_NO_ENCRYPT_PARAM,
        .name        = "TSS2_BASE_RC_NO_ENCRYPT_PARAM",
        .description = "If function called that uses encrypt parameter, but command doesn't support decrypt parameter.",
    },
    { /* 0x10 */
        .id          = TSS2_BASE_RC_BAD_SIZE,
        .name        = "TSS2_BASE_RC_BAD_SIZE",
        .description = "If size of a paremeter is incorrect",
    },
    { /* 0x11 */
        .id          = TSS2_BASE_RC_MALFORMED_RESPONSE,
        .name        = "TSS2_BASE_RC_MALFORMED_RESPONSE",
        .description = "Response is malformed",
    },
    { /* 0x12 */
        .id          = TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
        .name        = "TSS2_BASE_RC_INSUFFICIENT_CONTEXT",
        .description = "Context not large enough",
    },
    { /* 0x13 */
        .id          = TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
        .name        = "TSS2_BASE_RC_INSUFFICIENT_RESPONSE",
        .description = "Response is not long enough",
    },
    { /* 0x14 */
        .id          = TSS2_BASE_RC_INCOMPATIBLE_TCTI,
        .name        = "TSS2_BASE_RC_INCOMPATIBLE_TCTI",
        .description = "Unknown or unusable TCTI version",
    },
    { /* 0x15 */
        .id          = TSS2_BASE_RC_NOT_SUPPORTED,
        .name        = "TSS2_BASE_RC_NOT_SUPPORTED",
        .description = "Functionality not supported.",
    },
    { /* 0x16 */
        .id          = TSS2_BASE_RC_BAD_TCTI_STRUCTURE,
        .name        = "TSS2_BASE_RC_BAD_TCTI_STRUCTURE",
        .description = "TCTI context is bad.",
    }
};
/*
char*
tpm2_strrc (TSS2_RC  rc,
            char   *out_str,
            size_t  out_str_size)
{
    if (is_tpm2_rc_format_zero (rc))
        return tpm2_fmt0_entry [rc].description;
    else if (is_tpm2_rc_format_one (rc))
        return tpm2_fmt1_entry [rc].description;
    else
        return NULL;
}
 */
/* Functions to lookup / retrieve entries from the arrays of tpm2_rc_entry_t's
 * None of these functions check the format of the TSS2_RC before doing the
 * lookup. They just mask out the irrelevant bits and do the lookup doing the
 * remainder. "irrelevant bits" is determined by the 'select_func' parameter.
 * This is a function to mask out "irrelevant bits". The same function is
 * applied to both the source RC and the RCs in the 'id' field of the array.
 */
#define STR_ENTRY_ARRAY_LENGTH(name) (sizeof (name) / sizeof (struct tpm2_rc_entry))
#define STR_ENTRY_ARRAY_LOOKUP(rc, array, select_func) \
    unsigned i; \
    for (i = 0; i < STR_ENTRY_ARRAY_LENGTH (array); ++i) \
        if (select_func (rc) == select_func (array[i].id)) \
            return &array[i]; \
    return NULL;

tpm2_rc_entry_t*
tpm2_get_tss_base_rc_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_tss_base_rc_entry, tpm2_rc_get_tss_err_code);
}
tpm2_rc_entry_t*
tpm2_get_parameter_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_position_entry, tpm2_rc_get_parameter_number);
}
tpm2_rc_entry_t*
tpm2_get_handle_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_position_entry, tpm2_rc_get_handle_number);
}
tpm2_rc_entry_t*
tpm2_get_session_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_position_entry, tpm2_rc_get_session_number);
}
tpm2_rc_entry_t*
tpm2_get_layer_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_tss_layer_entry, tpm2_rc_get_layer);
}
tpm2_rc_entry_t*
tpm2_get_fmt0_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_ver1_entry, tpm2_rc_get_code_7bit);
}
tpm2_rc_entry_t*
tpm2_get_fmt1_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_fmt1_entry, tpm2_rc_get_code_6bit);
}
tpm2_rc_entry_t*
tpm2_get_warn_entry (TSS2_RC rc)
{
    STR_ENTRY_ARRAY_LOOKUP (rc, tpm2_warn_entry, tpm2_rc_get_code_6bit);
}
