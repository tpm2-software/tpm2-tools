/* SPDX-License-Identifier: BSD-3-Clause */

#include <stddef.h>
#include <stdlib.h>

#include "log.h"
#include "files.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"

#define OFFSET_TPMS_TIME_INFO_TIME offsetof(TPMS_TIME_INFO, time)
#define OFFSET_TPMS_TIME_INFO_CLOCK offsetof(TPMS_TIME_INFO, clockInfo.clock)
#define OFFSET_TPMS_TIME_INFO_RESETS offsetof(TPMS_TIME_INFO, clockInfo.resetCount)
#define OFFSET_TPMS_TIME_INFO_RESTARTS offsetof(TPMS_TIME_INFO, clockInfo.restartCount)
#define OFFSET_TPMS_TIME_INFO_SAFE offsetof(TPMS_TIME_INFO, clockInfo.safe);

typedef struct tpm_policycountertimer_ctx tpm_policycountertimer_ctx;
struct tpm_policycountertimer_ctx {
    //Inputs
    const char *session_path;
    tpm2_session *session;

    TPM2B_OPERAND operand_b;

    uint16_t offset;

    bool operation_set;
    TPM2_EO operation;

    //Output
    const char *policy_digest_path;
};

static tpm_policycountertimer_ctx ctx = {
    .operation = TPM2_EO_EQ,
    .offset = 0,
};

static bool convert_keyvalue_to_operand_buffer(const char *value,
    uint16_t offset, uint8_t size) {

    ctx.offset = offset;

    /*
     * Convert input string data to a *big endian* uint64_t or uint32_t
     */
    union data {
        uint32_t u32;
        uint64_t u64;
        uint8_t b;
    } data;

    bool result = false;
    switch(size) {
    case sizeof(uint32_t):
        result = tpm2_util_string_to_uint32(value, &data.u32);
        break;
    case sizeof(uint64_t):
        result = tpm2_util_string_to_uint64(value, &data.u64);
        break;
    default:
        LOG_ERR("Unknown size, got: %u", size);
        return false;
    }

    if (!result) {
        LOG_ERR("Invalid value specified for the key");
        return false;
    }

    /*
     * sizes should be u32 or u64 and thus never overflow a TPM2B_OPPERAND
     * but we will check anyways in case something changes elsewhere.
     */
    if (size > sizeof(ctx.operand_b.buffer)) {
        LOG_ERR("Size is too large for TPM2B_OPERAND. Got %u, max size is: %zu",
                size, sizeof(ctx.operand_b.buffer));
        return false;
    }

    ctx.operand_b.size = size;
    size_t i = 0;
    for (i = 0; i < size; i++) {
        ctx.operand_b.buffer[i] = *(&data.b + size - i - 1);
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify one argument as value/ parameter=value.");
        return false;
    }

    if (!strcmp("safe", argv[0])) {
        ctx.offset = OFFSET_TPMS_TIME_INFO_SAFE;
        ctx.operand_b.size = 1;
        ctx.operand_b.buffer[0] = TPM2_YES;
        return true;
    }

    const char *value;
    const char *key;
    char *a = argv[0];
    char *split = strchr(a, '=');
    if (!split) {
      value = argv[0];
      key = "time";
    } else {
        split[0] = '\0';
        value = split + 1;
        key = a;
    }

    if (!value[0]) {
      LOG_ERR("Must specify a corresponding value");
      return false;
    }

    // look up key and process value
    if (!strcmp("time", key)) {
        return convert_keyvalue_to_operand_buffer(value,
            OFFSET_TPMS_TIME_INFO_TIME, sizeof(uint64_t));
    }

    if (!strcmp("clock", key)) {
        return convert_keyvalue_to_operand_buffer(value,
            OFFSET_TPMS_TIME_INFO_CLOCK, sizeof(uint64_t));
    }

    if (!strcmp("resets", key)) {
        return convert_keyvalue_to_operand_buffer(value,
            OFFSET_TPMS_TIME_INFO_RESETS, sizeof(uint32_t));
    }

    if (!strcmp("restarts", key)) {
        return convert_keyvalue_to_operand_buffer(value,
            OFFSET_TPMS_TIME_INFO_RESTARTS, sizeof(uint32_t));
    }

    LOG_ERR("Unknown argument. Specify time/ clock/ resets/ restarts/ safe");
    return false;
}

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case TPM2_EO_EQ:
    case TPM2_EO_NEQ:
    case TPM2_EO_SIGNED_GT:
    case TPM2_EO_UNSIGNED_GT:
    case TPM2_EO_SIGNED_LT:
    case TPM2_EO_UNSIGNED_LT:
    case TPM2_EO_SIGNED_GE:
    case TPM2_EO_UNSIGNED_GE:
    case TPM2_EO_SIGNED_LE:
    case TPM2_EO_UNSIGNED_LE:
    case TPM2_EO_BITSET:
    case TPM2_EO_BITCLEAR:
        if (ctx.operation_set) {
            LOG_ERR("Only one operator can be specified");
            return false;
        }
        ctx.operation_set = true;
        ctx.operation = key;
        break;
    default:
        return false;
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "policy",    required_argument, NULL, 'L'                  },
        { "session",   required_argument, NULL, 'S'                  },
        { "eq",        no_argument,       NULL,  TPM2_EO_EQ          },
        { "neq",       no_argument,       NULL,  TPM2_EO_NEQ         },
        { "sgt",       no_argument,       NULL,  TPM2_EO_SIGNED_GT   },
        { "ugt",       no_argument,       NULL,  TPM2_EO_UNSIGNED_GT },
        { "slt",       no_argument,       NULL,  TPM2_EO_SIGNED_LT   },
        { "ult",       no_argument,       NULL,  TPM2_EO_UNSIGNED_LT },
        { "sge",       no_argument,       NULL,  TPM2_EO_SIGNED_GE   },
        { "uge",       no_argument,       NULL,  TPM2_EO_UNSIGNED_GE },
        { "sle",       no_argument,       NULL,  TPM2_EO_SIGNED_LE   },
        { "ule",       no_argument,       NULL,  TPM2_EO_UNSIGNED_LE },
        { "bs",        no_argument,       NULL,  TPM2_EO_BITSET      },
        { "bc",        no_argument,       NULL,  TPM2_EO_BITCLEAR    },
    };

    *opts = tpm2_options_new("L:S:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.operand_b.size) {
        LOG_WARN("Data to compare is of size 0");
        return false;
    }

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = is_input_option_args_valid();
    if (!result) {
        return tool_rc_general_error;
    }

    //Input
    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
        &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    ESYS_TR policy_session = tpm2_session_get_handle(ctx.session);

    //ESAPI call
    rc = tpm2_policy_countertimer(ectx, policy_session, &ctx.operand_b,
        ctx.offset, ctx.operation);
    if (rc != tool_rc_success) {
        return rc;
    }

    //Output
    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policycountertimer", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
