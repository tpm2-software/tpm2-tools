/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 1
typedef struct tpm_nvcertify_ctx tpm_nvcertify_ctx;
struct tpm_nvcertify_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } nvindex_authobj;

    TPM2_HANDLE nv_index;
    TPM2B_NAME precalc_nvname;
    TPM2B_NAME precalc_signername;
    TPMI_ALG_HASH halg;
    bool is_sigscheme_halg_specified;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    bool is_sigscheme_specified;
    UINT16 size;
    UINT16 offset;
    const char *policy_qualifier_arg;
    TPMT_SIG_SCHEME in_scheme;
    TPM2B_DATA policy_qualifier;

    /*
     * Outputs
     */
    char *certify_info_path;
    TPM2B_ATTEST *certify_info;
    char *signature_path;
    TPMT_SIGNATURE *signature;
    tpm2_convert_sig_fmt sig_format;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_tcti_none;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_nvcertify_ctx ctx = {
    .halg = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .policy_qualifier = TPM2B_EMPTY_INIT,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .aux_session_handle[0] = ESYS_TR_NONE,
};

static tool_rc nv_certify(ESYS_CONTEXT *ectx) {

    return tpm2_nvcertify(ectx, &ctx.signing_key.object,
        &ctx.nvindex_authobj.object, ctx.nv_index, &ctx.precalc_nvname,
        &ctx.precalc_signername, ctx.offset, ctx.size, &ctx.in_scheme,
        &ctx.certify_info, &ctx.signature, &ctx.policy_qualifier, &ctx.cp_hash,
        &ctx.rp_hash, ctx.parameter_hash_algorithm, ctx.aux_session_handle[0]);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

   UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    bool result = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
        ctx.signature_path);
    if (!result) {
        LOG_ERR("Failed saving signature data.");
        return tool_rc_general_error;
    }

    result = files_save_bytes_to_file(ctx.certify_info_path,
        (UINT8 *) &ctx.certify_info->attestationData, ctx.certify_info->size);
    if (!result) {
        LOG_ERR("Failed saving attestation data.");
        return tool_rc_general_error;
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
        rc = is_file_op_success ? tool_rc_success : tool_rc_general_error;
    }

    return rc;
}

static bool set_digest_algorithm(char *value) {

    ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
    if (ctx.halg == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert to number or lookup algorithm, got: "
                "\"%s\"", value);
        return false;
    }
    return true;
}

static bool set_signing_scheme(char *value) {

    ctx.sig_scheme = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
    if (ctx.sig_scheme == TPM2_ALG_ERROR) {
        LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
        return false;
    }
    return true;
}

static bool set_signature_format(char *value) {

    ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);
    if (ctx.sig_format == signature_format_err) {
        return false;
    }
    return true;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * Load signing key and auth
     */
    tool_rc rc = tool_rc_success;
    /*
     * if tcti is none, the signer name is read when recording the options.
     */
    if (!ctx.is_tcti_none) {
        rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
                ctx.signing_key.auth_str, &ctx.signing_key.object, false,
                TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
        if (rc != tool_rc_success) {
            LOG_ERR("Invalid signing key/ authorization.");
            return rc;
        }
    }

    /*
     * Load NV index authorization object and auth
     */
    if (ctx.is_tcti_none) {
        /*
         * Cannot use tpm2_util_object_load like in nvdefine as it makes a call
         * to tpm2_util_sys_handle_to_esys_handle which then tries to read the
         * ESYS_TR object off of the TPM expecting it to be there.
         * Note: this if it is a permanent handle ESYS_TR is fixed and so the
         * TPM is not probed even with tpm2_util_sys_handle_to_esys_handle.
         */
        rc = tpm2_util_handle_from_optarg(ctx.nvindex_authobj.ctx_path,
            &ctx.nvindex_authobj.object.handle,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P) ?
            tool_rc_success : tool_rc_option_error;

        ctx.nvindex_authobj.object.tr_handle = (rc == tool_rc_success) ?
          tpm2_tpmi_hierarchy_to_esys_tr(ctx.nvindex_authobj.object.handle) : 0;
    } else {
        rc = tpm2_util_object_load_auth(ectx, ctx.nvindex_authobj.ctx_path,
            ctx.nvindex_authobj.auth_str, &ctx.nvindex_authobj.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    }

    if (rc != tool_rc_success) {
        LOG_ERR("Invalid object specified for NV index authorization.");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Command specific initializations dependent on loaded objects
     */

    /*
     * Set appropriate signature scheme for key type
     */
    if (!ctx.is_tcti_none) {
        rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme, &ctx.in_scheme);
        if (rc != tool_rc_success) {
            LOG_ERR("bad signature scheme for key type!");
            return rc;
        }
    } else {
        ctx.in_scheme.scheme = ctx.sig_scheme;
        ctx.in_scheme.details.any.hashAlg = ctx.halg;
    }

    /*
     * Qualifier data is optional. If not specified default to 0
     */
    if (ctx.policy_qualifier_arg) {

        ctx.policy_qualifier.size = sizeof(ctx.policy_qualifier.buffer);
        bool result = tpm2_util_bin_from_hex_or_file(ctx.policy_qualifier_arg,
                &ctx.policy_qualifier.size,
                ctx.policy_qualifier.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
    */

    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.signing_key.object.session,
        ctx.nvindex_authobj.object.session,
        ctx.aux_session[0]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    ctx.is_tcti_none = flags.tcti_none ? true : false;
    if (ctx.is_tcti_none && !ctx.cp_hash_path) {
        LOG_ERR("If tcti is none, then cpHash path must be specified");
        return tool_rc_option_error;
    }

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * is_tcti_none       [N]
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.is_tcti_none ||
        (ctx.cp_hash_path && !ctx.rp_hash_path)) ? false : true;

    if (!ctx.signing_key.ctx_path && !ctx.is_tcti_none) {
        LOG_ERR("Must specify the signing key '-C'.");
        return tool_rc_option_error;
    }

    if (!ctx.signature_path && !ctx.is_tcti_none) {
        LOG_ERR("Must specify the file path to save signature '-o'");
        return tool_rc_option_error;
    }

    if (!ctx.certify_info_path && !ctx.is_tcti_none) {
        LOG_ERR("Must specify file path to save attestation '--attestation'");
        return tool_rc_option_error;
    }

    if (ctx.is_tcti_none && !ctx.is_sigscheme_specified) {
        LOG_ERR("Must specify the signing scheme");
        return tool_rc_option_error;
    }

    if (ctx.is_tcti_none && !ctx.is_sigscheme_halg_specified) {
        LOG_ERR("Must specify the digest alg for the signing scheme");
        return tool_rc_option_error;
    }

    /*
     * Peculiar to this and some other tools, the object (nvindex) name must
     * be specified when only calculating the cpHash.
     *
     * This breaks the compatibility with the 4.X tools where in a real tcti
     * is invoked to get a sapi handle to retrieve the params. Also this would
     * imply that a real NV index ought to be defined even in the case of simply
     * calculating the cpHash.
     *
     * To solve this conundrum, we can only mandate the requirement for the NV
     * index name in case tcti is specified as none. If tcti is not specified as
     * none we fall back to the old behavior of reading from a define NV index
     * 
     * Also, tcti is setup to a fake_tcti when tcti is specified "none" as the
     * tool option affords TPM2_OPTIONS_FAKE_TCTI.
     * 
     * If NVindex name is not specified and tcti is not none, it is expected
     * that the NV index is actually define. This behavior complies with the
     * backwards compatibility with 4.X
     */
    bool is_nv_name_specified = ctx.precalc_nvname.size;
    if (ctx.is_tcti_none && !is_nv_name_specified) {
        LOG_ERR("Must specify the NVIndex name.");
        return tool_rc_option_error;
    }

    if (!ctx.is_tcti_none && is_nv_name_specified) {
        LOG_ERR("Do not specify NV index name, it is directly read from NV");
        return tool_rc_option_error;
    }

    bool is_signer_name_specified = ctx.precalc_signername.size;
    if (ctx.is_tcti_none && !is_signer_name_specified) {
        LOG_ERR("Must specify the signing key name.");
        return tool_rc_option_error;
    }

    if (!ctx.is_tcti_none && is_signer_name_specified) {
        LOG_ERR("Do not specify signing key name, it is read from key handle");
        return tool_rc_option_error;
    }

    /*
     * Ensure that NV index is large enough for certifying data size at offset.
     */
    tool_rc rc = tool_rc_success;
    TPM2B_NV_PUBLIC *nv_public = 0;
    if (!ctx.is_tcti_none) {
        rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, 0, &nv_public, 0, 0, 0,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to access NVRAM public area at index 0x%X",
                    ctx.nv_index);
            goto is_input_options_args_valid_out;
        }

        if (ctx.offset + ctx.size > nv_public->nvPublic.dataSize) {
            LOG_ERR("Size to read at offset is bigger than nv index size");
            rc = tool_rc_option_error;
            goto is_input_options_args_valid_out;
        }
    }

is_input_options_args_valid_out:
    free(nv_public);
    return rc;
}

static bool on_arg(int argc, char **argv) {
    /*
     * If the user doesn't specify an authorization hierarchy use the index
     */
    if (!ctx.nvindex_authobj.ctx_path) {
        ctx.nvindex_authobj.ctx_path = argv[0];
    }
    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    bool result = true;
    uint32_t input_value;

    switch (key) {
    case 'C':
        ctx.signing_key.ctx_path = value;
        break;
    case 'P':
        ctx.signing_key.auth_str = value;
        break;
    case 'c':
        ctx.nvindex_authobj.ctx_path = value;
        break;
    case 'p':
        ctx.nvindex_authobj.auth_str = value;
        break;
    case 'g':
        result = set_digest_algorithm(value);
        ctx.is_sigscheme_halg_specified = true;
        goto on_option_out;
    case 's':
        result = set_signing_scheme(value);
        ctx.is_sigscheme_specified = true;
        goto on_option_out;
    case 'f':
        result = set_signature_format(value);
        goto on_option_out;
    case 'o':
        ctx.signature_path = value;
        break;
    case 'q':
        ctx.policy_qualifier_arg = value;
        break;
    case 0:
        result = tpm2_util_string_to_uint32(value, &input_value);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"", value);
            return false;
        }
        if (input_value > UINT16_MAX) {
            LOG_ERR("Specified size is larger than that allowed by command");
            return false;
        } else {
            ctx.size = input_value;
        }
        break;
    case 1:
        result = tpm2_util_string_to_uint32(value, &input_value);
        if (!result) {
            LOG_ERR("Could not convert offset to number, got: \"%s\"", value);
            return false;
        }
        if (input_value > UINT16_MAX) {
            LOG_ERR("Specified offset is larger than that allowed by command");
            return false;
        } else {
            ctx.offset = input_value;
        }
        break;
    case 2:
        ctx.certify_info_path = value;
        break;
    case 3:
        ctx.cp_hash_path = value;
        break;
    case 4:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
    case 'n':
        ctx.precalc_nvname.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q = tpm2_util_hex_to_byte_structure(value, &ctx.precalc_nvname.size,
        ctx.precalc_nvname.name);
        if (q) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
        break;
    case 5:
        ctx.precalc_signername.size = BUFFER_SIZE(TPM2B_NAME, name);
        int r = tpm2_util_hex_to_byte_structure(value,
            &ctx.precalc_signername.size, ctx.precalc_signername.name);
        if (r) {
            LOG_ERR("FAILED: %d", r);
            return false;
        }
        break;
    }

on_option_out:
    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "signingkey-context", required_argument, NULL, 'C' },
        { "signingkey-auth",    required_argument, NULL, 'P' },
        { "nvauthobj-context",  required_argument, NULL, 'c' },
        { "nvauthobj-auth",     required_argument, NULL, 'p' },
        { "hash-algorithm",     required_argument, NULL, 'g' },
        { "scheme",             required_argument, NULL, 's' },
        { "format",             required_argument, NULL, 'f' },
        { "signature",          required_argument, NULL, 'o' },
        { "qualification",      required_argument, NULL, 'q' },
        { "size",               required_argument, NULL,  0  },
        { "offset",             required_argument, NULL,  1  },
        { "attestation",        required_argument, NULL,  2  },
        { "cphash",             required_argument, NULL,  3  },
        { "rphash",             required_argument, NULL,  4  },
        { "session",            required_argument, NULL, 'S' },
        { "name",               required_argument, NULL, 'n' },
        { "signer-name",        required_argument, NULL,  5  },
    };

    *opts = tpm2_options_new("C:P:c:p:g:s:f:o:q:S:n:", ARRAY_LEN(topts), topts,
        on_option, on_arg, TPM2_OPTIONS_FAKE_TCTI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx, flags);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = nv_certify(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Free objects
     */
    Esys_Free(ctx.signature);
    Esys_Free(ctx.certify_info);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.signing_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.nvindex_authobj.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvcertify", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
