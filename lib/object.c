
#include <stdio.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tool_rc.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <tss2/tss2_mu.h>

#define NULL_OBJECT "null"
#define NULL_OBJECT_LEN (sizeof(NULL_OBJECT) - 1)

TPM2B_PRIVATE tpm2_util_object_tsspem_priv = { 0 };
TPM2B_PUBLIC tpm2_util_object_tsspem_pub = { 0 };

typedef struct {
    ASN1_OBJECT *type;
    ASN1_BOOLEAN emptyAuth;
    ASN1_INTEGER *parent;
    ASN1_OCTET_STRING *pubkey;
    ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY_OBJ;

ASN1_SEQUENCE(TSSPRIVKEY_OBJ) = {
    ASN1_SIMPLE(TSSPRIVKEY_OBJ, type, ASN1_OBJECT),
    ASN1_EXP_OPT(TSSPRIVKEY_OBJ, emptyAuth, ASN1_BOOLEAN, 0),
    ASN1_SIMPLE(TSSPRIVKEY_OBJ, parent, ASN1_INTEGER),
    ASN1_SIMPLE(TSSPRIVKEY_OBJ, pubkey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TSSPRIVKEY_OBJ, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY_OBJ)

#define OID_loadableKey "2.23.133.10.1.3"
#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY_OBJ);
IMPLEMENT_PEM_write_bio(TSSPRIVKEY_OBJ, TSSPRIVKEY_OBJ, TSSPRIVKEY_PEM_STRING,
    TSSPRIVKEY_OBJ);
IMPLEMENT_PEM_read_bio(TSSPRIVKEY_OBJ, TSSPRIVKEY_OBJ, TSSPRIVKEY_PEM_STRING,
    TSSPRIVKEY_OBJ);

tool_rc select_primary_template_alg(ESYS_CONTEXT *esys_ctx,
    TPM2_ALG_ID *alg_id) {

    tool_rc rc = tool_rc_success;
    TPMS_CAPABILITY_DATA *capability_data = NULL;
    TSS2_RC r = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS, NULL,
        &capability_data);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERR("Unable to fetch TPM supported algorithms");
        rc = tool_rc_general_error;
        goto ret;
    }

    TPM2_ALG_ID id = TPM2_ALG_NULL;
    for (uint32_t index = 0; index < capability_data->data.algorithms.count;
        index++) {
        if (capability_data->data.algorithms.algProperties[index].alg ==
        TPM2_ALG_ECC) {
            id = TPM2_ALG_ECC;
            break;
        }
    }

    if (id == TPM2_ALG_NULL) {
        id = TPM2_ALG_RSA;
    }
    *alg_id = id;

ret:
    Esys_Free(capability_data);
    return rc;
}

tool_rc setup_primary(ESYS_CONTEXT *esys_ctx, ESYS_TR *parent) {

    const TPM2B_PUBLIC *primary_template = NULL;

    const TPM2B_SENSITIVE_CREATE primary_sensitive = { 0 };

    const TPM2B_DATA all_outside_info = {
        .size = 0,
    };

    const TPML_PCR_SELECTION all_creation_PCR = {
        .count = 0,
    };

    static const TPM2B_PUBLIC primary_rsa_template = {
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                TPMA_OBJECT_RESTRICTED |
                                TPMA_OBJECT_DECRYPT |
                                TPMA_OBJECT_NODA |
                                TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
            }
        }
    };

    static const TPM2B_PUBLIC primary_ecc_template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                TPMA_OBJECT_RESTRICTED |
                                TPMA_OBJECT_DECRYPT |
                                TPMA_OBJECT_NODA |
                                TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                },
            },
            .unique.ecc = {
                .x.size = 0,
                .y.size = 0
            }
        }
    };

    TPM2_ALG_ID alg_id;
    tool_rc rc = select_primary_template_alg(esys_ctx, &alg_id);
    if (rc != tool_rc_success) {
        LOG_ERR("Unable to correctly select primary template");
        goto ret;
    }

    if (alg_id == TPM2_ALG_ECC) {
        primary_template = &primary_ecc_template;
    } else {
        primary_template = &primary_rsa_template;
    }

    TSS2_RC r = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
        ESYS_TR_NONE, ESYS_TR_NONE, &primary_sensitive, primary_template,
        &all_outside_info, &all_creation_PCR, parent, NULL, NULL, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERR("Unable to run create primary");
        rc = tool_rc_general_error;
        goto ret;
    }

ret:
    return rc;
}

static tool_rc tpm2_util_object_load_tsspem(ESYS_CONTEXT *ctx,
    const char *objectstr, tpm2_loaded_object *outobject) {

        tool_rc rc = tool_rc_success;
        TSSPRIVKEY_OBJ *tpk = NULL;
        BIO *input_bio = BIO_new_file(objectstr, "rb");
        if (!input_bio) {
            LOG_ERR("Unable to read as BIO file");
            rc = tool_rc_general_error;
            goto out;
        }

        /*
         * fetch out the various parts of the PEM file using openssl API
         */
        tpk = PEM_read_bio_TSSPRIVKEY_OBJ(input_bio, NULL, NULL, NULL);
        if (tpk == NULL) {
            LOG_ERR("Unable to read PEM from provided BIO/file");
            rc = tool_rc_general_error;
            goto out;
        }

        int pub_len = tpk->pubkey->length;
        int priv_len = tpk->privkey->length;

        rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(tpk->pubkey->data, pub_len,
            NULL, &tpm2_util_object_tsspem_pub);
        if (rc != tool_rc_success) {
            LOG_ERR("Error deserializing public portion of object");
            rc = tool_rc_general_error;
            goto out;
        }

        rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(tpk->privkey->data, priv_len,
            NULL, &tpm2_util_object_tsspem_priv);
        if (rc != tool_rc_success) {
            LOG_ERR("Error deserializing private portion of object");
            rc = tool_rc_general_error;
            goto out;
        }

        uint64_t val;
        int ret = ASN1_INTEGER_get_uint64(&val, tpk->parent);
        if (ret == 0 || val > UINT32_MAX) {
            LOG_ERR("Unable to convert parent to integer/value too large");
            rc = tool_rc_general_error;
            goto out;
        }

        bool is_persistent_parent = (val != TPM2_RH_OWNER && val != 0);
        if (!is_persistent_parent) {
            ESYS_TR obj_parent = ESYS_TR_NONE;
            rc = setup_primary(ctx, &obj_parent);
            if (rc != tool_rc_success) {
                LOG_ERR("Unable to create parent using createprimary");
                rc = tool_rc_general_error;
                goto out;
            }

            outobject->tr_handle = obj_parent;
            rc = Esys_TR_GetTpmHandle(ctx, obj_parent,
                &outobject->handle);
            if (rc != TSS2_RC_SUCCESS) {
                LOG_ERR("Unable to fetch TPM handle from ESYS TR handle");
                rc = tool_rc_general_error;
                goto out;
            }
        } else {
            ESYS_TR tr_parent = ESYS_TR_NONE;
            rc = tpm2_from_tpm_public(ctx, val, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &tr_parent);
            if (rc != tool_rc_success) {
                LOG_ERR("Unable to fetch TR Handle for persistent parent");
                rc = tool_rc_general_error;
                goto out;
            }

            outobject->tr_handle = tr_parent;
        }

out:
        if (tpk) {
            TSSPRIVKEY_OBJ_free(tpk);
        }
        if (input_bio) {
            BIO_free(input_bio);
        }

        return rc;
}


static tool_rc do_ctx_file(ESYS_CONTEXT *ctx, const char *objectstr, FILE *f,
        tpm2_loaded_object *outobject) {
    /* assign a dummy transient handle */
    outobject->handle = TPM2_TRANSIENT_FIRST;
    outobject->path = objectstr;
    return files_load_tpm_context_from_file(ctx, &outobject->tr_handle, f);
}

static tool_rc tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, bool do_auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    tool_rc rc = tool_rc_success;
    if (do_auth) {
        ESYS_CONTEXT *tmp_ctx = is_restricted_pswd_session ? NULL : ctx;
        tpm2_session *s = NULL;
        rc = tpm2_auth_util_from_optarg(tmp_ctx, auth, &s,
                is_restricted_pswd_session);
        if (rc != tool_rc_success) {
            return rc;
        }

        outobject->session = s;
    }

    if (!objectstr) {
        LOG_ERR("object string is empty");
        return tool_rc_general_error;
    }

    // 1. Attempt objectstr as a file path for context file.
    FILE *f = fopen(objectstr, "rb");
    if (f) {
        rc = do_ctx_file(ctx, objectstr, f, outobject);
        fclose(f);
        if (rc == tool_rc_success) {
            return rc;
        }
    }

    // 2. Attempt converting objectstr to a hierarchy or raw handle
    TPMI_RH_PROVISION handle;
    bool result = tpm2_util_handle_from_optarg(objectstr, &handle, flags);
    if (result) {
        outobject->handle = handle;
        outobject->path = NULL;
        return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle,
            &outobject->tr_handle);
    }

    // 3. Attempt objectstr as a file path for TSSPEM/ TSS-PRIVATE-KEY
    rc = tpm2_util_object_load_tsspem(ctx, objectstr, outobject);
    if (rc != tool_rc_success) {
        LOG_ERR("Cannot make sense of object context \"%s\"", objectstr);
    }

    return rc;
}

tool_rc tpm2_util_object_load(ESYS_CONTEXT *ctx, const char *objectstr,
        tpm2_loaded_object *outobject, tpm2_handle_flags flags) {

    return tpm2_util_object_load2(ctx, objectstr, NULL, false, outobject,
        false, flags);
}

tool_rc tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    return tpm2_util_object_load2(ctx, objectstr, auth, true, outobject,
            is_restricted_pswd_session, flags);
}
