/* SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include <yaml.h>

#include "log.h"
#include "tool_rc.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_yaml.h"

struct tpm2_yaml {
    yaml_document_t doc;
    int root;
};

#define null_ret(ptr, val) \
    if (!ptr) { \
        return val; \
    }

#define return_rc(rc) do { if (!rc) { return rc; } } while (0)

typedef struct key_value key_value;
struct key_value {
    const char *key;
    union {
        const char *as_str;
        const TPM2B *as_tpm2b;
        uint64_t as_int;
    } value;
    const yaml_char_t *tag;
};

#define TPM2B_TAG "TPM2B_TAG"

#define KVP_ADD_STR(k, v) {.key = k, .tag = YAML_STR_TAG, .value = { .as_str = v}}
#define KVP_ADD_INT(k, v) {.key = k, .tag = YAML_INT_TAG, .value = { .as_int = v}}
#define KVP_ADD_TPM2B(k, v) {.key = k, .tag = TPM2B_TAG, .value = { .as_tpm2b = (TPM2B *)v}}

tpm2_yaml *tpm2_yaml_new(void) {

    tpm2_yaml *t = calloc(1, sizeof(*t));
    if (!t) {
        return t;
    }

    int rc = yaml_document_initialize(
            &t->doc,
            NULL, /* version */
            NULL, /* start */
            NULL, /* end */
            1, /* implicit start */
            1 /* implicit end */);
    if (!rc) {
        LOG_ERR("Could not initialize YAML document");
        free(t);
        return NULL;
    }

    t->root = yaml_document_add_mapping(&t->doc, NULL, YAML_ANY_MAPPING_STYLE);
    if (!t->root) {
        LOG_ERR("Could not add YAML root node");
        free(t);
        return NULL;
    }

    return t;
}

void tpm2_yaml_free(tpm2_yaml *y) {

    if (!y) {
        return;
    }

    yaml_document_delete(&y->doc);
    free(y);
}

#define yaml_add_str(doc, str) \
        yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG, \
                    (yaml_char_t *)str, -1, YAML_ANY_SCALAR_STYLE);

static int yaml_add_int(yaml_document_t *doc, uint64_t data) {

    /*
     * 8 bytes for 64 bit nums, times two for 2 chars per byte in hex,
     * and a nul byte
     */
    char buf[8 * 2 + 1] = { 0 };

    snprintf(buf, sizeof(buf), "0x%"PRIx64, data);

    return yaml_document_add_scalar(doc, (yaml_char_t *)YAML_INT_TAG, \
                        (yaml_char_t *)buf, -1, YAML_ANY_SCALAR_STYLE);
}

static int yaml_add_tpm2b(yaml_document_t *doc, const TPM2B *data) {

    char *h = tpm2_util_bin2hex(data->buffer, data->size);
    if (!h) {
        LOG_ERR("oom");
        return 0;
    }
    int node = yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG,
            h, -1, YAML_ANY_SCALAR_STYLE);
    free(h);

    return node;
}

static int add_kvp(yaml_document_t *doc, int root, const key_value *k) {

    if (strcmp(k->tag, TPM2B_TAG) == 0 && k->value.as_tpm2b->size == 0) {
        return 1;
    }

    int key = yaml_document_add_scalar(doc, YAML_STR_TAG, \
                (yaml_char_t *)k->key, -1, YAML_ANY_SCALAR_STYLE);
    return_rc(key);

    int value = 0;
    if (strcmp(k->tag, YAML_STR_TAG) == 0) {
        value = yaml_add_str(doc, k->value.as_str);
    } else if (strcmp(k->tag, YAML_INT_TAG) == 0) {
        value = yaml_add_int(doc, k->value.as_int);
    } else if (strcmp(k->tag, TPM2B_TAG) == 0) {
        value = yaml_add_tpm2b(doc, k->value.as_tpm2b);
    } else {
        LOG_ERR("Unknown tag type: %s", k->tag ? (char *)k->tag : "(null)");
        return 0;
    }
    return_rc(value);

    int rc = yaml_document_append_mapping_pair(doc, root, key, value);
    return_rc(rc);
}

static int add_mapping_root_with_items(yaml_document_t *doc, int root,
        const char *mapkey, const key_value *kvs, size_t len) {

    int sub_root = yaml_document_add_mapping(doc,
            (yaml_char_t *)YAML_MAP_TAG, YAML_ANY_MAPPING_STYLE);
    return_rc(sub_root);

    int sub_root_key = yaml_add_str(doc, mapkey);
    return_rc(sub_root_key);

    size_t i;
    for(i=0; i < len; i++) {
        const key_value *k = &kvs[i];
        return_rc(add_kvp(doc, sub_root, k));
    }

    return yaml_document_append_mapping_pair(doc, root, sub_root_key, sub_root);
}

static int add_alg(yaml_document_t *doc, int root, const char *key, TPM2_ALG_ID alg) {
    key_value scheme_kvs[] = {
        KVP_ADD_STR("value", tpm2_alg_util_algtostr(alg, tpm2_alg_util_flags_any)),
        KVP_ADD_INT("raw", alg),
    };

    return add_mapping_root_with_items(doc, root, key,
            scheme_kvs, ARRAY_LEN(scheme_kvs));
}

static tool_rc tpm2b_name_to_yaml(const TPM2B_NAME *name, yaml_document_t *doc, int root) {

    struct key_value key_bits = KVP_ADD_TPM2B("name", name);
    return add_kvp(doc, root, &key_bits);
}

tool_rc tpm2_yaml_tpm2b_name(const TPM2B_NAME *name, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(name);
    return tpm2b_name_to_yaml(name, &y->doc, y->root);
}

static int tpmt_sym_def_object_to_yaml(yaml_document_t *doc,
        int root, const TPMT_SYM_DEF_OBJECT *sym) {

    /*
     * sym-alg:
     *   value: aes
     *   raw: 0x6
     * sym-mode:
     *   value: null
     *   raw: 0x10
     * sym-keybits: 128
     */
    int rc = add_alg(doc, root, "sym-alg", sym->algorithm);
    return_rc(rc);

    key_value sym_mode_kvs[] = {
            KVP_ADD_STR("value", tpm2_alg_util_algtostr(sym->mode.sym, tpm2_alg_util_flags_any)),
            KVP_ADD_INT("raw", sym->mode.sym),
    };

    rc = add_alg(doc, root, "sym-mode", sym->mode.sym);
    return_rc(rc);

    struct key_value key_bits = KVP_ADD_INT("sym-keybits", sym->keyBits.sym);
    return add_kvp(doc, root, &key_bits);
}

static int tpms_keyedhash_parms_to_yaml(yaml_document_t *doc, int root, const TPMS_KEYEDHASH_PARMS *k) {

    /*
     * algorithm:
     *   value:
     *   raw:
     */
    int rc = add_alg(doc, root, "algorithm", k->scheme.scheme);
    return_rc(rc);

    switch(k->scheme.scheme) {
    case TPM2_ALG_HMAC:

        rc = add_alg(doc, root, "hash-alg", k->scheme.details.hmac.hashAlg);
        break;
    case TPM2_ALG_XOR:

        rc = add_alg(doc, root, "hash-alg", k->scheme.details.exclusiveOr.hashAlg);
        return_rc(rc);

        rc = add_alg(doc, root, "kdfa-alg", k->scheme.details.exclusiveOr.kdf);
        break;
    default:
        LOG_ERR("Unknown scheme: 0x%x", k->scheme.scheme);
        rc = 0;
    }

    return rc;
}

static int tpms_rsa_parms_to_yaml(yaml_document_t *doc, int root, const TPMS_RSA_PARMS *r) {

    /*
     * exponent: 65537
     * bits: 2048
     * scheme:
     *   value:
     *   raw:
     * schme-halg<optional>:
     *   value: sha256
     *   raw: 0xb
     *   TODO BILL FILL OUT
     */
    key_value exponent = KVP_ADD_INT("exponent", r->exponent ? r->exponent : 65537);
    int rc = add_kvp(doc, root, &exponent);
    return_rc(rc);

    key_value bits = KVP_ADD_INT("bits", r->keyBits);
    rc = add_kvp(doc, root, &bits);
    return_rc(rc);

    rc = add_alg(doc, root, "scheme", r->scheme.scheme);

    /*
     * everything is a union on a hash algorithm except for RSAES which
     * has nothing. So on RSAES skip the hash algorithm printing
     */
    if (r->scheme.scheme != TPM2_ALG_RSAES) {
        rc = add_alg(doc, root, "scheme-halg", r->scheme.details.anySig.hashAlg);
    }

    return tpmt_sym_def_object_to_yaml(doc, root, &r->symmetric);
}

static int tpmt_kdf_scheme(yaml_document_t *doc, int root, const TPMT_KDF_SCHEME *s) {

        /*
         * kdfa-alg:
         *   value:
         *   raw:
         * kdfa-halg:
         *   value:
         *   raw:
         */
        int rc = add_alg(doc, root, "kdfa-alg", s->scheme);
        return_rc(rc);

        return add_alg(doc, root, "kdfa-halg", s->details.mgf1.hashAlg);
}

static int tpmt_scheme_to_yaml(yaml_document_t *doc, int root, const TPMT_ECC_SCHEME *scheme) {

    /*
     * scheme:
     *   value:
     *   raw:
     * scheme-halg:
     *   value:
     *   raw:
     * scheme-count<optional>: 2
     */

    int rc = add_alg(doc, root, "scheme", scheme->scheme);
    return_rc(rc);

    rc = add_alg(doc, root, "scheme-halg", scheme->details.anySig.hashAlg);
    return_rc(rc);

    /*
     * everything but ecdaa uses only hash alg
     * in a union, so we only need to do things differently
     * for ecdaa.
     */
    if (scheme->scheme == TPM2_ALG_ECDAA) {
        struct key_value key_bits = KVP_ADD_INT("scheme-count", scheme->details.ecdaa.count);
        rc = add_kvp(doc, root, &key_bits);
    }

    return rc;
}

static int tpms_ecc_parms_to_yaml(yaml_document_t *doc, int root, const TPMS_ECC_PARMS *e) {

    /*
     * curve-id:
     *   value:
     *   raw:
     *   value:
     *   raw:
     * kdfa-halg:
     *   value:
     *   raw:
     * scheme:
     *   value:
     *   raw:
     * scheme-halg:
     *   value:
     *   raw:
     * scheme-count<optional>: 2
     * sym-alg:
     *   value: aes
     *   raw: 0x6
     * sym-mode:
     *   value: null
     *   raw: 0x10
     * sym-keybits: 128
     */

    key_value curve_id_kvs[] = {
        KVP_ADD_STR("value", tpm2_alg_util_algtostr(e->curveID, tpm2_alg_util_flags_any)),
        KVP_ADD_INT("raw", e->curveID),
    };

    int rc = add_mapping_root_with_items(doc, root, "curve-id",
            curve_id_kvs, ARRAY_LEN(curve_id_kvs));
    return_rc(rc);

    rc = tpmt_kdf_scheme(doc, root, &e->kdf);
    return_rc(rc);

    rc = tpmt_scheme_to_yaml(doc, root, &e->scheme);
    return_rc(rc);

    return tpmt_sym_def_object_to_yaml(doc, root, &e->symmetric);
}

static int tpmt_public_to_yaml(const TPMT_PUBLIC *public,
        yaml_document_t *doc, int root) {

    /* name-alg:
     *   value: sha256
     *   raw: 0x0b
     */
    int rc = add_alg(doc, root, "name-alg", public->nameAlg);
    return_rc(rc);

    /*
     * attributes:
     *   value: sign|restricted
     *   raw: 0x42
     */
    char *attrs = tpm2_attr_util_obj_attrtostr(public->objectAttributes);
    if (!attrs) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    key_value object_attrs[] = {
        KVP_ADD_STR("value", attrs),
        KVP_ADD_INT("raw", public->objectAttributes)
    };

    rc = add_mapping_root_with_items(doc, root, "attributes",
            object_attrs, ARRAY_LEN(object_attrs));
    free(attrs);
    return_rc(rc);

    /*
     * type:
     *   value: symcipher
     *   raw: 0x25
     */
    key_value type[] = {
        KVP_ADD_STR("value", tpm2_alg_util_algtostr(public->type, tpm2_alg_util_flags_any)),
        KVP_ADD_INT("raw", public->type)
    };

    rc = add_alg(doc, root, "type", public->type);
    return_rc(rc);

    key_value keydata[2] = { 0 };
    size_t keydata_len = 0;

    switch(public->type) {
    case TPM2_ALG_SYMCIPHER: {
        rc = tpmt_sym_def_object_to_yaml(doc, root, &public->parameters.symDetail.sym);
        key_value tmp = KVP_ADD_TPM2B("symcipher", &public->unique.sym);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_KEYEDHASH: {
        rc = tpms_keyedhash_parms_to_yaml(doc, root, &public->parameters.keyedHashDetail);
        key_value tmp = KVP_ADD_TPM2B("keyedhash", &public->unique.keyedHash);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_RSA: {
        LOG_ERR("need RSA support");
        rc = tpms_rsa_parms_to_yaml(doc, root, &public->parameters.rsaDetail);
        key_value tmp = KVP_ADD_TPM2B("rsa", &public->unique.rsa);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_ECC:
        rc = tpms_ecc_parms_to_yaml(doc, root, &public->parameters.eccDetail);
        key_value tmp[2] = {
            KVP_ADD_TPM2B("x", &public->unique.ecc.x),
            KVP_ADD_TPM2B("y", &public->unique.ecc.y),
        };
        memcpy(keydata, tmp, sizeof(tmp));
        keydata_len = 2;
        break;
    default:
        LOG_ERR("Unknown key type: 0x%x", public->type);
        return tool_rc_general_error;
    }

    /*
     * rsa|keyedhash|symcipher: <hex> OR
     * ecc:
     *   x: <hex>
     *   y: <hex>
     */
    rc = add_mapping_root_with_items(doc, root, "keydata",
            keydata, keydata_len);

    /*
     * authorization policy: <hex>
     */
    key_value auth_data =
        KVP_ADD_TPM2B("authorization data", &public->authPolicy);

    return add_kvp(doc, root, &auth_data);
}

tool_rc tpm2_yaml_tpmt_public(tpm2_yaml *y, const TPMT_PUBLIC *public) {
    null_ret(y, 1);
    assert(public);

    int r = tpmt_public_to_yaml(public,
            &y->doc, y->root);
    return  r ? tool_rc_success: tool_rc_general_error;
}

tool_rc tpm2_yaml_dump(tpm2_yaml *y, FILE *f) {

    tool_rc rc = tool_rc_general_error;

    yaml_emitter_t emitter = { 0 };
    int r = yaml_emitter_initialize(&emitter);
    if (!r) {
        LOG_ERR("Could not initialize YAML emitter");
        return tool_rc_general_error;
    }

    //yaml_emitter_set_canonical(&emitter, 1);

    yaml_emitter_set_output_file(&emitter, f);

    r = yaml_emitter_dump(&emitter, &y->doc);
    if (!r) {
        LOG_ERR("Could not dump YAML");
        goto err;
    }

    r = yaml_emitter_close(&emitter);
    if (!r) {
        LOG_ERR("Could not close YAML emitter");
        goto err;
    }

    rc = tool_rc_success;
err:

    yaml_emitter_delete(&emitter);
    return rc;
}
