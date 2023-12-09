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
    int canonical;
    int written;
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
    unsigned base;
    const yaml_char_t *tag;
};

#define TPM2B_TAG "TPM2B_TAG"

#define KVP_ADD_STR(k, v) {.key = k, .tag = YAML_STR_TAG, .value = { .as_str = v}}
#define KVP_ADD_HEX(k, v) {.key = k, .tag = YAML_INT_TAG, .value = { .as_int = v}, .base = 16}
#define KVP_ADD_INT(k, v) {.key = k, .tag = YAML_INT_TAG, .value = { .as_int = v}, .base = 10}
#define KVP_ADD_TPM2B(k, v) {.key = k, .tag = TPM2B_TAG, .value = { .as_tpm2b = (TPM2B *)v}}

typedef struct list list;
struct list {
    union {
        const char *as_str;
        const TPM2B *as_tpm2b;
        uint64_t as_int;
    } value;
    unsigned base;
    const yaml_char_t *tag;
};

tpm2_yaml *tpm2_yaml_new(int canonical) {

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


    if (canonical) {
        t->canonical = 1;
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

#define NULL_STR "(null)"

/*
 * IMPORTANT All base add functions for types MUST set the written flag
 * or output will be an empty document of {}.
 */
static int yaml_add_str(tpm2_yaml *y, const char *str) {
    y->written = 1;
    return yaml_document_add_scalar(&y->doc, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)str ? str : NULL_STR, -1, YAML_ANY_SCALAR_STYLE);
}

static int yaml_add_int(tpm2_yaml *y, uint64_t data, unsigned base) {

    /*
     * 8 bytes for 64 bit nums, times two for 2 chars per byte in hex,
     * and a nul byte
     */
    char buf[8 * 2 + 1] = { 0 };

    const char *fmt = NULL;
    switch(base) {
    case 10:
        fmt = "%"PRIu64;
        break;
    case 16:
        fmt = "0x%"PRIx64;
        break;
    default:
        LOG_ERR("Cannot handle integer base: %u", base);
        return 0;
    }

    snprintf(buf, sizeof(buf), fmt, data);

    /* prevents something like !!int always being tagged on ints unless canonical is set */
    yaml_char_t *tag = y->canonical ? YAML_INT_TAG : YAML_STR_TAG;

    y->written = 1;
    return yaml_document_add_scalar(&y->doc, (yaml_char_t *)tag, \
                        (yaml_char_t *)buf, -1, YAML_ANY_SCALAR_STYLE);
}

static int yaml_add_tpm2b(tpm2_yaml *y, const TPM2B *data) {

    char *h = tpm2_util_bin2hex(data->buffer, data->size);
    if (!h) {
        LOG_ERR("oom");
        return 0;
    }
    y->written = 1;
    int node = yaml_document_add_scalar(&y->doc, (yaml_char_t *)YAML_STR_TAG,
            h, -1, YAML_ANY_SCALAR_STYLE);
    free(h);

    return node;
}

static int add_kvp(tpm2_yaml *y, int root, const key_value *k) {

    if (strcmp(k->tag, TPM2B_TAG) == 0 && k->value.as_tpm2b->size == 0) {
        return 1;
    }

    int key = yaml_document_add_scalar(&y->doc, YAML_STR_TAG, \
                (yaml_char_t *)k->key, -1, YAML_ANY_SCALAR_STYLE);
    return_rc(key);

    int value = 0;
    if (strcmp(k->tag, YAML_STR_TAG) == 0) {
        value = yaml_add_str(y, k->value.as_str);
    } else if (strcmp(k->tag, YAML_INT_TAG) == 0) {
        value = yaml_add_int(y, k->value.as_int, k->base);
    } else if (strcmp(k->tag, TPM2B_TAG) == 0) {
        value = yaml_add_tpm2b(y, k->value.as_tpm2b);
    } else {
        LOG_ERR("Unknown tag type: %s", k->tag ? (char *)k->tag : "(null)");
        return 0;
    }
    return_rc(value);

    int rc = yaml_document_append_mapping_pair(&y->doc, root, key, value);
    return_rc(rc);
}

static int add_kvp_list(tpm2_yaml *y, int root, const key_value *kvs, size_t len) {

    size_t i;
    for(i=0; i < len; i++) {
        const key_value *k = &kvs[i];
        return_rc(add_kvp(y, root, k));
    }

    return 1;
}

static int add_lst(tpm2_yaml *y, int root, const list *l) {

    if (strcmp(l->tag, TPM2B_TAG) == 0 && l->value.as_tpm2b->size == 0) {
        return 1;
    }

    int value = 0;
    if (strcmp(l->tag, YAML_STR_TAG) == 0) {
        value = yaml_add_str(y, l->value.as_str);
    } else if (strcmp(l->tag, YAML_INT_TAG) == 0) {
        value = yaml_add_int(y, l->value.as_int, l->base);
    } else if (strcmp(l->tag, TPM2B_TAG) == 0) {
        value = yaml_add_tpm2b(y, l->value.as_tpm2b);
    } else {
        LOG_ERR("Unknown tag type: %s", l->tag ? (char *)l->tag : "(null)");
        return 0;
    }
    return_rc(value);

    int rc = yaml_document_append_sequence_item(&y->doc, root, value);
    return_rc(rc);
}

static int add_sequence_root_with_items(tpm2_yaml *y, int root,
        const char *mapkey, const list *lst, size_t len) {

    int sub_root = yaml_document_add_sequence(&y->doc,
            YAML_SEQ_TAG, YAML_ANY_SEQUENCE_STYLE);
    return_rc(sub_root);

    size_t i;
    for(i=0; i < len; i++) {
        const list *x = &lst[i];
        return_rc(add_lst(y, sub_root, x));
    }

    int sub_root_key = yaml_add_str(y, mapkey);
    return_rc(sub_root_key);

    return yaml_document_append_mapping_pair(&y->doc, root, sub_root_key, sub_root);
}


static int add_mapping_root_with_items(tpm2_yaml *y, int root,
        const char *mapkey, const key_value *kvs, size_t len) {

    int sub_root = yaml_document_add_mapping(&y->doc,
            (yaml_char_t *)YAML_MAP_TAG, YAML_ANY_MAPPING_STYLE);
    return_rc(sub_root);

    int sub_root_key = yaml_add_str(y, mapkey);
    return_rc(sub_root_key);

    int rc = add_kvp_list(y, sub_root, kvs, len);
    return_rc(rc);

    return yaml_document_append_mapping_pair(&y->doc, root, sub_root_key, sub_root);
}

static int add_alg(tpm2_yaml *y, int root, const char *key, TPM2_ALG_ID alg) {

    key_value scheme_kvs[] = {
        KVP_ADD_STR("value", tpm2_alg_util_algtostr(alg, tpm2_alg_util_flags_any)),
        KVP_ADD_HEX("raw", alg),
    };

    return add_mapping_root_with_items(y, root, key,
            scheme_kvs, ARRAY_LEN(scheme_kvs));
}

static tool_rc tpm2b_to_yaml(tpm2_yaml *y, int root, const char *key, const TPM2B_NAME *name) {

    struct key_value key_bits = KVP_ADD_TPM2B(key, name);
    int rc = add_kvp(y, root, &key_bits);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_tpm2b_name(const TPM2B_NAME *name, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(name);
    return tpm2b_to_yaml(y, y->root, "name", name);
}

tool_rc tpm2_yaml_qualified_name(const TPM2B_NAME *qname, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(qname);
    return tpm2b_to_yaml(y, y->root, "qualified name", qname);
}

static int tpmt_sym_def_object_to_yaml(tpm2_yaml *y,
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
    int rc = add_alg(y, root, "sym-alg", sym->algorithm);
    return_rc(rc);

    rc = add_alg(y, root, "sym-mode", sym->mode.sym);
    return_rc(rc);

    struct key_value key_bits = KVP_ADD_INT("sym-keybits", sym->keyBits.sym);
    return add_kvp(y, root, &key_bits);
}

static int tpms_keyedhash_parms_to_yaml(tpm2_yaml *y, int root, const TPMS_KEYEDHASH_PARMS *k) {

    /*
     * algorithm:
     *   value:
     *   raw:
     */
    int rc = add_alg(y, root, "algorithm", k->scheme.scheme);
    return_rc(rc);

    switch(k->scheme.scheme) {
    case TPM2_ALG_HMAC:

        rc = add_alg(y, root, "hash-alg", k->scheme.details.hmac.hashAlg);
        break;
    case TPM2_ALG_XOR:

        rc = add_alg(y, root, "hash-alg", k->scheme.details.exclusiveOr.hashAlg);
        return_rc(rc);

        rc = add_alg(y, root, "kdfa-alg", k->scheme.details.exclusiveOr.kdf);
        break;
    default:
        LOG_ERR("Unknown scheme: 0x%x", k->scheme.scheme);
        rc = 0;
    }

    return rc;
}

static int tpms_rsa_parms_to_yaml(tpm2_yaml *y, int root, const TPMS_RSA_PARMS *r) {

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
    int rc = add_kvp(y, root, &exponent);
    return_rc(rc);

    key_value bits = KVP_ADD_INT("bits", r->keyBits);
    rc = add_kvp(y, root, &bits);
    return_rc(rc);

    rc = add_alg(y, root, "scheme", r->scheme.scheme);

    /*
     * everything is a union on a hash algorithm except for RSAES which
     * has nothing. So on RSAES skip the hash algorithm printing
     */
    if (r->scheme.scheme != TPM2_ALG_RSAES) {
        rc = add_alg(y, root, "scheme-halg", r->scheme.details.anySig.hashAlg);
    }

    return tpmt_sym_def_object_to_yaml(y, root, &r->symmetric);
}

static int tpmt_kdf_scheme(tpm2_yaml *y, int root, const TPMT_KDF_SCHEME *s) {

        /*
         * kdfa-alg:
         *   value:
         *   raw:
         * kdfa-halg:
         *   value:
         *   raw:
         */
        int rc = add_alg(y, root, "kdfa-alg", s->scheme);
        return_rc(rc);

        return add_alg(y, root, "kdfa-halg", s->details.mgf1.hashAlg);
}

static int tpmt_scheme_to_yaml(tpm2_yaml *y, int root, const TPMT_ECC_SCHEME *scheme) {

    /*
     * scheme:
     *   value:
     *   raw:
     * scheme-halg:
     *   value:
     *   raw:    struct key_value key_bits = KVP_ADD_TPM2B(key, name);
    int rc = add_kvp(y, root, &key_bits);
    return rc ? tool_rc_success : tool_rc_general_error;
     * scheme-count<optional>: 2
     */

    int rc = add_alg(y, root, "scheme", scheme->scheme);
    return_rc(rc);

    rc = add_alg(y, root, "scheme-halg", scheme->details.anySig.hashAlg);
    return_rc(rc);

    /*
     * everything but ecdaa uses only hash alg
     * in a union, so we only need to do things differently
     * for ecdaa.
     */
    if (scheme->scheme == TPM2_ALG_ECDAA) {
        struct key_value key_bits = KVP_ADD_INT("scheme-count", scheme->details.ecdaa.count);
        rc = add_kvp(y, root, &key_bits);
    }

    return rc;
}

static int tpms_ecc_parms_to_yaml(tpm2_yaml *y, int root, const TPMS_ECC_PARMS *e) {

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
    int rc = add_alg(y, root, "curve-id", e->curveID);
    return_rc(rc);

    rc = tpmt_kdf_scheme(y, root, &e->kdf);
    return_rc(rc);

    rc = tpmt_scheme_to_yaml(y, root, &e->scheme);
    return_rc(rc);

    return tpmt_sym_def_object_to_yaml(y, root, &e->symmetric);
}

static int tpmt_public_to_yaml(const TPMT_PUBLIC *public,
        tpm2_yaml *y, int root) {

    /* name-alg:
     *   value: sha256
     *   raw: 0x0b
     */
    int rc = add_alg(y, root, "name-alg", public->nameAlg);
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
        KVP_ADD_HEX("raw", public->objectAttributes)
    };

    rc = add_mapping_root_with_items(y, root, "attributes",
            object_attrs, ARRAY_LEN(object_attrs));
    free(attrs);
    return_rc(rc);

    /*
     * type:
     *   value: symcipher
     *   raw: 0x25
     */
    rc = add_alg(y, root, "type", public->type);
    return_rc(rc);

    key_value keydata[2] = { 0 };
    size_t keydata_len = 0;

    switch(public->type) {
    case TPM2_ALG_SYMCIPHER: {
        rc = tpmt_sym_def_object_to_yaml(y, root, &public->parameters.symDetail.sym);
        key_value tmp = KVP_ADD_TPM2B("symcipher", &public->unique.sym);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_KEYEDHASH: {
        rc = tpms_keyedhash_parms_to_yaml(y, root, &public->parameters.keyedHashDetail);
        key_value tmp = KVP_ADD_TPM2B("keyedhash", &public->unique.keyedHash);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_RSA: {
        rc = tpms_rsa_parms_to_yaml(y, root, &public->parameters.rsaDetail);
        key_value tmp = KVP_ADD_TPM2B("rsa", &public->unique.rsa);
        keydata[0] = tmp;
        keydata_len = 1;
    } break;
    case TPM2_ALG_ECC:
        rc = tpms_ecc_parms_to_yaml(y, root, &public->parameters.eccDetail);
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
    rc = add_kvp_list(y, root, keydata, keydata_len);
    return_rc(rc);

    /*
     * authorization policy: <hex>
     */
    key_value auth_data =
        KVP_ADD_TPM2B("authorization data", &public->authPolicy);

    return add_kvp(y, root, &auth_data);
}

tool_rc tpm2_yaml_tpmt_public(tpm2_yaml *y, const TPMT_PUBLIC *public) {
    null_ret(y, 1);
    assert(public);

    int r = tpmt_public_to_yaml(public,
            y, y->root);
    return  r ? tool_rc_success: tool_rc_general_error;
}

static int add_tpml_algs(tpm2_yaml *y, const char *seqkey, const TPML_ALG *alg_list) {

    if (alg_list->count == 0 ||
            alg_list->count > ARRAY_LEN(alg_list->algorithms)) {
        return 0;
    }

    size_t cnt = alg_list->count;
    list *lst = calloc(alg_list->count, sizeof(*lst));
    if (!lst) {
        return 0;
    }

    /* convert to friendly names */
    size_t i;
    for (i=0; i < cnt; i++) {
        lst[i].tag = YAML_STR_TAG;
        lst[i].value.as_str = tpm2_alg_util_algtostr(alg_list->algorithms[i],
                tpm2_alg_util_flags_any);
    }

    int r = add_sequence_root_with_items(y, y->root, seqkey, lst, cnt);
    free(lst);
    return r;
}

/* XXX guess on scalar name, might be a candiate for removal */
tool_rc tpm2_yaml_tpml_alg(tpm2_yaml *y, const TPML_ALG *alg_list) {
    null_ret(y, 1);
    assert(alg_list);

    return add_tpml_algs(y, "algorithms", alg_list) ?
            tool_rc_general_error : tool_rc_success;
}

tool_rc tpm2_yaml_tpm_alg_todo(tpm2_yaml *y, const TPML_ALG *to_do_list) {
    null_ret(y, 1);
    assert(to_do_list);

    /*
     * status: success
     * remaining:
     * - tdes
     * - sha384
     * - rsassa
     * --- OR ---
     * status: complete
     */

    const char *value = to_do_list->count == 0 ? "complete" : "success";

    struct key_value status = KVP_ADD_STR("status", value);
    int r = add_kvp(y, y->root, &status);
    if (!r) {
        return tool_rc_general_error;
    }

    if (to_do_list->count == 0) {
        return tool_rc_success;
    }

    return add_tpml_algs(y, "remaining", to_do_list) ?
            tool_rc_success : tool_rc_general_error;

}

tool_rc tpm2_yaml_tpm2_nv_index(tpm2_yaml *y, TPM2_NV_INDEX index) {

    struct key_value kvp = KVP_ADD_HEX("nv-index", index);
    return add_kvp(y, y->root, &kvp)  ?
            tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_dump(tpm2_yaml *y, FILE *f) {
    assert(y);
    assert(f);
    tool_rc rc = tool_rc_general_error;

    if (!y->written) {
        return tool_rc_success;
    }

    yaml_emitter_t emitter = { 0 };
    int r = yaml_emitter_initialize(&emitter);
    if (!r) {
        LOG_ERR("Could not initialize YAML emitter");
        return tool_rc_general_error;
    }

    yaml_emitter_set_canonical(&emitter, y->canonical);

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
