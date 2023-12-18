/* SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include <yaml.h>

#include <tss2/tss2_mu.h>

#include "log.h"
#include "tool_rc.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_convert.h"
#include "tpm2_yaml.h"

#define MAX_YAML_STACK 5

typedef struct tpm2_yaml_stack_object tpm2_yaml_stack_object;
struct tpm2_yaml_stack_object {
    int index;
    tpm2_yaml_stack_object_t type;
    char *name;
};

struct tpm2_yaml {
    yaml_document_t doc;
    int root;
    int canonical;
    int written;
    tpm2_yaml_stack_object object_stack[MAX_YAML_STACK];
    int stack_idx;
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
    t->stack_idx = 0;
    t->object_stack[0].index = t->root;
    t->object_stack[0].type = yaml_mapping;
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
     * and a nul byte and extra bytes for the fmt string
     */
    char buf[128] = { 0 };

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

    /* prefix bytes of 0x and nul byte */
    size_t len = strlen(h) + 2 + 1;
    char *prefixed = calloc(1, len);
    if (!prefixed) {
        free(h);
        return 0;
    }
    snprintf(prefixed, len, "0x%s", h);
    free(h);

    y->written = 1;
    int node = yaml_document_add_scalar(&y->doc, (yaml_char_t *)YAML_STR_TAG,
            prefixed, -1, YAML_ANY_SCALAR_STYLE);
    free(prefixed);

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

    return yaml_document_append_mapping_pair(&y->doc, root, key, value);
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

    return yaml_document_append_sequence_item(&y->doc, root, value);
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

static int add_sig_hex(tpm2_yaml *y, int root, const char *key, TPMT_SIGNATURE *sig) {


    TPM2B_MAX_BUFFER tmp = { 0 };
    BYTE *sig_bin = tpm2_convert_sig(&tmp.size, sig);
    if (!sig_bin) {
        return tool_rc_general_error;
    }
    memcpy(tmp.buffer, sig_bin, tmp.size);

    key_value sig_kvs[] =
        {
         KVP_ADD_STR("alg", tpm2_alg_util_algtostr(sig->sigAlg, tpm2_alg_util_flags_sig)),
         KVP_ADD_TPM2B("sig", &tmp),
        };

    return add_mapping_root_with_items(y, root, key,
            sig_kvs, ARRAY_LEN(sig_kvs));
}

static int tpms_time_info_to_yaml(tpm2_yaml *y, int root,
                                  const TPMS_TIME_INFO *time_info) {
    /* time: 105594980
     */
    struct key_value key_time = KVP_ADD_INT("time", time_info->time);
    int rc = add_kvp(y, root, &key_time);
    return_rc(rc);

    /* clock_info:
     *   clock: 128285828
     *   reset_count: 1
     *   restart_count: 0
     *   safe: yes
     */

    key_value clock_info[] = {
        KVP_ADD_INT("clock", time_info->clockInfo.clock),
        KVP_ADD_INT("reset_count", time_info->clockInfo.resetCount),
        KVP_ADD_INT("restartcount", time_info->clockInfo.restartCount),
        KVP_ADD_STR("safe", time_info->clockInfo.safe == TPM2_YES ? "yes" : "no"),
    };

    return add_mapping_root_with_items(y, root, "clock_info",
                                       clock_info, ARRAY_LEN(clock_info));
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

tool_rc tpm2_yaml_hex_string(const char *hex, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(hex);
    int rc = yaml_add_str(y, hex);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_qualified_name(const TPM2B_NAME *qname, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(qname);
    return tpm2b_to_yaml(y, y->root, "qualified name", qname);
}

tool_rc tpm2_yaml_attest2b(const TPM2B_ATTEST *attest, tpm2_yaml *y) {
    null_ret(y, 1);
    return tpm2b_to_yaml(y, y->root, "quoted", (TPM2B_NAME *)attest);
}

tool_rc tpm2_yaml_tpms_time_info(const TPMS_TIME_INFO *time_info, tpm2_yaml *y) {
    null_ret(y, 1);
    return tpms_time_info_to_yaml(y, y->root, time_info) ?  tool_rc_success
        : tool_rc_general_error;
}

tool_rc tpm2_yaml_tpm2b_digest(const char *name, const TPM2B_DIGEST *tpm2b, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(name);
    return tpm2b_to_yaml(y, y->root, name, tpm2b);
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

static int tpmt_signature_hex_to_yaml(const TPMT_SIGNATURE *sig,
        tpm2_yaml *y, int root) {

    /* signature:
     *   alg: rsassa
     *   sig: 26daf030...
     */
    return add_sig_hex(y, root, "signature", sig);
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

tool_rc tpm2_yaml_tpmt_signature_hex(tpm2_yaml *y, const TPMT_SIGNATURE *signature) {
    null_ret(y, 1);
    assert(signature);

    int r = tpmt_signature_hex_to_yaml(signature,
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
    null_ret(y, 1);
    assert(index);

    struct key_value kvp = KVP_ADD_HEX("nv-index", index);
    return add_kvp(y, y->root, &kvp)  ?
            tool_rc_success : tool_rc_general_error;
}

static int tpms_nv_pin_counter_parameters_to_yaml_raw(tpm2_yaml *y,
        int root, const char *key, const uint8_t *data, size_t data_len) {
    /*
     * <key>:
     *   pinCount: 1
     *   pinLimit: 3
     */
    TPMS_NV_PIN_COUNTER_PARAMETERS pin_params = { 0 };
    TSS2_RC rc = Tss2_MU_TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(data, data_len,
            NULL, &pin_params);
    if (rc != TSS2_RC_SUCCESS) {
        return 0;
    }

    key_value scheme_kvs[] = {
        KVP_ADD_INT("pinCount", pin_params.pinCount),
        KVP_ADD_INT("pinLimit", pin_params.pinLimit),
    };

    return add_mapping_root_with_items(y, root, key,
            scheme_kvs, ARRAY_LEN(scheme_kvs));}

static int tpm2_nv_read_to_yaml(tpm2_yaml *y, const TPMS_NV_PUBLIC *pub, const uint8_t *data,
        size_t data_len) {

    TPM2_NT nt = (pub->attributes & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT;
    switch (nt) {
    case TPM2_NT_COUNTER: {
        if (data_len != sizeof(UINT64)) {
            LOG_ERR("Unexpected size for TPM2_NV_COUNTER of %zu bytes, expected %zu",
                    data_len, sizeof(UINT64));
            return 0;
        }
        UINT64 v = 0;
        memcpy(&v, data, sizeof(UINT64));
        v = be64toh(v);
        struct key_value kvp = KVP_ADD_INT("counter", v);
        return add_kvp(y, y->root, &kvp);
    }
    case TPM2_NT_BITS: {
        if (data_len != sizeof(UINT64)) {
            LOG_ERR("Unexpected size for TPM2_NV_BITS of %zu bytes, expected %zu",
                    data_len, sizeof(UINT64));
            return 0;
        }

        UINT64 v = 0;
        memcpy(&v, data, sizeof(UINT64));
        v = be64toh(v);
        struct key_value kvp = KVP_ADD_HEX("bits", v);
        return add_kvp(y, y->root, &kvp);
    }
    case TPM2_NT_EXTEND: {

        /*
         * 8 bytes for 64 bit nums, times two for 2 chars per byte in hex,
         * and a nul byte and extra for the format
         */
        char buf[128] = { 0 };

        /* plop data into a TPM2B structure to make outputiting to hex easier */
        TPM2B_DIGEST d = {
            .size = data_len,
        };
        if (data_len > sizeof(d.buffer)) {
            LOG_ERR("Read data is larger than buffer, got %zu expected less than %zu",
                    data_len, sizeof(d.buffer));
            return 0;
        }
        memcpy(d.buffer, data, data_len);

        /* convert index to 0x<index> */
        snprintf(buf, sizeof(buf), "0x%"PRIx32, pub->nvIndex);

        const char *algstr = tpm2_alg_util_algtostr(pub->nameAlg, tpm2_alg_util_flags_any);
        struct key_value kvp = KVP_ADD_TPM2B(algstr, &d);
        return add_kvp(y, y->root, &kvp);
    }
    break;
    case TPM2_NT_PIN_FAIL:
        return tpms_nv_pin_counter_parameters_to_yaml_raw(y, y->root, "pinfail", data, data_len);
    case TPM2_NT_PIN_PASS:
        return tpms_nv_pin_counter_parameters_to_yaml_raw(y, y->root, "pinpass", data, data_len);
        /* no default - keep compilers happy */
    default:
        break;
    }

    /* copy data to a simple TPM2B to make outputting easier */
    TPM2B_MAX_NV_BUFFER b = {
        .size = data_len
    };

    if (data_len > sizeof(b.buffer)) {
        LOG_ERR("Read data is larger than buffer, got %zu expected less than %zu",
                data_len, sizeof(b.buffer));
        return 0;
    }
    memcpy(b.buffer, data, data_len);
    struct key_value kvp = KVP_ADD_TPM2B("data", &b);
    return add_kvp(y, y->root, &kvp);
}

tool_rc tpm2_yaml_nv_read(const char *data, size_t data_len, const TPM2B_NV_PUBLIC *nv_public,
        tpm2_yaml *y) {
    null_ret(y, 1);
    assert(data);
    assert(nv_public);

    return tpm2_nv_read_to_yaml(y, &nv_public->nvPublic, data, data_len) ?
           tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_sequence(char *name, tpm2_yaml *y) {
    if (y->stack_idx == MAX_YAML_STACK - 1) {
        LOG_ERR("Yaml stack overflow");
        return tool_rc_general_error;
    }

    int key = yaml_document_add_scalar(&y->doc, YAML_STR_TAG,       \
                                       (yaml_char_t *)name, -1, YAML_ANY_SCALAR_STYLE);
    if (!key) {
        LOG_ERR("Yaml key can't be created");
        return tool_rc_general_error;
    }
    int sequence = yaml_document_add_sequence(&y->doc,
                                              NULL,
                                              YAML_ANY_SEQUENCE_STYLE);
    if (!sequence) {
        LOG_ERR("Yaml sequence can't be added");
        return tool_rc_general_error;
    }
    y->stack_idx++;
    y->object_stack[y->stack_idx].index = sequence;
    y->object_stack[y->stack_idx].type = yaml_sequence;

    yaml_document_append_mapping_pair(&y->doc,
                                      y->object_stack[y->stack_idx - 1].index, key, sequence);
    return tool_rc_success;
}

tool_rc tpm2_yaml_add_mapping(tpm2_yaml *y) {
    if (y->stack_idx == MAX_YAML_STACK - 1) {
        LOG_ERR("Yaml stack overflow");
        return tool_rc_general_error;
    }
    y->stack_idx++;
    int mapping = yaml_document_add_mapping(&y->doc, NULL, YAML_ANY_MAPPING_STYLE);

    y->object_stack[y->stack_idx].index = mapping;
    y->object_stack[y->stack_idx].type = yaml_mapping;

    if (y->object_stack[y->stack_idx - 1].type == yaml_mapping) {
        assert(y->object_stack[y->stack_idx - 1].name);
        int key = yaml_document_add_scalar(&y->doc, YAML_STR_TAG,   \
                                           (yaml_char_t *)
                                           y->object_stack[y->stack_idx - 1].name,
                                           -1, YAML_ANY_SCALAR_STYLE);

        yaml_document_append_mapping_pair(&y->doc, y->object_stack[y->stack_idx - 1].index ,
                                          key, mapping);
    } else {
        yaml_document_append_sequence_item(&y->doc, y->object_stack[y->stack_idx - 1].index,
                                           mapping);
    }

    return tool_rc_success;
}

tool_rc tpm2_yaml_add_mapping_name(tpm2_yaml *y, char *name) {
    assert(y->stack_idx != MAX_YAML_STACK -1);
    y->object_stack[y->stack_idx + 1].name = name;
    return tpm2_yaml_add_mapping(y);
}

tool_rc tpm2_yaml_close_mapping(tpm2_yaml *y) {
    assert(y->stack_idx > 0);
    y->stack_idx--;
    return tool_rc_success;
}

tool_rc tpm2_yaml_close_sequence(tpm2_yaml *y) {
    assert(y->stack_idx > 0);
    y->stack_idx--;
    return tool_rc_success;
}

tool_rc tpm2_yaml_add_kv_tpm2b(const char *key, const TPM2B *tpm2b, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_TPM2B(key, tpm2b);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_str(const char *key, const char *str, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_STR(key, str);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uint64(const char *key, const uint64_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_INT(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uint32(const char *key, const uint32_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_INT(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uint16(const char *key, const uint16_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_INT(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uint8(const char *key, const uint8_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_INT(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uintx64(const char *key, const uint64_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_HEX(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uintx32(const char *key, const uint32_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_HEX(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uintx16(const char *key, const uint16_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_HEX(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_add_kv_uintx8(const char *key, const uint8_t n, tpm2_yaml *y) {
    assert(y->object_stack[y->stack_idx].type == yaml_mapping);
    struct key_value kv = KVP_ADD_HEX(key, n);
    int rc = add_kvp(y, y->object_stack[y->stack_idx].index, &kv);
    return rc ? tool_rc_success : tool_rc_general_error;
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
