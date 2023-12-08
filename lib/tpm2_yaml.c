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

static tool_rc tpm2b_name_to_yaml(const TPM2B_NAME *name, yaml_document_t *doc, int root) {

    int key = yaml_add_str(doc, "name");
    int value = yaml_add_tpm2b(doc, (const TPM2B *)name);
    int rc = yaml_document_append_mapping_pair(doc, root, key, value);

    return rc != 0 ? tool_rc_success : tool_rc_general_error;
}

tool_rc tpm2_yaml_tpm2b_name(const TPM2B_NAME *name, tpm2_yaml *y) {
    null_ret(y, 1);
    assert(name);
    return tpm2b_name_to_yaml(name, &y->doc, y->root);
}

typedef struct key_value key_value;
struct key_value {
    const char *key;
    union {
        const char *as_str;
        const uint64_t as_int;
    } value;
    const yaml_char_t *tag;
};

#define KVP_ADD_STR(k, v) {.key = k, .tag = YAML_STR_TAG, .value = { .as_str = v}}
#define KVP_ADD_INT(k, v) {.key = k, .tag = YAML_INT_TAG, .value = { .as_int = v}}

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
        int key = yaml_document_add_scalar(doc, YAML_STR_TAG, \
                    (yaml_char_t *)k->key, -1, YAML_ANY_SCALAR_STYLE);
        return_rc(key);

        int value = 0;
        if (strcmp(k->tag, YAML_STR_TAG) == 0) {
            value = yaml_add_str(doc, k->value.as_str);
        } else if (strcmp(k->tag, YAML_INT_TAG) == 0) {
            value = yaml_add_int(doc, k->value.as_int);
        } else {
            LOG_ERR("Unknown tag type: %s", k->tag ? (char *)k->tag : "(null)");
            return 0;
        }
        return_rc(value);

        int rc = yaml_document_append_mapping_pair(doc, sub_root, key, value);
        return_rc(rc);
    }

    return yaml_document_append_mapping_pair(doc, root, sub_root_key, sub_root);
}

static int tpms_symcipher_params_to_yaml(yaml_document_t *t,
        const TPMS_SYMCIPHER_PARMS *params) {

    print_alg_raw("sym-alg", sym->algorithm, indent);
    print_alg_raw("sym-mode", sym->mode.sym, indent);
    tpm2_tool_output("%ssym-keybits: %u\n", indent, sym->keyBits.sym);
}

static tool_rc tpmt_public_to_yaml(const TPMT_PUBLIC *public,
        yaml_document_t *doc, int root) {

    /* name-alg:
     *   value: sha256
     *   raw: 0x0b
     */
    key_value name_alg[] = {
        KVP_ADD_STR("value", tpm2_alg_util_algtostr(public->nameAlg, tpm2_alg_util_flags_any)),
        KVP_ADD_INT("raw", public->nameAlg)
    };

    int rc = add_mapping_root_with_items(doc, root, "name-alg",
            name_alg, ARRAY_LEN(name_alg));
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

    int type_node = 0;
    switch(public->type) {
    case TPM2_ALG_SYMCIPHER:
        type_node = tpms_symcipher_params_to_yaml();
        break;
    case TPM2_ALG_KEYEDHASH:
        break;
    case TPM2_ALG_RSA:
        break;
    case TPM2_ALG_ECC:
        break;
    default:
        LOG_ERR("Unknown key type: 0x%x", public->type);
        return tool_rc_general_error;
    }

    return tool_rc_success;

//    tpm2_tool_output("%stype:\n", indent);
//    tpm2_tool_output("%s  value: %s\n", indent,
//            tpm2_alg_util_algtostr(public->type,
//                    tpm2_alg_util_flags_any));
//    tpm2_tool_output("%s  raw: 0x%x\n", indent, public->type);
//
//    switch (public->type) {
//    case TPM2_ALG_SYMCIPHER: {
//        TPMS_SYMCIPHER_PARMS *s = &public->parameters.symDetail;
//        print_sym(&s->sym, indent);
//    }
//        break;
//    case TPM2_ALG_KEYEDHASH: {
//        TPMS_KEYEDHASH_PARMS *k = &public->parameters.keyedHashDetail;
//        tpm2_tool_output("%salgorithm: \n", indent);
//        tpm2_tool_output("%s  value: %s\n", indent,
//                tpm2_alg_util_algtostr(k->scheme.scheme,
//                        tpm2_alg_util_flags_any));
//        tpm2_tool_output("%s  raw: 0x%x\n", indent, k->scheme.scheme);
//
//        if (k->scheme.scheme == TPM2_ALG_HMAC) {
//            tpm2_tool_output("%shash-alg:\n", indent);
//            tpm2_tool_output("%s  value: %s\n", indent,
//                    tpm2_alg_util_algtostr(k->scheme.details.hmac.hashAlg,
//                            tpm2_alg_util_flags_any));
//            tpm2_tool_output("%s  raw: 0x%x\n", indent,
//                    k->scheme.details.hmac.hashAlg);
//        } else if (k->scheme.scheme == TPM2_ALG_XOR) {
//            tpm2_tool_output("%shash-alg:\n", indent);
//            tpm2_tool_output("%s  value: %s\n", indent,
//                    tpm2_alg_util_algtostr(
//                            k->scheme.details.exclusiveOr.hashAlg,
//                            tpm2_alg_util_flags_any));
//            tpm2_tool_output("%s  raw: 0x%x\n", indent,
//                    k->scheme.details.exclusiveOr.hashAlg);
//
//            tpm2_tool_output("%skdfa-alg:\n", indent);
//            tpm2_tool_output("%s  value: %s\n", indent,
//                    tpm2_alg_util_algtostr(k->scheme.details.exclusiveOr.kdf,
//                            tpm2_alg_util_flags_any));
//            tpm2_tool_output("%s  raw: 0x%x\n", indent,
//                    k->scheme.details.exclusiveOr.kdf);
//        }
//
//    }
//        break;
//    case TPM2_ALG_RSA: {
//        TPMS_RSA_PARMS *r = &public->parameters.rsaDetail;
//        tpm2_tool_output("%sexponent: %u\n", indent, r->exponent ? r->exponent : 65537);
//        tpm2_tool_output("%sbits: %u\n", indent, r->keyBits);
//
//        print_rsa_scheme(&r->scheme, indent);
//
//        print_sym(&r->symmetric, indent);
//    }
//        break;
//    case TPM2_ALG_ECC: {
//        TPMS_ECC_PARMS *e = &public->parameters.eccDetail;
//
//        tpm2_tool_output("%scurve-id:\n", indent);
//        tpm2_tool_output("%s  value: %s\n", indent,
//                tpm2_alg_util_ecc_to_str(e->curveID));
//        tpm2_tool_output("%s  raw: 0x%x\n", indent, e->curveID);
//
//        print_kdf_scheme(&e->kdf, indent);
//
//        print_ecc_scheme(&e->scheme, indent);
//
//        print_sym(&e->symmetric, indent);
//    }
//        break;
//    }
//
//    tpm2_util_keydata keydata = TPM2_UTIL_KEYDATA_INIT
//    ;
//    tpm2_util_public_to_keydata(public, &keydata);
//
//    UINT16 i;
//    /* if no keydata len will be 0 and it wont print */
//    for (i = 0; i < keydata.len; i++) {
//        tpm2_tool_output("%s%s: ", indent, keydata.entries[i].name);
//        tpm2_util_print_tpm2b(keydata.entries[i].value);
//        tpm2_tool_output("%s\n", indent);
//    }
//
//    if (public->authPolicy.size) {
//        tpm2_tool_output("%sauthorization policy: ", indent);
//        tpm2_util_hexdump(public->authPolicy.buffer,
//            public->authPolicy.size);
//        tpm2_tool_output("%s\n", indent);
//    }
}

tool_rc tpm2_yaml_tpmt_public(tpm2_yaml *y, const TPMT_PUBLIC *public) {
    null_ret(y, 1);
    assert(public);

    return tpmt_public_to_yaml(public,
            &y->doc, y->root);
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
