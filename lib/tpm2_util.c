/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tool_rc.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_systemdeps.h"

// verify that the quote digest equals the digest we calculated
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest,
        TPM2B_DIGEST *pcr_digest) {

    // Sanity check -- they should at least be same size!
    if (quoteDigest->size != pcr_digest->size) {
        LOG_ERR("FATAL ERROR: PCR values failed to match quote's digest!");
        return false;
    }

    // Compare running digest with quote's digest
    int k;
    for (k = 0; k < quoteDigest->size; k++) {
        if (quoteDigest->buffer[k] != pcr_digest->buffer[k]) {
            LOG_ERR("FATAL ERROR: PCR values failed to match quote's digest!");
            return false;
        }
    }

    return true;
}

bool tpm2_util_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append) {

    if (!result || !append) {
        return false;
    }

    if (((UINT32)result->size + append->size) > TPM2_MAX_DIGEST_BUFFER) {
        return false;
    }

    memcpy(&result->buffer[result->size], append->buffer, append->size);
    result->size += append->size;

    return true;
}

bool tpm2_util_string_to_uint8(const char *str, uint8_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 8 bits? */
    if (tmp > UINT8_MAX) {
        return false;
    }

    *value = (uint8_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint64(const char *str, uint64_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    /*
     * unsigned long long is at least 64 bits, although commonly  just 64 bits even on 64 bit systems
     * however, ensure that on some weird system it isn't greater than 64 bits since it is allowed by
     * the standard.
     */
    unsigned long long int tmp = strtoull(str, &endptr, 0);
    if (errno || tmp > UINT64_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint64_t) tmp;
    return true;
}

bool tpm2_util_string_to_int32(const char *str, int32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    signed long int tmp = strtol(str, &endptr, 0);
    if (errno || tmp > INT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (int32_t) tmp;
    return true;
}

int tpm2_util_hex_to_byte_structure(const char *input_string, UINT16 *byte_length,
        BYTE *byte_buffer) {
    int str_length; //if the input_string likes "1a2b...", no prefix "0x"
    int i = 0;
    if (input_string == NULL || byte_length == NULL || byte_buffer == NULL)
        return -1;
    str_length = strlen(input_string);
    if (str_length % 2)
        return -2;
    for (i = 0; i < str_length; i++) {
        if (!isxdigit(input_string[i]))
            return -3;
    }

    if (*byte_length < str_length / 2)
        return -4;

    *byte_length = str_length / 2;

    for (i = 0; i < *byte_length; i++) {
        char tmp_str[4] = { 0 };
        tmp_str[0] = input_string[i * 2];
        tmp_str[1] = input_string[i * 2 + 1];
        byte_buffer[i] = strtol(tmp_str, NULL, 16);
    }
    return 0;
}

bool tpm2_util_bin_from_hex_or_file(const char *input, UINT16 *len, BYTE *buffer) {

    bool result = false;

    FILE *f = fopen(input, "rb");
    if (!f) {
        result = tpm2_util_hex_to_byte_structure(input, len, buffer) == 0;
        goto out;
    }

    result = file_read_bytes_from_file(f, buffer, len, input);
    fclose(f);
out:
    if (!result) {
        LOG_ERR("Could not convert \"%s\". Neither a file path nor hex string.",
        input);
    }

    return result;
}

void tpm2_util_hexdump2(FILE *f, const BYTE *data, size_t len) {

    size_t i;
    for (i = 0; i < len; i++) {
        fprintf(f, "%02x", data[i]);
    }
}

void tpm2_util_hexdump(const BYTE *data, size_t len) {

    if (!output_enabled) {
        return;
    }

    tpm2_util_hexdump2(stdout, data, len);
}

bool tpm2_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) { \
    \
        UINT##size converted; \
        UINT8 *bytes = (UINT8 *)&data; \
        UINT8 *tmp = (UINT8 *)&converted; \
    \
        size_t i; \
        for(i=0; i < sizeof(UINT##size); i ++) { \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1]; \
        } \
        \
        return converted; \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)
STRING_BYTES_ENDIAN_CONVERT(64)

#define STRING_BYTES_ENDIAN_HTON(size) \
    UINT##size tpm2_util_hton_##size(UINT##size data) { \
    \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        if (is_big_endian) { \
           return data; \
        } \
    \
        return tpm2_util_endian_swap_##size(data); \
    }

STRING_BYTES_ENDIAN_HTON(16)
STRING_BYTES_ENDIAN_HTON(32)
STRING_BYTES_ENDIAN_HTON(64)

/*
 * Converting from host-to-network (hton) or network-to-host (ntoh) is
 * the same operation: if endianess differs between host and data, swap
 * endianess. Thus we can just call the hton routines, but have some nice
 * names for folks.
 */
UINT16 tpm2_util_ntoh_16(UINT16 data) {
    return tpm2_util_hton_16(data);
}

UINT32 tpm2_util_ntoh_32(UINT32 data) {
    return tpm2_util_hton_32(data);
}
UINT64 tpm2_util_ntoh_64(UINT64 data) {
    return tpm2_util_hton_64(data);
}

UINT32 tpm2_util_pop_count(UINT32 data) {

    static const UINT8 bits_per_nibble[] =
        {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

    UINT8 count = 0;
    UINT8 *d = (UINT8 *) &data;

    size_t i;
    for (i = 0; i < sizeof(data); i++) {
        count += bits_per_nibble[d[i] & 0x0f];
        count += bits_per_nibble[d[i] >> 4];
    }

    return count;
}

#define TPM2_UTIL_KEYDATA_INIT { .len = 0 };

typedef struct tpm2_util_keydata tpm2_util_keydata;
struct tpm2_util_keydata {
    UINT16 len;
    struct {
        const char *name;
        TPM2B *value;
    } entries[2];
};

static void tpm2_util_public_to_keydata(TPMT_PUBLIC *public,
        tpm2_util_keydata *keydata) {

    switch (public->type) {
    case TPM2_ALG_RSA:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(
            public->type, tpm2_alg_util_flags_any);
        keydata->entries[0].value = (TPM2B *) &public->unique.rsa;
        return;
    case TPM2_ALG_KEYEDHASH:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(
            public->type, tpm2_alg_util_flags_any);
        keydata->entries[0].value =
                (TPM2B *) &public->unique.keyedHash;
        return;
    case TPM2_ALG_SYMCIPHER:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(
            public->type, tpm2_alg_util_flags_any);
        keydata->entries[0].value = (TPM2B *) &public->unique.sym;
        return;
    case TPM2_ALG_ECC:
        keydata->len = 2;
        keydata->entries[0].name = "x";
        keydata->entries[0].value = (TPM2B *) &public->unique.ecc.x;
        keydata->entries[1].name = "y";
        keydata->entries[1].value = (TPM2B *) &public->unique.ecc.y;
        return;
    default:
        LOG_WARN("The algorithm type(0x%4.4x) is not supported",
            public->type);
    }

    return;
}

void print_yaml_indent(size_t indent_count) {
    while (indent_count--) {
        tpm2_tool_output("  ");
    }
}

void tpm2_util_tpma_object_to_yaml(TPMA_OBJECT obj, char *indent) {

    if (!indent) {
        indent = "";
    }

    char *attrs = tpm2_attr_util_obj_attrtostr(obj);
    tpm2_tool_output("%sattributes:\n", indent);
    tpm2_tool_output("%s  value: %s\n", indent, attrs);
    tpm2_tool_output("%s  raw: 0x%x\n", indent, obj);
    free(attrs);
}

static void print_alg_raw(const char *name, TPM2_ALG_ID alg, const char *indent) {

    tpm2_tool_output("%s%s:\n", indent, name);
    tpm2_tool_output("%s  value: %s\n", indent,
            tpm2_alg_util_algtostr(alg, tpm2_alg_util_flags_any));
    tpm2_tool_output("%s  raw: 0x%x\n", indent, alg);
}

static void print_scheme_common(TPMI_ALG_RSA_SCHEME scheme, const char *indent) {
    print_alg_raw("scheme", scheme, indent);
}

static void print_sym(TPMT_SYM_DEF_OBJECT *sym, const char *indent) {

    print_alg_raw("sym-alg", sym->algorithm, indent);
    print_alg_raw("sym-mode", sym->mode.sym, indent);
    tpm2_tool_output("%ssym-keybits: %u\n", indent, sym->keyBits.sym);
}

static void print_rsa_scheme(TPMT_RSA_SCHEME *scheme, const char *indent) {

    print_scheme_common(scheme->scheme, indent);

    /*
     * everything is a union on a hash algorithm except for RSAES which
     * has nothing. So on RSAES skip the hash algorithm printing
     */
    if (scheme->scheme != TPM2_ALG_RSAES) {
        print_alg_raw("scheme-halg", scheme->details.oaep.hashAlg, indent);
    }
}

static void print_ecc_scheme(TPMT_ECC_SCHEME *scheme, const char *indent) {

    print_scheme_common(scheme->scheme, indent);

    /*
     * everything but ecdaa uses only hash alg
     * in a union, so we only need to do things differently
     * for ecdaa.
     */
    print_alg_raw("scheme-halg", scheme->details.oaep.hashAlg, indent);

    if (scheme->scheme == TPM2_ALG_ECDAA) {
        tpm2_tool_output("%sscheme-count: %u\n", indent,
                scheme->details.ecdaa.count);
    }
}

static void print_kdf_scheme(TPMT_KDF_SCHEME *kdf, const char *indent) {

    print_alg_raw("kdfa-alg", kdf->scheme, indent);

    /*
     * The hash algorithm for the KDFA is in a union, just grab one of them.
     */
    print_alg_raw("kdfa-halg", kdf->details.mgf1.hashAlg, indent);
}

void tpm2_util_tpmt_public_to_yaml(TPMT_PUBLIC *public, char *indent) {

    if (!indent) {
        indent = "";
    }

    tpm2_tool_output("%sname-alg:\n", indent);
    tpm2_tool_output("%s  value: %s\n", indent,
            tpm2_alg_util_algtostr(public->nameAlg,
                    tpm2_alg_util_flags_any));
    tpm2_tool_output("%s  raw: 0x%x\n", indent, public->nameAlg);

    tpm2_util_tpma_object_to_yaml(public->objectAttributes, indent);

    tpm2_tool_output("%stype:\n", indent);
    tpm2_tool_output("%s  value: %s\n", indent,
            tpm2_alg_util_algtostr(public->type,
                    tpm2_alg_util_flags_any));
    tpm2_tool_output("%s  raw: 0x%x\n", indent, public->type);

    switch (public->type) {
    case TPM2_ALG_SYMCIPHER: {
        TPMS_SYMCIPHER_PARMS *s = &public->parameters.symDetail;
        print_sym(&s->sym, indent);
    }
        break;
    case TPM2_ALG_KEYEDHASH: {
        TPMS_KEYEDHASH_PARMS *k = &public->parameters.keyedHashDetail;
        tpm2_tool_output("%salgorithm: \n", indent);
        tpm2_tool_output("%s  value: %s\n", indent,
                tpm2_alg_util_algtostr(k->scheme.scheme,
                        tpm2_alg_util_flags_any));
        tpm2_tool_output("%s  raw: 0x%x\n", indent, k->scheme.scheme);

        if (k->scheme.scheme == TPM2_ALG_HMAC) {
            tpm2_tool_output("%shash-alg:\n", indent);
            tpm2_tool_output("%s  value: %s\n", indent,
                    tpm2_alg_util_algtostr(k->scheme.details.hmac.hashAlg,
                            tpm2_alg_util_flags_any));
            tpm2_tool_output("%s  raw: 0x%x\n", indent,
                    k->scheme.details.hmac.hashAlg);
        } else if (k->scheme.scheme == TPM2_ALG_XOR) {
            tpm2_tool_output("%shash-alg:\n", indent);
            tpm2_tool_output("%s  value: %s\n", indent,
                    tpm2_alg_util_algtostr(
                            k->scheme.details.exclusiveOr.hashAlg,
                            tpm2_alg_util_flags_any));
            tpm2_tool_output("%s  raw: 0x%x\n", indent,
                    k->scheme.details.exclusiveOr.hashAlg);

            tpm2_tool_output("%skdfa-alg:\n", indent);
            tpm2_tool_output("%s  value: %s\n", indent,
                    tpm2_alg_util_algtostr(k->scheme.details.exclusiveOr.kdf,
                            tpm2_alg_util_flags_any));
            tpm2_tool_output("%s  raw: 0x%x\n", indent,
                    k->scheme.details.exclusiveOr.kdf);
        }

    }
        break;
    case TPM2_ALG_RSA: {
        TPMS_RSA_PARMS *r = &public->parameters.rsaDetail;
        tpm2_tool_output("%sexponent: %u\n", indent, r->exponent ? r->exponent : 65537);
        tpm2_tool_output("%sbits: %u\n", indent, r->keyBits);

        print_rsa_scheme(&r->scheme, indent);

        print_sym(&r->symmetric, indent);
    }
        break;
    case TPM2_ALG_ECC: {
        TPMS_ECC_PARMS *e = &public->parameters.eccDetail;

        tpm2_tool_output("%scurve-id:\n", indent);
        tpm2_tool_output("%s  value: %s\n", indent,
                tpm2_alg_util_ecc_to_str(e->curveID));
        tpm2_tool_output("%s  raw: 0x%x\n", indent, e->curveID);

        print_kdf_scheme(&e->kdf, indent);

        print_ecc_scheme(&e->scheme, indent);

        print_sym(&e->symmetric, indent);
    }
        break;
    }

    tpm2_util_keydata keydata = TPM2_UTIL_KEYDATA_INIT
    ;
    tpm2_util_public_to_keydata(public, &keydata);

    UINT16 i;
    /* if no keydata len will be 0 and it wont print */
    for (i = 0; i < keydata.len; i++) {
        tpm2_tool_output("%s%s: ", indent, keydata.entries[i].name);
        tpm2_util_print_tpm2b(keydata.entries[i].value);
        tpm2_tool_output("%s\n", indent);
    }

    if (public->authPolicy.size) {
        tpm2_tool_output("%sauthorization policy: ", indent);
        tpm2_util_hexdump(public->authPolicy.buffer,
            public->authPolicy.size);
        tpm2_tool_output("%s\n", indent);
    }
}

void tpm2_util_public_to_yaml(TPM2B_PUBLIC *public, char *indent) {

    tpm2_util_tpmt_public_to_yaml(&public->publicArea, indent);
}

bool tpm2_util_calc_unique(TPMI_ALG_HASH name_alg,
        TPM2B_PRIVATE_VENDOR_SPECIFIC *key, TPM2B_DIGEST *seed,
        TPM2B_DIGEST *unique_data) {

    TPM2B_MAX_BUFFER buf = { .size = key->size + seed->size };
    if (buf.size > sizeof(buf.buffer)) {
        LOG_ERR("Seed and key size are too big");
        return false;
    }

    memcpy(buf.buffer, seed->buffer, seed->size);
    memcpy(&buf.buffer[seed->size], key->buffer, key->size);

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(name_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported: %x", name_alg);
        return false;
    }

    unsigned int hash_size;
    int rc = EVP_Digest(buf.buffer, buf.size, unique_data->buffer, &hash_size,
                        md, NULL);
    if (!rc) {
        LOG_ERR("Hash calculation failed");
        return false;
    }
    unique_data->size = hash_size;

    return true;
}

ESYS_TR tpm2_tpmi_hierarchy_to_esys_tr(TPMI_RH_PROVISION inh) {

    switch (inh) {
    case TPM2_RH_OWNER:
        return ESYS_TR_RH_OWNER;
    case TPM2_RH_PLATFORM:
        return ESYS_TR_RH_PLATFORM;
    case TPM2_RH_ENDORSEMENT:
        return ESYS_TR_RH_ENDORSEMENT;
    case TPM2_RH_NULL:
        return ESYS_TR_RH_NULL;
    case TPM2_RH_LOCKOUT:
        return ESYS_TR_RH_LOCKOUT;
    }
    return ESYS_TR_NONE;
}

tool_rc tpm2_util_sys_handle_to_esys_handle(ESYS_CONTEXT *context,
        TPM2_HANDLE sys_handle, ESYS_TR *esys_handle) {

    ESYS_TR h = tpm2_tpmi_hierarchy_to_esys_tr(sys_handle);
    if (h != ESYS_TR_NONE) {
        *esys_handle = h;
        return tool_rc_success;
    }

    return tpm2_from_tpm_public(context, sys_handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, esys_handle);
}

char *tpm2_util_getenv(const char *name) {

    return getenv(name);
}

bool tpm2_util_env_yes(const char *name) {

    char *value = getenv(name);
    return (value && (strcasecmp(value, "yes") == 0 ||
                      strcasecmp(value, "1") == 0 ||
                      strcasecmp(value, "true") == 0));
}

/**
 * Parses a hierarchy value from an option argument.
 * @param value
 *  The string to parse, which can be a numerical string as
 *  understood by strtoul() with a base of 0, or an:
 *    - o - Owner hierarchy
 *    - p - Platform hierarchy
 *    - e - Endorsement hierarchy
 *    - n - Null hierarchy
 * @param hierarchy
 *  The parsed hierarchy as output.
 * @param flags
 *  What hierarchies should be supported by
 *  the parsing.
 * @return
 *  True on success, False otherwise.
 */

static bool filter_hierarchy_handles(TPMI_RH_PROVISION hierarchy,
        tpm2_handle_flags flags) {

    switch (hierarchy) {
    case TPM2_RH_OWNER:
        if (!(flags & TPM2_HANDLE_FLAGS_O)) {
            LOG_ERR("Unexpected handle - TPM2_RH_OWNER");
            return false;
        }
        break;
    case TPM2_RH_PLATFORM:
        if (!(flags & TPM2_HANDLE_FLAGS_P)) {
            LOG_ERR("Unexpected handle - TPM2_RH_PLATFORM");
            return false;
        }
        break;
    case TPM2_RH_ENDORSEMENT:
        if (!(flags & TPM2_HANDLE_FLAGS_E)) {
            LOG_ERR("Unexpected handle - TPM2_RH_ENDORSEMENT");
            return false;
        }
        break;
    case TPM2_RH_NULL:
        if (!(flags & TPM2_HANDLE_FLAGS_N)) {
            LOG_ERR("Unexpected handle - TPM2_RH_NULL");
            return false;
        }
        break;
    case TPM2_RH_LOCKOUT:
        if (!(flags & TPM2_HANDLE_FLAGS_L)) {
            LOG_ERR("Unexpected handle - TPM2_RH_LOCKOUT");
            return false;
        }
        break;
    default: //If specified a random offset to the permanent handle range
        if (flags == TPM2_HANDLE_ALL_W_NV || flags == TPM2_HANDLE_FLAGS_NONE) {
            return true;
        }
        return false;
    }

    return true;
}

static bool filter_handles(TPMI_RH_PROVISION *hierarchy,
        tpm2_handle_flags flags) {

    TPM2_RH range = *hierarchy & TPM2_HR_RANGE_MASK;

    /*
     * if their is no range, then it could be NV or PCR, use flags
     * to figure out what it is.
     */
    if (range == 0) {
        if (flags & TPM2_HANDLE_FLAGS_NV) {
            *hierarchy += TPM2_HR_NV_INDEX;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else if (flags & TPM2_HANDLE_FLAGS_PCR) {
            *hierarchy += TPM2_HR_PCR;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else {
            LOG_ERR("Implicit indices are not supported.");
            return false;
        }
    }

    /* now that we have fixed up any non-ranged handles, check them */
    if (range == TPM2_HR_NV_INDEX) {
        if (!(flags & TPM2_HANDLE_FLAGS_NV)) {
            LOG_ERR("NV-Index handles are not supported by this command.");
            return false;
        }
        if (*hierarchy < TPM2_NV_INDEX_FIRST
                || *hierarchy > TPM2_NV_INDEX_LAST) {
            LOG_ERR("NV-Index handle is out of range.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PCR) {
        if (!(flags & TPM2_HANDLE_FLAGS_PCR)) {
            LOG_ERR("PCR handles are not supported by this command.");
            return false;
        }
        /* first is 0 so no possible way unsigned is less than 0, thus no check */
        if (*hierarchy > TPM2_PCR_LAST) {
            LOG_ERR("PCR handle out of range.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_TRANSIENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_TRANSIENT)) {
            LOG_ERR("Transient handles are not supported by this command.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PERMANENT) {
        return filter_hierarchy_handles(*hierarchy, flags);
    } else if (range == TPM2_HR_PERSISTENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_PERSISTENT)) {
            LOG_ERR("Persistent handles are not supported by this command.");
            return false;
        }
        if (*hierarchy < TPM2_PERSISTENT_FIRST
                || *hierarchy > TPM2_PERSISTENT_LAST) {
            LOG_ERR("Persistent handle out of range.");
            return false;
        }
        return true;
    }

    /* else its a session flag and shouldn't use this interface */
    return false;
}

bool tpm2_util_handle_from_optarg(const char *value,
        TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags) {

    if (!value || !value[0]) {
        return false;
    }

    if ((flags & TPM2_HANDLE_FLAGS_NV) && (flags & TPM2_HANDLE_FLAGS_PCR)) {
        LOG_ERR("Cannot specify NV and PCR index together");
        return false;
    }

    *hierarchy = 0;

    bool is_o = !strncmp(value, "owner", strlen(value));
    if (is_o) {
        *hierarchy = TPM2_RH_OWNER;
    }

    bool is_p = !strncmp(value, "platform", strlen(value));
    if (is_p) {
        *hierarchy = TPM2_RH_PLATFORM;
    }

    bool is_e = !strncmp(value, "endorsement", strlen(value));
    if (is_e) {
        *hierarchy = TPM2_RH_ENDORSEMENT;
    }

    bool is_n = !strncmp(value, "null", strlen(value));
    if (is_n) {
        *hierarchy = TPM2_RH_NULL;
    }

    bool is_l = !strncmp(value, "lockout", strlen(value));
    if (is_l) {
        *hierarchy = TPM2_RH_LOCKOUT;
    }

    bool result = true;
    if (!*hierarchy) {
        /*
         * This branch is executed when hierarchy is specified as a hex handle.
         * The raw hex returned may be a generic (non hierarchy) TPM2_HANDLE.
         */
        result = tpm2_util_string_to_uint32(value, hierarchy);
    }
    if (!result) {

        char msg[256] = { 0 };

        char print_flags[32] = { '[', '\0' };

        if (flags & TPM2_HANDLE_FLAGS_O) {
            strncat(print_flags, "o|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_P) {
            strncat(print_flags, "p|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_E) {
            strncat(print_flags, "e|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_N) {
            strncat(print_flags, "n|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_L) {
            strncat(print_flags, "l|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        size_t len = strlen(print_flags);
        if (print_flags[len - 1] == '|') {
            len--;
            print_flags[len] = '\0';
        }

        strncat(print_flags, "]",
                sizeof(print_flags) - strlen(print_flags) - 1);
        len++;

        bool has_print_flags = len > 2;

        if (has_print_flags) {
            snprintf(msg, sizeof(msg), "expected %s or ", print_flags);
        }

        strncat(msg, "a handle number", sizeof(msg) - strlen(msg) - 1);

        LOG_ERR("Incorrect handle value, got: \"%s\", expected %s", value, msg);
        return false;
    }

    /*
     * If the caller specifies the expected valid hierarchies, either as string,
     * or hex handles, they are additionally filtered here.
     */

    bool res = filter_handles(hierarchy, flags);
    if (!res) {
        LOG_ERR("Unknown or unsupported handle, got: \"%s\"", value);
    }
    return res;
}

bool tpm2_util_get_label(const char *value, TPM2B_DATA *label) {

    if (!value) {
        label->size = 0;
        return true;
    }

    FILE *f = fopen(value, "rb");
    if (f) {
        /* set size one smaller for NUL byte */
        label->size = sizeof(label->buffer) - 1;
        size_t cnt = fread(label->buffer, 1, label->size, f);
        if (!feof(f)) {
            LOG_ERR("label file \"%s\" larger than expected. Expected %u",
                    value, label->size);
            fclose(f);
            return false;
        }
        if (ferror(f)) {
            LOG_ERR("reading label file \"%s\" error: %s", value,
                    strerror(errno));
            fclose(f);
            return false;
        }
        fclose(f);

        label->size = cnt;

        /* Set NUL byte and increment */
        label->buffer[label->size++] = '\0';

        return true;
    }

    size_t len = strlen(value);
    if (len > sizeof(label->buffer) - 1) {
        LOG_ERR("label file \"%s\" larger than expected. Expected %zu", value,
                sizeof(label->buffer) - 1);
        return false;
    }

    memcpy(label->buffer, value, len);

    label->size = len;
    /* Set NUL byte and increment */
    label->buffer[label->size++] = '\0';

    return true;
}

void tpm2_util_print_time(const TPMS_TIME_INFO *current_time) {

    tpm2_tool_output("time: %"PRIu64"\n", current_time->time);

    tpm2_tool_output("clock_info:\n");

    tpm2_tool_output("  clock: %"PRIu64"\n",
            current_time->clockInfo.clock);

    tpm2_tool_output("  reset_count: %"PRIu32"\n",
            current_time->clockInfo.resetCount);

    tpm2_tool_output("  restart_count: %"PRIu32"\n",
            current_time->clockInfo.restartCount);

    tpm2_tool_output("  safe: %s\n",
            current_time->clockInfo.safe ? "yes" : "no");
}

bool tpm2_calq_qname(TPM2B_NAME *pqname,
        TPMI_ALG_HASH halg, TPM2B_NAME *name, TPM2B_NAME *qname) {

    // QNB ≔ HB (QNA || NAMEB)
    bool result = false;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(halg);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    size_t offset = sizeof(halg);
    rc = EVP_DigestUpdate(mdctx, pqname->name, pqname->size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, name->name, name->size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, &qname->name[offset], &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    /* hash sizes are not bigger than 16 bits, safe truncate */
    qname->size = (UINT16)size;

    /* put the hash alg on the front, since name already has it in marshalled
     * proper form just use it.
     */
    memcpy(qname->name, name->name, offset);
    qname->size += offset;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

bool tpm2_safe_read_from_stdin(int length, char *data) {
    int rc;

    char *buf = malloc(length);
    char *read_data = malloc(length);

    if (buf == fgets(buf, length, stdin)) {
        rc = sscanf(buf, "%s", read_data);
        if (rc != 1) {
            free(buf);
            free(read_data);
            return false;
        }
    }
    else {
        free(buf);
        free(read_data);
        return false;
    }

    strcpy(data, read_data);
    free(buf);
    free(read_data);
    return true;
}

bool tpm2_pem_encoded_key_to_fingerprint(const char *pem_encoded_key,
    char *fingerprint) {

    bool is_pemkey_len_valid = strlen(pem_encoded_key) > 1024 ? false : true;
    if (!is_pemkey_len_valid) {
        return false;
    }

    char str[1024] = "";
    strcpy(str, pem_encoded_key);

    /* walk through other tokens */
    char base64[1024] = "";
    char *token = strtok(str, "\n");
    while ( token != NULL ) {
        if (!strstr(token, "-----")) {
            bool is_base64_overrun = (strlen(base64) + strlen(token)) > 1024 ?
                true : false;
            if (is_base64_overrun) {
                return false;
            }
            strcat(base64, token);
        }
        token = strtok(NULL, "\n");
    }

    BYTE buffer[1024];
    size_t buffer_length = 0;
    int rc = tpm2_base64_decode(base64, buffer, &buffer_length);
    if(!rc){
        LOG_ERR("%s", "tpm2_base64_decode");
        return false;
    }

    TPM2B_DIGEST digest;
    rc = tpm2_openssl_hash_compute_data(TPM2_ALG_SHA256, buffer,
        buffer_length, &digest);
    if(!rc){
        LOG_ERR("%s", "tpm2_openssl_hash_compute_data");
        return false;
    }

    rc = tpm2_base64_encode(buffer, buffer_length, base64);
    if(!rc){
        LOG_ERR("%s", "tpm2_base64_decode");
        return false;
    }
    strcpy(fingerprint, "SHA256:");
    strcat(fingerprint, base64);

    fingerprint[strlen(fingerprint)-1] = 0; // remove trailing \n

    return true;
}

#define MAX_SESSION_CNT 3
tool_rc tpm2_util_aux_sessions_setup(ESYS_CONTEXT *ectx, uint8_t session_cnt,
    const char **session_path, ESYS_TR *session_handle,
    tpm2_session **session) {

    /*
     * If no aux sessions were specified, simply return.
     */
    if (!session_cnt) {
        return tool_rc_success;
    }

    if (session_cnt > MAX_SESSION_CNT) {
        LOG_ERR("A max of 3 sessions allowed");
        return tool_rc_general_error;
    }

    uint8_t session_idx = 0;
    for (session_idx = 0; session_idx < (session_cnt); session_idx++) {
        if (session_path[session_idx]) {
                tool_rc rc = tpm2_session_restore(ectx,
                    session_path[session_idx], false, &session[session_idx]);
            if (rc != tool_rc_success) {
                LOG_ERR("Could not restore aux-session #%s",
                session_path[session_idx]);
                return rc;
            }
            session_handle[session_idx] =
                tpm2_session_get_handle(session[session_idx]);
        }
    }

    return tool_rc_success;
}

static TPMI_ALG_HASH calc_phash_alg_from_phash_path(const char **phash_path) {

    if (!*phash_path) {
        return TPM2_ALG_ERROR;
    }

    /*
     * Expecting single token, so tokenize just once.
     */
    char *str = malloc(strlen(*phash_path) + 1);
    strcpy(str, *phash_path);
    char *token = strtok(str, ":");

    TPMI_ALG_HASH hashalg = tpm2_alg_util_from_optarg(
        token, tpm2_alg_util_flags_hash);
    /*
     * Adjust the pHash path to skip the <halg>:
     */
    if (hashalg != TPM2_ALG_ERROR) {
        *phash_path += strlen(token) + 1;
    }

    free(str);
    return hashalg;
}

static TPMI_ALG_HASH tpm2_util_calc_phash_algorithm_from_session_types(
    ESYS_CONTEXT *ectx, tpm2_session **sessions) {

    TPMI_ALG_HASH rethash = TPM2_ALG_ERROR;

    size_t session_idx = 0;
    for (session_idx = 0; session_idx < MAX_SESSION_CNT; session_idx++) {
        if(!sessions[session_idx]) {
            continue;
        }

        /*
         * Ignore password sessions
         */
        ESYS_TR session_handle = tpm2_session_get_handle(sessions[session_idx]);
        if(session_handle == ESYS_TR_PASSWORD) {
            continue;
        }

        /*
         * Ignore trial sessions
         */
        TPM2_SE session_type = tpm2_session_get_type(sessions[session_idx]);
        if (session_type != TPM2_SE_HMAC && session_type != TPM2_SE_POLICY) {
            continue;
        }

        /*
         * If this is an audit session, use that session halg.
         * Note: Audit sessions are always HMAC type.
         */
        if (session_type == TPM2_SE_HMAC) {
            TPMA_SESSION attrs = 0;
            tool_rc tmp_rc = tpm2_sess_get_attributes(ectx, session_handle,
                &attrs);
            UNUSED(tmp_rc);

            if (attrs & TPMA_SESSION_AUDIT) {
                rethash = tpm2_session_get_authhash(sessions[session_idx]);
                break;
            }
        }

        /*
         * If no other sessions remain, simply use (policy)sessions halg.
         */
        rethash = tpm2_session_get_authhash(sessions[session_idx]);
    }

    return rethash;
}

/*
 * It should be noted that the auths aren't checked when calculating the pHash,
 * instead the sessions are consumed to determine the pHash algorithm.
 *
 * 1. If phash_path is preceded with <halg>: use that as phash-halg return
 * Otherwise
 *
 *  Consume session only if it is a policy-session or an hmac-session
 *  1. If only hmac or policy session is specified, return that session's halg
 *  2. If hmac-session with audit is specified, return that session's halg
 *  3. If policy-session, then return policy-session's halg
 *
 * Otherwise
 *  return SHA256
 *
 */
TPMI_ALG_HASH tpm2_util_calculate_phash_algorithm(ESYS_CONTEXT *ectx,
    const char **cphash_path, TPM2B_DIGEST *cp_hash, const char **rphash_path,
    TPM2B_DIGEST *rp_hash, tpm2_session **sessions) {

    /* <halg> specified in pHash path */
    TPMI_ALG_HASH cphash_alg = cphash_path ? calc_phash_alg_from_phash_path(
        cphash_path) : TPM2_ALG_ERROR;

    TPMI_ALG_HASH rphash_alg = rphash_path ? calc_phash_alg_from_phash_path(
        rphash_path) : TPM2_ALG_ERROR;
    /*
     * Default to cphash_alg if both are specified.
     * This removes the conflict if cphash_alg and rphash_alg don't match.
     * This also sets the cphash_alg if only rphash_alg is specified and vice
     * versa.
     */
    TPMI_ALG_HASH phash_alg = cphash_alg != TPM2_ALG_ERROR ? cphash_alg :
        (rphash_alg != TPM2_ALG_ERROR ? rphash_alg : TPM2_ALG_ERROR);

    if (phash_alg != TPM2_ALG_ERROR) {
        goto out;
    }

    /* <halg> determined from the sessions */
    if (sessions) {
        phash_alg = tpm2_util_calc_phash_algorithm_from_session_types(ectx,
            sessions);
    }

out:
    /* <halg> defaults to TPM2_ALG_SHA256 if cannot find from path or sessions */
    if (phash_alg == TPM2_ALG_ERROR) {
        phash_alg = TPM2_ALG_SHA256;
    }

    /*
     * Side-effect: Set the size of the cp_hash and/or rp_hash
     */
    if (cphash_path && cp_hash) {
        cp_hash->size = tpm2_alg_util_get_hash_size(phash_alg);
    }

    if (rphash_path && rp_hash) {
        rp_hash->size = tpm2_alg_util_get_hash_size(phash_alg);
    }

    return phash_alg;
}

void tpm2_util_tpms_nv_pin_counter_parameters_to_yaml(TPMS_NV_PIN_COUNTER_PARAMETERS *pin_params, int indent) {
    print_yaml_indent(indent);
    tpm2_tool_output("pinCount: %u\n", pin_params->pinCount);
    print_yaml_indent(indent);
    tpm2_tool_output("pinLimit: %u\n", pin_params->pinLimit);
}

void tpm2_util_tpm2_nv_to_yaml(TPM2B_NV_PUBLIC *nv_public, UINT8 *data, UINT16 size, int indent) {
    int ds, i;
    UINT64 v;
    char *algstr;
    TPMS_NV_PIN_COUNTER_PARAMETERS pin_params;

    TPM2_NT nt = (nv_public->nvPublic.attributes & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT;
    switch (nt) {
    case TPM2_NT_COUNTER:
        memcpy(&v, data, sizeof(UINT64));
        v = be64toh(v);
        print_yaml_indent(indent);
        tpm2_tool_output("counter: %" PRIu64 "\n", v);
        break;
    case TPM2_NT_BITS:
        memcpy(&v, data, sizeof(UINT64));
        v = be64toh(v);
        print_yaml_indent(indent);
        tpm2_tool_output("bits: [");
        bool first = true;
        for (int i=0;i < 64;i++) {
	    if (!(((UINT64) 1 << i) & v)) {
	        continue;
	    }
	    if (first) {
	        first = false;
	        tpm2_tool_output(" %u", i);
	    } else {
	        tpm2_tool_output(", %u", i);
	    }
        }
        tpm2_tool_output(" ]\n");
        break;
    case TPM2_NT_EXTEND:
        algstr = (char *) tpm2_alg_util_algtostr(nv_public->nvPublic.nameAlg, tpm2_alg_util_flags_any);
        ds = tpm2_alg_util_get_hash_size(nv_public->nvPublic.nameAlg);
        print_yaml_indent(indent);
        tpm2_tool_output("%s: 0x", algstr);
        for (i=0;i < ds;i++) {
	    tpm2_tool_output("%02X", data[i]);
        }
        tpm2_tool_output("\n");
        break;
    case TPM2_NT_PIN_FAIL:
        Tss2_MU_TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(data, size, NULL, &pin_params);
	print_yaml_indent(indent);
	tpm2_tool_output("pinfail:\n");
	tpm2_util_tpms_nv_pin_counter_parameters_to_yaml(&pin_params, indent + 1);
	break;
    case TPM2_NT_PIN_PASS:
        Tss2_MU_TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(data, size, NULL, &pin_params);
	print_yaml_indent(indent);
	tpm2_tool_output("pinpass:\n");
	tpm2_util_tpms_nv_pin_counter_parameters_to_yaml(&pin_params, indent + 1);
	break;
    default:
        print_yaml_indent(indent);
	tpm2_tool_output("data: ");
	tpm2_util_hexdump(data, size);
	tpm2_tool_output("\n");
	break;
    }
}
