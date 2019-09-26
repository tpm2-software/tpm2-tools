/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/pem.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path);

tpm2_convert_pubkey_fmt tpm2_convert_pubkey_fmt_from_optarg(const char *label) {
    if (strcasecmp(label, "der") == 0) {
        return pubkey_format_der;
    } else if (strcasecmp(label, "pem") == 0) {
        return pubkey_format_pem;
    } else if (strcasecmp(label, "tss") == 0) {
        return pubkey_format_tss;
    } else if (strcasecmp(label, "tpmt") == 0) {
        return pubkey_format_tpmt;
    }

    LOG_ERR("Invalid public key output format '%s' specified", label);

    return pubkey_format_err;
}

tpm2_convert_sig_fmt tpm2_convert_sig_fmt_from_optarg(const char *label) {
    if (strcasecmp(label, "tss") == 0) {
        return signature_format_tss;
    } else if (strcasecmp(label, "plain") == 0) {
        return signature_format_plain;
    }

    LOG_ERR("Invalid signature output format '%s' specified", label);

    return signature_format_err;
}

static void print_ssl_error(const char *failed_action) {
    char errstr[256] = { 0 };
    unsigned long errnum = ERR_get_error();

    ERR_error_string_n(errnum, errstr, sizeof(errstr));
    LOG_ERR("%s: %s", failed_action, errstr);
}

bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path) {

    if (format == pubkey_format_der || format == pubkey_format_pem) {
        return tpm2_convert_pubkey_ssl(&public->publicArea, format, path);
    } else if (format == pubkey_format_tss) {
        return files_save_public(public, path);
    } else if (format == pubkey_format_tpmt) {
        return files_save_template(&public->publicArea, path);
    }

    LOG_ERR("Unsupported public key output format.");
    return false;
}

static bool convert_pubkey_RSA(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, FILE *fp) {

    bool ret = false;
    RSA *ssl_rsa_key = NULL;
    BIGNUM *e = NULL, *n = NULL;

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    // OpenSSL expects this in network byte order
    exponent = tpm2_util_hton_32(exponent);
    ssl_rsa_key = RSA_new();
    if (!ssl_rsa_key) {
        print_ssl_error("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_bin2bn((void*) &exponent, sizeof(exponent), NULL);
    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size,
    NULL);

    if (!n || !e) {
        print_ssl_error("Failed to convert data to SSL internal format");
        goto error;
    }

    if (!RSA_set0_key(ssl_rsa_key, n, e, NULL)) {
        print_ssl_error("Failed to set RSA modulus and exponent components");
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    int ssl_res = 0;

    switch (format) {
    case pubkey_format_pem:
        ssl_res = PEM_write_RSA_PUBKEY(fp, ssl_rsa_key);
        break;
    case pubkey_format_der:
        ssl_res = i2d_RSA_PUBKEY_fp(fp, ssl_rsa_key);
        break;
    default:
        LOG_ERR("Invalid OpenSSL target format %d encountered", format);
        goto error;
    }

    if (ssl_res <= 0) {
        print_ssl_error("OpenSSL public key conversion failed");
        goto error;
    }

    ret = true;

    error: if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }
    if (ssl_rsa_key) {
        RSA_free(ssl_rsa_key);
    }

    return ret;
}

static bool convert_pubkey_ECC(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, FILE *fp) {

    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_KEY *key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    bool result = false;

    TPMS_ECC_PARMS *tpm_ecc = &public->parameters.eccDetail;
    TPMS_ECC_POINT *tpm_point = &public->unique.ecc;

    int nid = tpm2_ossl_curve_to_nid(tpm_ecc->curveID);
    if (nid < 0) {
        return false;
    }

    /*
     * Create an empty EC key by the NID
     */
    key = EC_KEY_new_by_curve_name(nid);
    if (!key) {
        print_ssl_error("Failed to create EC key from nid");
        return false;
    }

    group = EC_KEY_get0_group(key);
    if (!group) {
        print_ssl_error("EC key missing group");
        goto out;
    }

    /*
     * Create a new point in the group, which is the public key.
     */
    point = EC_POINT_new(group);

    /*
     * Set the affine coordinates for the point
     */
    x = BN_bin2bn(tpm_point->x.buffer, tpm_point->x.size, NULL);
    if (!x) {
        print_ssl_error("Could not convert x coordinate to BN");
        goto out;
    }

    y = BN_bin2bn(tpm_point->y.buffer, tpm_point->y.size, NULL);
    if (!y) {
        print_ssl_error("Could not convert y coordinate to BN");
        goto out;
    }

    int rc = EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL);
    if (!rc) {
        print_ssl_error("Could not set affine coordinates");
        goto out;
    }

    rc = EC_KEY_set_public_key(key, point);
    if (!rc) {
        print_ssl_error("Could not set point as public key portion");
        goto out;
    }

    int ssl_res = 0;

    switch (format) {
    case pubkey_format_pem:
        ssl_res = PEM_write_EC_PUBKEY(fp, key);
        break;
    case pubkey_format_der:
        ssl_res = i2d_EC_PUBKEY_fp(fp, key);
        break;
    default:
        LOG_ERR("Invalid OpenSSL target format %d encountered", format);
        goto out;
    }

    if (ssl_res <= 0) {
        print_ssl_error("OpenSSL public key conversion failed");
        goto out;
    }

    result = true;

out:
    if (x) {
        BN_free(x);
    }
    if (y) {
        BN_free(y);
    }
    if (point) {
        EC_POINT_free(point);
    }
    if (key) {
        EC_KEY_free(key);
    }

    return result;
}

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path) {

    bool result = false;

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        LOG_ERR("Failed to open public key output file '%s': %s", path,
                strerror(errno));
        goto out;
    }

    switch (public->type) {
    case TPM2_ALG_RSA:
        result = convert_pubkey_RSA(public, format, fp);
        break;
    case TPM2_ALG_ECC:
        result = convert_pubkey_ECC(public, format, fp);
        break;
    default:
        LOG_ERR(
                "Unsupported key type for requested output format. Only RSA is supported.");
    }

    fclose(fp);

out:
    ERR_free_strings();
    return result;
}

bool tpm2_convert_sig_save(TPMT_SIGNATURE *signature,
        tpm2_convert_sig_fmt format, const char *path) {

    switch (format) {
    case signature_format_tss:
        return files_save_signature(signature, path);
    case signature_format_plain: {
        UINT8 *buffer;
        UINT16 size;

        buffer = tpm2_convert_sig(&size, signature);
        if (buffer == NULL) {
            return false;
        }

        bool ret = files_save_bytes_to_file(path, buffer, size);
        free(buffer);
        return ret;
    }
    default:
        LOG_ERR("Unsupported signature output format.");
        return false;
    }
}

/**
 * Parses the ASN1 format for an ECDSA Signature
 *
 * The ASN1 format for ECDSA signature is: https://www.ietf.org/rfc/rfc5480.txt
 *   ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
 *
 * @param path
 * @param ecdsa
 * @return
 */
static bool pop_ecdsa(const char *path, TPMS_SIGNATURE_ECDSA *ecdsa) {

    TPM2B_MAX_BUFFER buf = { .size = sizeof(buf.buffer) };

    bool res = files_load_bytes_from_path(path, buf.buffer, &buf.size);
    if (!res) {
        return res;
    }

    int tag;
    int class;
    long len;
    const unsigned char *p = buf.buffer;

    int j = ASN1_get_object(&p, &len, &tag, &class, buf.size);
    if (!(j & V_ASN1_CONSTRUCTED)) {
        LOG_ERR("Expected ECDSA signature to start as ASN1 Constructed object");
        return false;
    }

    if (tag != V_ASN1_SEQUENCE) {
        LOG_ERR("Expected ECDSA signature to be an ASN1 sequence");
        return false;
    }

    /*
     * Get R
     */
    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    ASN1_INTEGER *r = d2i_ASN1_INTEGER(NULL, &p, len);
    if (!r) {
        LOG_ERR("oom");
        return false;
    }
    memcpy(R->buffer, r->data, r->length);
    R->size = r->length;
    ASN1_INTEGER_free(r);

    /*
     * Get S
     */
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;
    ASN1_INTEGER *s = d2i_ASN1_INTEGER(NULL, &p, len);
    if (!s) {
        LOG_ERR("oom");
        return false;
    }
    memcpy(S->buffer, s->data, s->length);
    S->size = s->length;
    ASN1_INTEGER_free(s);

    return true;
}

static bool sig_load(const char *path, TPMI_ALG_SIG_SCHEME sig_alg,
        TPMI_ALG_HASH halg, TPMT_SIGNATURE *signature) {

    signature->sigAlg = sig_alg;

    switch (sig_alg) {
    case TPM2_ALG_RSASSA:
        signature->signature.rsassa.hash = halg;
        signature->signature.rsassa.sig.size =
                sizeof(signature->signature.rsassa.sig.buffer);
        bool res = files_load_bytes_from_path(path,
                signature->signature.rsassa.sig.buffer,
                &signature->signature.rsassa.sig.size);
        return res;
    case TPM2_ALG_ECDSA:
        signature->signature.ecdsa.hash = halg;
        return pop_ecdsa(path, &signature->signature.ecdsa);
    default:
        LOG_ERR("Unsupported signature input format.");
        return false;
    }
}

bool tpm2_convert_sig_load(const char *path, tpm2_convert_sig_fmt format,
        TPMI_ALG_SIG_SCHEME sig_alg, TPMI_ALG_HASH halg,
        TPMT_SIGNATURE *signature) {

    switch (format) {
    case signature_format_tss:
        return files_load_signature(path, signature);
    case signature_format_plain:
        return sig_load(path, sig_alg, halg, signature);
    default:
        LOG_ERR("Unsupported signature input format.");
        return false;
    }
}

static UINT8 *extract_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, UINT16 *size) {

    /* the DER encoded ECDSA signature */
    unsigned char *buf = NULL;

    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        return NULL;
    }

    BIGNUM *bn_r = BN_bin2bn(R->buffer, R->size, NULL);
    if (!bn_r) {
        goto out;
    }

    BIGNUM *bn_s = BN_bin2bn(S->buffer, S->size, NULL);
    if (!bn_s) {
        BN_free(bn_r);
        goto out;
    }

    int rc = ECDSA_SIG_set0(sig, bn_r, bn_s);
    if (rc != 1) {
        BN_free(bn_r);
        BN_free(bn_s);
        goto out;
    }

    /*
     * r and s are now owned by the ecdsa signature no need
     * to free
     */

    int len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        goto out;
    }

    buf = malloc(len);
    if (!buf) {
        goto out;
    }

    unsigned char *pp = buf;
    len = i2d_ECDSA_SIG(sig, &pp);
    if (len <= 0) {
        free(buf);
        buf = NULL;
        goto out;
    }

    *size = len;
    /* success */

out:
    ECDSA_SIG_free(sig);

    return buf;
}

UINT8 *tpm2_convert_sig(UINT16 *size, TPMT_SIGNATURE *signature) {

    UINT8 *buffer = NULL;
    *size = 0;

    switch (signature->sigAlg) {
    case TPM2_ALG_RSASSA:
        *size = signature->signature.rsassa.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsassa.sig.buffer, *size);
        break;
    case TPM2_ALG_RSAPSS:
        *size = signature->signature.rsapss.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsapss.sig.buffer, *size);
        break;
    case TPM2_ALG_HMAC: {
        TPMU_HA *hmac_sig = &(signature->signature.hmac.digest);
        *size = tpm2_alg_util_get_hash_size(signature->signature.hmac.hashAlg);
        if (*size == 0) {
            LOG_ERR("Hash algorithm %d has 0 size",
                    signature->signature.hmac.hashAlg);
            goto nomem;
        }
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, hmac_sig, *size);
        break;
    }
    case TPM2_ALG_ECDSA: {
        return extract_ecdsa(&signature->signature.ecdsa, size);
    }
    default:
        LOG_ERR("%s: unknown signature scheme: 0x%x", __func__,
                signature->sigAlg);
        return NULL;
    }

    return buffer;
nomem:
    LOG_ERR("%s: couldn't allocate memory", __func__);
    return NULL;
}
