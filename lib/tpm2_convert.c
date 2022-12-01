/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path);

tpm2_convert_pcrs_output_fmt tpm2_convert_pcrs_output_fmt_from_optarg(
    const char *label) {

    if (strcasecmp(label, "values") == 0) {
        return pcrs_output_format_values;
    } else if (strcasecmp(label, "serialized") == 0) {
        return pcrs_output_format_serialized;
    }

    LOG_ERR("Invalid pcrs output format '%s' specified", label);

    return pcrs_output_format_err;
}

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

EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public) {

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa_key = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#endif
    BIGNUM *e = NULL, *n = NULL;
    EVP_PKEY *pkey = NULL;

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size, NULL);
    if (!n) {
        print_ssl_error("Failed to convert data to SSL internal format");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rsa_key = RSA_new();
    if (!rsa_key) {
        print_ssl_error("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_new();
    if (!e) {
        print_ssl_error("Failed to convert data to SSL internal format");
        goto error;
    }
    int rc = BN_set_word(e, exponent);
    if (!rc) {
        print_ssl_error("Failed to convert data to SSL internal format");
        goto error;
    }

    rc = RSA_set0_key(rsa_key, n, e, NULL);
    if (!rc) {
        print_ssl_error("Failed to set RSA modulus and exponent components");
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) {
        print_ssl_error("Failed to allocate OpenSSL EVP structure");
        goto error;
    }

    rc = EVP_PKEY_assign_RSA(pkey, rsa_key);
    if (!rc) {
        print_ssl_error("Failed to set OpenSSL EVP structure");
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto error;
    }
    /* rsa key is now owner by the EVP_PKEY struct */
    rsa_key = NULL;
#else
    build = OSSL_PARAM_BLD_new();
    if (!build) {
        print_ssl_error("Failed to allocate OpenSSL parameters");
        goto error;
    }

    int rc = OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n);
    if (!rc) {
        print_ssl_error("Failed to set RSA modulus");
        goto error;
    }

    rc = OSSL_PARAM_BLD_push_uint32(build, OSSL_PKEY_PARAM_RSA_E, exponent);
    if (!rc) {
        print_ssl_error("Failed to set RSA exponent");
        goto error;
    }

    params = OSSL_PARAM_BLD_to_param(build);
    if (!params) {
        print_ssl_error("Failed to build OpenSSL parameters");
        goto error;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        print_ssl_error("Failed to allocate RSA key context");
        goto error;
    }

    rc = EVP_PKEY_fromdata_init(ctx);
    if (rc <= 0) {
        print_ssl_error("Failed to initialize RSA key creation");
        goto error;
    }

    rc = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc <= 0) {
        print_ssl_error("Failed to create a RSA public key");
        goto error;
    }
#endif
error:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsa_key);
#else
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
#endif
    BN_free(n);
    BN_free(e);
    return pkey;
}

EVP_PKEY *convert_pubkey_ECC(TPMT_PUBLIC *public) {

    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_POINT *point = NULL;
    EC_GROUP *group = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EC_KEY *ec_key = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *puboct = NULL;
    size_t bsize;
#endif
    EVP_PKEY *pkey = NULL;

    TPMS_ECC_PARMS *tpm_ecc = &public->parameters.eccDetail;
    TPMS_ECC_POINT *tpm_point = &public->unique.ecc;

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

    int nid = tpm2_ossl_curve_to_nid(tpm_ecc->curveID);
    if (nid < 0) {
        goto out;
    }

    /*
     * Create a new point in the group, which is the public key.
     */
    group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        print_ssl_error("EC key missing group");
        goto out;
    }

    point = EC_POINT_new(group);

    int rc = EC_POINT_set_affine_coordinates_tss(group, point, x, y, NULL);
    if (!rc) {
        print_ssl_error("Could not set affine coordinates");
        goto out;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /*
     * Create an empty EC key by the NID
     */
    ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) {
        print_ssl_error("Failed to create EC key from nid");
        return false;
    }

    rc = EC_KEY_set_public_key(ec_key, point);
    if (!rc) {
        print_ssl_error("Could not set point as public key portion");
        goto out;
    }

    if ((pkey = EVP_PKEY_new()) == NULL) {
        print_ssl_error("Failed to allocate OpenSSL EVP structure");
        goto out;
    }

    rc = EVP_PKEY_assign_EC_KEY(pkey, ec_key);
    if (!rc) {
        print_ssl_error("Failed to set OpenSSL EVP structure");
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto out;
    }
    /* rsa key is now owner by the EVP_PKEY struct */
    ec_key = NULL;
#else
    build = OSSL_PARAM_BLD_new();
    if (!build) {
        print_ssl_error("Failed to allocate OpenSSL parameters");
        goto out;
    }

    rc = OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)OBJ_nid2sn(nid), 0);
    if (!rc) {
        print_ssl_error("Failed to set the EC group name");
        goto out;
    }

    bsize = EC_POINT_point2buf(group, point,
                               POINT_CONVERSION_COMPRESSED,
                               &puboct, NULL);
    if (bsize == 0) {
        print_ssl_error("Failed compress the EC public key");
        goto out;
    }

    rc = OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
                                          puboct, bsize);
    if (!rc) {
        print_ssl_error("Failed set the EC public key");
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(build);
    if (!params) {
        print_ssl_error("Failed to build OpenSSL parameters");
        goto out;
    }

    if (nid == NID_sm2) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    } else {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    }
    if (!ctx) {
        print_ssl_error("Failed to allocate EC key context");
        goto out;
    }

    rc = EVP_PKEY_fromdata_init(ctx);
    if (rc <= 0) {
        print_ssl_error("Failed to initialize EC key creation");
        goto out;
    }

    rc = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc <= 0) {
        print_ssl_error("Failed to create a EC public key");
        goto out;
    }
#endif

out:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EC_KEY_free(ec_key);
#else
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
    OPENSSL_free(puboct);
#endif
    EC_POINT_free(point);
    EC_GROUP_free(group);
    BN_free(x);
    BN_free(y);
    return pkey;
}

static bool tpm2_convert_pubkey_bio(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, BIO *bio) {

    EVP_PKEY *pubkey = NULL;
    int ssl_res = 0;

    switch (public->type) {
    case TPM2_ALG_RSA:
        pubkey = convert_pubkey_RSA(public);
        break;
    case TPM2_ALG_ECC:
        pubkey = convert_pubkey_ECC(public);
        break;
    default:
        LOG_ERR("Unsupported key type for requested output format.");
    }

    if (pubkey == NULL)
        return false;

    switch (format) {
    case pubkey_format_pem:
        ssl_res = PEM_write_bio_PUBKEY(bio, pubkey);
        break;
    case pubkey_format_der:
        ssl_res = i2d_PUBKEY_bio(bio, pubkey);
        break;
    default:
        LOG_ERR("Invalid OpenSSL target format %d encountered", format);
    }

    EVP_PKEY_free(pubkey);

    if (ssl_res <= 0) {
        print_ssl_error("OpenSSL public key conversion failed");
        return false;
    }

    return true;
}

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path) {

    BIO *bio = path ? BIO_new_file(path, "wb") : BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio) {
        LOG_ERR("Failed to open public key output file '%s': %s", path ? path : "<stdin>",
                ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    bool result = tpm2_convert_pubkey_bio(public, format, bio);
    BIO_free(bio);
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
    bool res = false;
    switch (sig_alg) {
    case TPM2_ALG_RSASSA:
        signature->signature.rsassa.hash = halg;
        signature->signature.rsassa.sig.size =
                sizeof(signature->signature.rsassa.sig.buffer);
        res = files_load_bytes_from_path(path,
                signature->signature.rsassa.sig.buffer,
                &signature->signature.rsassa.sig.size);
        return res;
    case TPM2_ALG_RSAPSS:
        signature->signature.rsapss.hash = halg;
        signature->signature.rsapss.sig.size =
                sizeof(signature->signature.rsapss.sig.buffer);
        res = files_load_bytes_from_path(path,
                signature->signature.rsapss.sig.buffer,
                &signature->signature.rsapss.sig.size);
        return res;
    case TPM2_ALG_ECDSA:
    case TPM2_ALG_SM2:
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

bool tpm2_convert_sig_load_plain(const char *path,
        TPM2B_MAX_BUFFER *signature, TPMI_ALG_HASH *halg) {

    /*
     * TSS signature need be read and converted to plain
     *
     * So load it up into the TPMT Structure
     */
    TPMT_SIGNATURE tmp = { 0 };
    bool ret = files_load_signature_silent(path, &tmp);
    if (!ret) {
        /* plain signatures are just used as is */

        *halg = TPM2_ALG_NULL;

        signature->size = sizeof(signature->buffer);
        return files_load_bytes_from_path(path,
                signature->buffer,
                &signature->size);
    }

    *halg = tmp.signature.any.hashAlg;

    /* Then convert it to plain, but into a buffer */
    UINT8 *buffer;
    UINT16 size;

    buffer = tpm2_convert_sig(&size, &tmp);
    if (buffer == NULL) {
        return false;
    }

    if (size > sizeof(signature->buffer)) {
        LOG_ERR("Signature size bigger than buffer, got: %u expected"
                " less than %zu", size, sizeof(signature->buffer));
        free(buffer);
        return false;
    }

    signature->size = size;
    memcpy(signature->buffer, buffer, size);
    free(buffer);
    return true;
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
    case TPM2_ALG_ECDSA:
    case TPM2_ALG_SM2: {
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

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey) {

    bool result = false;

    BIO *bio = NULL;
    EVP_PKEY *p = NULL;

    /*
     * Order Matters. You must check for the smallest TSS size first, which
     * it the TPMT_PUBLIC as it's embedded in the TPM2B_PUBLIC. It's possible
     * to have valid TPMT's and have them parse as valid TPM2B_PUBLIC's (apparantly).
     *
     * If none of them convert, we try it as a plain signature.
     */
    TPM2B_PUBLIC public = { 0 };
    bool ret = files_load_template_silent(path, &public.publicArea);
    if (ret) {
        goto convert_to_pem;
    }

    ret = files_load_public_silent(path, &public);
    if (ret) {
        goto convert_to_pem;
    }

    /* not a tss format, just treat it as a pem file */
    bio = BIO_new_file(path, "rb");
    if (!bio) {
        LOG_ERR("Failed to open public key output file '%s': %s", path,
                ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    /* not a tpm data structure, must be pem */
    goto try_pem;

convert_to_pem:
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        LOG_ERR("Failed to allocate memory bio: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    ret = tpm2_convert_pubkey_bio(&public.publicArea, pubkey_format_pem, bio);
    if (!ret) {
        goto out;
    }

try_pem:
    p = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!p) {
        LOG_ERR("Failed to convert public key from file '%s': %s", path,
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    *pkey = p;

    result = true;

out:
    if (bio) {
        BIO_free(bio);
    }

    return result;
}

bool tpm2_base64_encode(BYTE *buffer, size_t buffer_length, char *base64) {

    unsigned char out[1024];
    int outl;

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(ctx);

    int rc = EVP_EncodeUpdate(ctx, out, &outl, buffer, buffer_length);
    if(rc < 0) {
        LOG_ERR("EVP_DecodeUpdate failed with %d\n", rc);
        EVP_ENCODE_CTX_free(ctx);
        return false;
    }

    EVP_EncodeFinal(ctx, out, &outl); // no return value

    EVP_ENCODE_CTX_free(ctx);

    strcpy(base64, (char*) out);

    return true;
}

bool tpm2_base64_decode(char *base64, BYTE *buffer, size_t *buffer_length) {

    bool is_base64_bufferlen_valid = strlen(base64) > 1024 ? false : true;
    if (!is_base64_bufferlen_valid) {
        return false;
    }

    unsigned char base64u[1024];
    memcpy(base64u, base64, strlen(base64));

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    unsigned char out[1024];
    int outl;
    int rc = EVP_DecodeUpdate(ctx, out, &outl, base64u, strlen(base64));
    if(rc < 0) {
        LOG_ERR("EVP_DecodeUpdate failed with %d\n", rc);
        EVP_ENCODE_CTX_free(ctx);
        return false;
    }

    *buffer_length = outl;

    rc = EVP_DecodeFinal(ctx, out, &outl);
    if(rc < 0) {
        LOG_ERR("EVP_DecodeFinal failed with %d\n", rc);
        EVP_ENCODE_CTX_free(ctx);
        return false;
    }

    EVP_ENCODE_CTX_free(ctx);

    *buffer_length += outl;
    memcpy(buffer, out, *buffer_length);

    return true;
}
