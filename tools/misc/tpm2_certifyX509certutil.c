/* SPDX-License-Identifier: BSD-3-Clause */

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

#include "log.h"
#include "tpm2_tool.h"

typedef struct {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
} TPM2_PARTIAL_CERT_VALIDITY;

typedef struct {
    X509_ALGOR *algorithm;
    X509_NAME *issuer;
    TPM2_PARTIAL_CERT_VALIDITY *validity;
    X509_NAME *subject;
    STACK_OF(X509_EXTENSION) *extensions;
} TPM2_PARTIAL_CERT;

ASN1_SEQUENCE(TPM2_PARTIAL_CERT_VALIDITY) = {
    ASN1_SIMPLE(TPM2_PARTIAL_CERT_VALIDITY, notBefore, ASN1_TIME),
    ASN1_SIMPLE(TPM2_PARTIAL_CERT_VALIDITY, notAfter, ASN1_TIME),
} ASN1_SEQUENCE_END(TPM2_PARTIAL_CERT_VALIDITY)

/* partialCertificate per Part 3, 18.8.1 */
ASN1_SEQUENCE(TPM2_PARTIAL_CERT) = {
    ASN1_OPT(TPM2_PARTIAL_CERT, algorithm, X509_ALGOR),
    ASN1_SIMPLE(TPM2_PARTIAL_CERT, issuer, X509_NAME),
    ASN1_SIMPLE(TPM2_PARTIAL_CERT, validity, TPM2_PARTIAL_CERT_VALIDITY),
    ASN1_SIMPLE(TPM2_PARTIAL_CERT, subject, X509_NAME),
    ASN1_EXP_SEQUENCE_OF(TPM2_PARTIAL_CERT, extensions, X509_EXTENSION, 3),
} ASN1_SEQUENCE_END(TPM2_PARTIAL_CERT)

IMPLEMENT_ASN1_FUNCTIONS(TPM2_PARTIAL_CERT)

int i2d_TPM2_PARTIAL_CERT_bio(BIO *bp, const TPM2_PARTIAL_CERT *a)
{
    return ASN1_i2d_bio_of(TPM2_PARTIAL_CERT, i2d_TPM2_PARTIAL_CERT, bp, a);
}

int TPM2_add_ext(TPM2_PARTIAL_CERT *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->extensions), ex, loc) != NULL);
}


struct tpm_gen_partial_cert {
    const char *out_path;
    const char *valid_str;
    const char *subject;
    const char *issuer;
};

#define CERT_FILE "partial_cert.der"
#define VALID_DAYS "3560"
#define SUBJ "C=US;O=CA org;OU=CA unit;CN=example"
#define ISSUER "C=US;O=CA org;OU=CA unit;CN=example"

static struct tpm_gen_partial_cert ctx = {
    .out_path = CERT_FILE,
    .valid_str = VALID_DAYS,
    .subject = SUBJ,
    .issuer = ISSUER
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.out_path = value;
        break;
    case 'd':
        ctx.valid_str = value;
        break;
    case 's':
        ctx.subject = value;
        break;
    case 'i':
        ctx.issuer = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "outcert", optional_argument, NULL, 'o' },
      { "days",    optional_argument, NULL, 'd' },
      { "subject", optional_argument, NULL, 's' },
      { "issuer", optional_argument, NULL, 'i' }
    };

    *opts = tpm2_options_new("o:d:s:i:", ARRAY_LEN(topts), topts, on_option,
                             NULL, TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

struct name_fields {
    const char *field;
    const char *del;
    const char *def;
    int maxlen;
};

static struct name_fields names[] = {
    { .field = "CN",
      .del = "CN=",
      .maxlen = 8,
      .def = "default" },
    { .field = "C",
      .del = "C=",
      .maxlen = 2,
      .def = "US" },
    { .field = "O",
      .del = "O=",
      .maxlen = 8,
      .def = "CA Org" },
    { .field = "OU",
      .del = "OU=",
      .maxlen = 8,
      .def = "CA Unit" },
};

static int populate_fields(X509_NAME *name, const char *opt) {

    char *name_opt = strdup(opt);
    if (!name_opt) {
        LOG_ERR("Alloc failed");
        return -1;
    }

    const char *tok = strtok(name_opt, ";");

    unsigned i = 0;
    int fields_added = 0;
    while (tok != NULL) {
        LOG_INFO("Parsing token %s", tok);

        /* Loop through supported fields and add them if found */
        for (i = 0; i < ARRAY_LEN(names); i++) {
            const char *del = names[i].del;
            const char *fld =  names[i].field;
            unsigned int maxlen =  names[i].maxlen;
            size_t len = strlen(del);
            const char *ptr;

            if (strncmp(tok, del, len) == 0) {
                if (strlen(tok + len) > maxlen || strlen(tok + len) == 0) {
                    LOG_WARN("Field %s too long or empty. Using default", fld);
                    ptr = names[i].def;
                } else {
                    ptr = tok + len;
                }
                LOG_INFO("Adding name field %s%s", del, ptr);
                int ret = X509_NAME_add_entry_by_txt(name, fld, MBSTRING_ASC,
                                               (const unsigned char *) ptr,
                                               -1, -1, 0);
                if (ret != 1) {
                    free(name_opt);
                    LOG_ERR("X509_NAME_add_entry_by_txt");
                    return -1;
                }
                fields_added++;
            }
        }
        tok = strtok(NULL, ";");
    }

    free(name_opt);

    return fields_added;
}

static tool_rc generate_partial_X509() {

    BIO *cert_out = BIO_new_file(ctx.out_path, "wb");
    if (!cert_out) {
        LOG_ERR("Can not create file %s", ctx.out_path);
        return -1;
    }

    X509_EXTENSION *extv3 = NULL;
    TPM2_PARTIAL_CERT *cert = TPM2_PARTIAL_CERT_new();
    if (!cert) {
        LOG_ERR("TPM2_PARTIAL_CERT_new");
        goto out_err;
    }

    /* populate issuer */
    int fields_added = populate_fields(cert->issuer, ctx.issuer);
    if (fields_added <= 0) {
        LOG_ERR("Could not parse any issuer fields");
        goto out_err;
    } else {
        LOG_INFO("Added %d issuer fields", fields_added);
    }

    /* populate validity */
    unsigned int valid_days;
    if (!tpm2_util_string_to_uint32(ctx.valid_str, &valid_days)) {
        LOG_ERR("string_to_uint32");
        goto out_err;
    }

    X509_gmtime_adj(cert->validity->notBefore, 0); // add valid not before
    X509_gmtime_adj(cert->validity->notAfter, valid_days * 86400); // add valid not after

    /* populate subject */
    fields_added = populate_fields(cert->subject, ctx.subject);
    if (fields_added <= 0) {
        LOG_ERR("Could not parse any subject fields");
        goto out_err;
    } else {
        LOG_INFO("Added %d subject fields", fields_added);
    }

    /* populate extensions */
    extv3 = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                "critical,digitalSignature,keyCertSign,cRLSign");
    if (!extv3) {
        LOG_ERR("X509V3_EXT_conf_nid");
        goto out_err;
    }

    int ret = TPM2_add_ext(cert, extv3, -1); // add required v3 extention: key usage
    if (ret != 1) {
        LOG_ERR("X509_add_ext");
        goto out_err;
    }

    /* output */
    ret = i2d_TPM2_PARTIAL_CERT_bio(cert_out, cert); // print cert in DER format
    if (ret != 1) {
        LOG_ERR("i2d_X509_bio");
        goto out_err;
    }

    X509_EXTENSION_free(extv3);
    TPM2_PARTIAL_CERT_free(cert);
    BIO_free_all(cert_out);

    return tool_rc_success;

out_err:
    BIO_free_all(cert_out);
    X509_EXTENSION_free(extv3);
    TPM2_PARTIAL_CERT_free(cert);

    return tool_rc_general_error;
}


static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    return generate_partial_X509();
}

TPM2_TOOL_REGISTER("certifyX509certutil", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
