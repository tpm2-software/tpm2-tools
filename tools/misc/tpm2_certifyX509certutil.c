/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "tpm2_tool.h"
#include "log.h"

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

static int fixup_cert(const char *cert)
{
    int fd, r;
    ssize_t size;
    struct stat fs;
    char *buf;

    r = lstat(cert, &fs);
    if (r < 0) {
        return tool_rc_general_error;
    }

    size = fs.st_size;
    if (size < 100 || size > 255) {
        LOG_ERR("Wrong cert size %zd", size);
        return tool_rc_general_error; /* there is something wrong with this cert */
    }

    buf = calloc(1, size);
    if (!buf) {
        LOG_ERR("Alloc failed");
        return tool_rc_general_error;
    }

    fd = open(cert, O_RDONLY);
    if (fd < 0) {
        LOG_ERR("open failed");
        goto err_free;
    }

    r = read(fd, buf, size);
    if (r != size) {
        LOG_ERR("read failed");
        goto err_free;
    }

    close(fd);

    fd = open(cert, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        LOG_ERR("second open failed");
        free(buf);
        return tool_rc_general_error;
    }

    /* We need to skip one wrapping sequence (8 bytes) and one
     * sequence with one empty byte field at the end (5 bytes).
     * Fix the size here */
    buf[2] = size - 16;

    /* Write the external sequence with the fixed size */
    r = write(fd, buf, 3);
    if (r != 3) {
        LOG_ERR("write failed");
        goto err_free;
    }

    /* skip the wrapping sequence the write the rest
     * without the 5 bytes at the end */
    r = write(fd, buf + 11, size - 16);
    if (r != size - 16) {
        LOG_ERR("second write failed");
        goto err_free;
    }

    free(buf);
    close(fd);
    return tool_rc_success;

err_free:
    free(buf);
    close(fd);
    return tool_rc_general_error;
}

static int populate_fields(X509_NAME *name, const char *opt) {
    unsigned int fields_added = 0, i;
    char *name_opt = strdup(opt);
    const char *tok;

    if (!name_opt) {
        LOG_ERR("Alloc failed");
        return -1;
    }

    tok = strtok(name_opt, ";");

    while (tok != NULL) {
        LOG_INFO("Parsing token %s", tok);

        /* Loop through supported fields and add them if found */
        for (i = 0; i < ARRAY_LEN(names); i++) {
            const char *del = names[i].del;
            const char *fld =  names[i].field;
            unsigned int maxlen =  names[i].maxlen;
            size_t len = strlen(del);
            const char *ptr;
            int r;

            if (strncmp(tok, del, len) == 0) {
                if (strlen(tok + len) > maxlen || strlen(tok + len) == 0) {
                    LOG_WARN("Field %s too long or empty. Using default", fld);
                    ptr = names[i].def;
                } else {
                    ptr = tok + len;
                }
                LOG_INFO("Adding name field %s%s", del, ptr);
                r = X509_NAME_add_entry_by_txt(name, fld, MBSTRING_ASC,
                                               (const unsigned char *) ptr,
                                               -1, -1, 0);
                if (r != 1) {
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
    int r = tool_rc_success, fields_added;
    X509_EXTENSION *extv3 = NULL;
    X509 *cert;
    BIO *cert_out;

    cert_out = BIO_new_file(ctx.out_path, "wb");
    if (!cert_out) {
        LOG_ERR("Can not create file %s", ctx.out_path);
        return -1;
    }

    cert = X509_new();
    if (!cert) {
        LOG_ERR("X509_new");
        goto out_err;
    }

    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (!issuer) {
        LOG_ERR("X509_get_issuer_name");
        goto out_err;
    }

    fields_added = populate_fields(issuer, ctx.issuer);
    if (fields_added <= 0) {
        LOG_ERR("Could not parse any issuer fields");
        goto out_err;
    } else {
        LOG_INFO("Added %d issuer fields", fields_added);
    }

    r = X509_set_issuer_name(cert, issuer); // add issuer
    if (r != 1) {
        LOG_ERR("X509_set_issuer_name");
        goto out_err;
    }

    unsigned int valid_days;
    if (!tpm2_util_string_to_uint32(ctx.valid_str, &valid_days)) {
        LOG_ERR("string_to_uint32");
        goto out_err;
    }

    X509_gmtime_adj(X509_get_notBefore(cert), 0); // add valid not before
    X509_gmtime_adj(X509_get_notAfter(cert), valid_days * 86400); // add valid not after

    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject) {
        LOG_ERR("X509_get_subject_name");
        goto out_err;
    }

    fields_added = populate_fields(subject, ctx.subject);
    if (fields_added <= 0) {
        LOG_ERR("Could not parse any subject fields");
        goto out_err;
    } else {
        LOG_INFO("Added %d subject fields", fields_added);
    }

    r = X509_set_subject_name(cert, subject);  // add subject
    if (r != 1) {
        LOG_ERR("X509_NAME_add_entry_by_txt");
        goto out_err;
    }

    extv3 = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    if (!extv3) {
        LOG_ERR("X509V3_EXT_conf_nid");
        goto out_err;
    }

    r = X509_add_ext(cert, extv3, -1); // add required v3 extention: key usage
    if (r != 1) {
        LOG_ERR("X509_add_ext");
        goto out_err;
    }
    r = i2d_X509_bio(cert_out, cert); // print cert in DER format
    if (r != 1) {
        LOG_ERR("i2d_X509_bio");
        goto out_err;
    }

    X509_EXTENSION_free(extv3);
    X509_free(cert);
    BIO_free_all(cert_out);

    r = fixup_cert(ctx.out_path);
    if (r) {
        LOG_ERR("fixup_cert");
        return tool_rc_general_error;
    }

    return tool_rc_success;

out_err:
    BIO_free_all(cert_out);
    if (cert) {
        X509_free(cert);
    }
    if (extv3) {
        X509_EXTENSION_free(extv3);
    }

    return tool_rc_general_error;
}


static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    return generate_partial_X509();
}

TPM2_TOOL_REGISTER("certifyX509certutil", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
