/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_capability.h"
#include "tpm2_tool.h"

typedef struct tpm_getekcertificate_ctx tpm_getekcertificate_ctx;
struct tpm_getekcertificate_ctx {
    char *ec_cert_path;
    FILE *ec_cert_file_handle;
    char *ek_server_addr;
    unsigned int SSL_NO_VERIFY;
    char *ek_path;
    bool verbose;
    bool is_tpm2_device_active;
    TPM2B_PUBLIC *out_public;
};

static tpm_getekcertificate_ctx ctx = {
    .is_tpm2_device_active = true,
    .ek_server_addr = "https://ekop.intel.com/ekcertservice/",
};

static unsigned char *hash_ek_public(void) {

    unsigned char *hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        LOG_ERR("OOM");
        return NULL;
    }

    SHA256_CTX sha256;
    int is_success = SHA256_Init(&sha256);
    if (!is_success) {
        LOG_ERR("SHA256_Init failed");
        goto err;
    }

    switch (ctx.out_public->publicArea.type) {
    case TPM2_ALG_RSA:
        is_success = SHA256_Update(&sha256,
                ctx.out_public->publicArea.unique.rsa.buffer,
                ctx.out_public->publicArea.unique.rsa.size);
        if (!is_success) {
            LOG_ERR("SHA256_Update failed");
            goto err;
        }

        if (ctx.out_public->publicArea.parameters.rsaDetail.exponent != 0) {
            LOG_ERR("non-default exponents unsupported");
            goto err;
        }
        BYTE buf[3] = { 0x1, 0x00, 0x01 }; // Exponent
        is_success = SHA256_Update(&sha256, buf, sizeof(buf));
        if (!is_success) {
            LOG_ERR("SHA256_Update failed");
            goto err;
        }
        break;

    case TPM2_ALG_ECC:
        is_success = SHA256_Update(&sha256,
                ctx.out_public->publicArea.unique.ecc.x.buffer,
                ctx.out_public->publicArea.unique.ecc.x.size);
        if (!is_success) {
            LOG_ERR("SHA256_Update failed");
            goto err;
        }

        is_success = SHA256_Update(&sha256,
                ctx.out_public->publicArea.unique.ecc.y.buffer,
                ctx.out_public->publicArea.unique.ecc.y.size);
        if (!is_success) {
            LOG_ERR("SHA256_Update failed");
            goto err;
        }
        break;

    default:
        LOG_ERR("unsupported EK algorithm");
        goto err;
    }

    is_success = SHA256_Final(hash, &sha256);
    if (!is_success) {
        LOG_ERR("SHA256_Final failed");
        goto err;
    }

    if (ctx.verbose) {
        tpm2_tool_output("public-key-hash:\n");
        tpm2_tool_output("  sha256: ");
        unsigned i;
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            tpm2_tool_output("%02X", hash[i]);
        }
        tpm2_tool_output("\n");
    }

    return hash;
err:
    free(hash);
    return NULL;
}

char *base64_encode(const unsigned char* buffer)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_pointer;

    LOG_INFO("Calculating the base64_encode of the hash of the Endorsement"
             "Public Key:");

    if (buffer == NULL) {
        LOG_ERR("hash_ek_public returned null");
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, SHA256_DIGEST_LENGTH);
    UNUSED(BIO_flush(bio));
    BIO_get_mem_ptr(bio, &buffer_pointer);

    /* these are not NULL terminated */
    char *b64text = buffer_pointer->data;
    size_t len = buffer_pointer->length;

    size_t i;
    for (i = 0; i < len; i++) {
        if (b64text[i] == '+') {
            b64text[i] = '-';
        }
        if (b64text[i] == '/') {
            b64text[i] = '_';
        }
    }

    char *final_string = NULL;

    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_escape(curl, b64text, len);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    BIO_free_all(bio);

    /* format to a proper NULL terminated string */
    return final_string;
}

int retrieve_endorsement_certificate(char *b64h) {
    int ret = -1;

    size_t len = 1 + strlen(b64h) + strlen(ctx.ek_server_addr);
    char *weblink = (char *) malloc(len);
    if (!weblink) {
        LOG_ERR("oom");
        return ret;
    }

    snprintf(weblink, len, "%s%s", ctx.ek_server_addr, b64h);

    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_global_init failed: %s", curl_easy_strerror(rc));
        goto out_memory;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERR("curl_easy_init failed");
        goto out_global_cleanup;
    }

    /*
     * should not be used - Used only on platforms with older CA certificates.
     */
    if (ctx.SSL_NO_VERIFY) {
        rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        if (rc != CURLE_OK) {
            LOG_ERR("curl_easy_setopt for CURLOPT_SSL_VERIFYPEER failed: %s",
                    curl_easy_strerror(rc));
            goto out_easy_cleanup;
        }
    }

    rc = curl_easy_setopt(curl, CURLOPT_URL, weblink);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    /*
     * If verbose is set, add in diagnostic information for debugging connections.
     * https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html
     */
    rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, (long )ctx.verbose);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_VERBOSE failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    /*
     * If an output file is specified, write to the file, else curl will use stdout:
     * https://curl.haxx.se/libcurl/c/CURLOPT_WRITEDATA.html
     */
    if (ctx.ec_cert_file_handle) {
        rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx.ec_cert_file_handle);
        if (rc != CURLE_OK) {
            LOG_ERR("curl_easy_setopt for CURLOPT_WRITEDATA failed: %s",
                    curl_easy_strerror(rc));
            goto out_easy_cleanup;
        }
    }

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_perform() failed: %s", curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    ret = 0;

out_easy_cleanup:
    curl_easy_cleanup(curl);
out_global_cleanup:
    curl_global_cleanup();
out_memory:
    free(weblink);

    return ret;
}

int get_ek_certificate(void) {
    int rc = 1;
    unsigned char *hash = hash_ek_public();
    char *b64 = base64_encode(hash);
    if (!b64) {
        LOG_ERR("base64_encode returned null");
        goto out;
    }

    LOG_INFO("%s", b64);

    rc = retrieve_endorsement_certificate(b64);

    free(b64);
out:
    free(hash);
    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.ec_cert_path = value;
        break;
    case 'X':
        ctx.SSL_NO_VERIFY = 1;
        LOG_WARN("TLS communication with the said TPM manufacturer server setup"
                 " with SSL_NO_VERIFY!");
        break;
    case 'u':
        ctx.ek_path = value;
        break;
    case 'x':
        ctx.is_tpm2_device_active = false;
        break;
    }
    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one remote server url, got: %d", argc);
        return false;
    }

    ctx.ek_server_addr = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] =
    {
        { "ek-certificate",   required_argument, NULL, 'o' },
        { "allow-unverified", no_argument,       NULL, 'X' },
        { "ek-public",        required_argument, NULL, 'u' },
        { "offline",          no_argument,       NULL, 'x' },
    };

    *opts = tpm2_options_new("o:u:Xx", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

#define INTC 0x494E5443
#define IBM  0x49424D20
bool is_getekcertificate_feasible(ESYS_CONTEXT *ectx) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;

    tool_rc rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        return false;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value == IBM) {
        LOG_ERR("Simulator endorsement keys aren't certified");
        return false;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value != INTC) {
        return true;
    }

    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PERMANENT,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        return false;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value &
        TPMA_PERMANENT_TPMGENERATEDEPS) {
        LOG_ERR("Cannot proceed. For further information please refer to: "
                "https://www.intel.com/content/www/us/en/security-center/"
                "advisory/intel-sa-00086.html. Recovery tools are located here:"
                "https://github.com/intel/INTEL-SA-00086-Linux-Recovery-Tools");
        return false;
    }

    return true;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(ectx);

    bool is_getekcert_feasible;
    if (ctx.is_tpm2_device_active) {
        is_getekcert_feasible = is_getekcertificate_feasible(ectx);
        if (!is_getekcert_feasible) {
            return tool_rc_general_error;
        }
    }

    if (!ctx.ek_path) {
        LOG_ERR("Must specify the ek public key path");
        return tool_rc_general_error;
    }

    if (!ctx.ek_server_addr) {
        LOG_ERR("Must specify a remote server url!");
        return tool_rc_option_error;
    }

    if (ctx.ec_cert_path) {
        ctx.ec_cert_file_handle = fopen(ctx.ec_cert_path, "wb");
        if (!ctx.ec_cert_file_handle) {
            LOG_ERR("Could not open file for writing: \"%s\"",
                ctx.ec_cert_path);
            return tool_rc_general_error;
        }
    }

    ctx.out_public = malloc(sizeof(*ctx.out_public));
    ctx.out_public->size = 0;
    bool res = files_load_public(ctx.ek_path, ctx.out_public);
    if (!res) {
        LOG_ERR("Could not load EK public from file");
        return tool_rc_general_error;
    }

    ctx.verbose = flags.verbose;

    int ret = get_ek_certificate();
    if (ret) {
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (ctx.ec_cert_file_handle) {
        fclose(ctx.ec_cert_file_handle);
    }

    return tool_rc_success;
}
