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
#include "object.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_capability.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

typedef struct tpm_getekcertificate_ctx tpm_getekcertificate_ctx;
struct tpm_getekcertificate_ctx {
    // TPM Device properties
    bool is_tpm2_device_active;
    bool is_cert_on_nv;
    bool is_intc_cert;
    bool is_rsa_ek_cert_nv_location_defined;
    bool is_ecc_ek_cert_nv_location_defined;
    bool is_tpmgeneratedeps;
    // Certficate data handling
    uint8_t cert_count;
    char *ec_cert_path_1;
    FILE *ec_cert_file_handle_1;
    char *ec_cert_path_2;
    FILE *ec_cert_file_handle_2;
    unsigned char *rsa_cert_buffer;
    uint16_t rsa_cert_buffer_size;
    unsigned char *ecc_cert_buffer;
    uint16_t ecc_cert_buffer_size;
    bool is_cert_raw;
    // EK certificate hosting particulars
    char *ek_server_addr;
    unsigned int SSL_NO_VERIFY;
    char *ek_path;
    bool verbose;
    TPM2B_PUBLIC *out_public;
};

static tpm_getekcertificate_ctx ctx = {
    .is_tpm2_device_active = true,
    .ek_server_addr = "https://ekop.intel.com/ekcertservice/",
    .is_cert_on_nv = true,
    .cert_count = 0,
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

static char *base64_encode(const unsigned char* buffer)
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

static size_t writecallback(void *contents, size_t size, size_t nitems,
    char *CERT_BUFFER) {

    strncpy(CERT_BUFFER, (const char *)contents, nitems * size);
    ctx.rsa_cert_buffer_size = nitems * size;

    return ctx.rsa_cert_buffer_size;
}
static bool retrieve_web_endorsement_certificate(char *b64h) {

    size_t len = 1 + strlen(b64h) + strlen(ctx.ek_server_addr);
    char *weblink = (char *) malloc(len);
    if (!weblink) {
        LOG_ERR("oom");
        return false;
    }

    bool ret = true;
    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_global_init failed: %s", curl_easy_strerror(rc));
        ret = false;
        goto out_memory;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERR("curl_easy_init failed");
        ret = false;
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
            ret = false;
            goto out_easy_cleanup;
        }
    }

    snprintf(weblink, len, "%s%s", ctx.ek_server_addr, b64h);
    rc = curl_easy_setopt(curl, CURLOPT_URL, weblink);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        ret = false;
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
        ret = false;
        goto out_easy_cleanup;
    }

    rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_WRITEFUNCTION failed: %s",
                curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }
    /*
     * As only one cert is downloaded at a time, we can simply use
     * rsa_cert_buffer for either RSA EK cert or ECC EK cert.
     */
    ctx.rsa_cert_buffer = malloc(CURL_MAX_WRITE_SIZE);
    rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)ctx.rsa_cert_buffer);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_WRITEDATA failed: %s",
                curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_perform() failed: %s", curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

out_easy_cleanup:
    curl_easy_cleanup(curl);
out_global_cleanup:
    curl_global_cleanup();
out_memory:
    free(weblink);

    return ret;
}

static bool get_web_ek_certificate(void) {

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("TLS communication with the said TPM manufacturer server setup"
                 " with SSL_NO_VERIFY!");
    }

    bool ret = true;
    unsigned char *hash = hash_ek_public();
    char *b64 = base64_encode(hash);
    if (!b64) {
        LOG_ERR("base64_encode returned null");
        ret = false;
        goto out;
    }

    LOG_INFO("%s", b64);

    ret = retrieve_web_endorsement_certificate(b64);

    free(b64);
out:
    free(hash);
    return ret;
}

#define INTC 0x494E5443
#define IBM  0x49424D20
#define RSA_EK_CERT_NV_INDEX 0x01C00002
#define ECC_EK_CERT_NV_INDEX 0x01C0000A
tool_rc get_tpm_properties(ESYS_CONTEXT *ectx) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    tool_rc rc = tool_rc_success;
    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        goto get_tpm_properties_out;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value == IBM) {
        LOG_WARN("The TPM device is a simulator —— Inspect the certficate chain and root certificate");
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value == INTC) {
        ctx.is_intc_cert = true;
    }

    free(capability_data);
    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PERMANENT,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        goto get_tpm_properties_out;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value &
        TPMA_PERMANENT_TPMGENERATEDEPS) {
            ctx.is_tpmgeneratedeps = true;
    }

    free(capability_data);
    rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES,
        tpm2_util_hton_32(TPM2_HT_NV_INDEX), TPM2_PT_NV_INDEX_MAX, NULL,
        &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to read capability data for NV indices.");
        ctx.is_cert_on_nv = false;
        goto get_tpm_properties_out;
    }

    if (capability_data->data.handles.count == 0) {
        ctx.is_cert_on_nv = false;
        goto get_tpm_properties_out;
    }

    UINT32 i;
    for (i = 0; i < capability_data->data.handles.count; i++) {
        TPMI_RH_NV_INDEX index = capability_data->data.handles.handle[i];
        if (index == RSA_EK_CERT_NV_INDEX) {
            ctx.is_rsa_ek_cert_nv_location_defined = true;
        }
        if (index == ECC_EK_CERT_NV_INDEX) {
            ctx.is_ecc_ek_cert_nv_location_defined = true;
        }
    }

    if (!ctx.is_rsa_ek_cert_nv_location_defined &&
    !ctx.is_ecc_ek_cert_nv_location_defined) {
        ctx.is_cert_on_nv = false;
    }

get_tpm_properties_out:
    free(capability_data);
    return rc;
}

static tool_rc nv_read(ESYS_CONTEXT *ectx, TPMI_RH_NV_INDEX nv_index) {

    /*
     * Typical NV Index holding EK certificate has an empty auth
     * with attributes:
     * ppwrite|ppread|ownerread|authread|no_da|written|platformcreate
     */
    char index_string[11];
    if (nv_index == RSA_EK_CERT_NV_INDEX) {
        strcpy(index_string, "0x01C00002");
    } else {
        strcpy(index_string, "0x01C0000A");
    }
    tpm2_loaded_object object;
    tool_rc tmp_rc = tool_rc_success;
    tool_rc rc = tpm2_util_object_load_auth(ectx, index_string, NULL, &object,
        false, TPM2_HANDLE_FLAGS_NV);
    if (rc != tool_rc_success) {
        goto nv_read_out;
    }

    rc = nv_index == RSA_EK_CERT_NV_INDEX ?
         tpm2_util_nv_read(ectx, nv_index, 0, 0, &object, &ctx.rsa_cert_buffer,
         &ctx.rsa_cert_buffer_size, 0) :
         tpm2_util_nv_read(ectx, nv_index, 0, 0, &object, &ctx.ecc_cert_buffer,
         &ctx.ecc_cert_buffer_size, 0);

nv_read_out:
    tmp_rc = tpm2_session_close(&object.session);
    if (rc != tool_rc_success) {
        return tmp_rc;
    }

    return rc;
}

static tool_rc get_nv_ek_certificate(ESYS_CONTEXT *ectx) {

    if (!ctx.is_cert_on_nv) {
        LOG_ERR("TCG specified location for EK certs aren't defined.");
        return tool_rc_general_error;
    }

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("Ignoring -X or --allow-unverified if EK certificate found on NV");
    }

    if (ctx.ek_path) {
        LOG_WARN("Ignoring -u or --ek-public option if EK certificate found on NV");
        return tool_rc_option_error;
    }

    if (ctx.is_rsa_ek_cert_nv_location_defined &&
    ctx.is_ecc_ek_cert_nv_location_defined && ctx.cert_count == 1) {
        LOG_WARN("Found 2 certficates on NV. Add another -o to save the ECC cert");
    }

    if ((!ctx.is_rsa_ek_cert_nv_location_defined ||
    !ctx.is_ecc_ek_cert_nv_location_defined) && ctx.cert_count == 2) {
        LOG_WARN("Ignoring the additional output file since only 1 cert found on NV");
    }

    tool_rc rc = tool_rc_success;
    if (ctx.is_rsa_ek_cert_nv_location_defined) {
        rc = nv_read(ectx, RSA_EK_CERT_NV_INDEX);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    if (ctx.is_ecc_ek_cert_nv_location_defined) {
        rc = nv_read(ectx, ECC_EK_CERT_NV_INDEX);
    }

    return rc;
}

static tool_rc print_intel_ek_certificate_warning(void) {

    if (ctx.is_intc_cert && ctx.is_tpmgeneratedeps && !ctx.is_cert_on_nv) {

        LOG_ERR("Cannot proceed. For further information please refer to: "
                "https://www.intel.com/content/www/us/en/security-center/"
                "advisory/intel-sa-00086.html. Recovery tools are located here:"
                "https://github.com/intel/INTEL-SA-00086-Linux-Recovery-Tools");

        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc get_ek_certificates(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_success;
    if (ctx.is_cert_on_nv) {
        rc = get_nv_ek_certificate(ectx);
        if (rc == tool_rc_success) {
            return rc;
        } else {
            LOG_WARN("EK certificate not found on NV");
            ctx.is_cert_on_nv = false;
        }
    }

    /*
     * Following is everything applicable to ctx.is_cert_on_nv = false.
     */

    rc = print_intel_ek_certificate_warning();
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.ek_path) {
        LOG_ERR("Must specify the EK public key path");
        return tool_rc_option_error;
    }

    if (ctx.cert_count > 1) {
        LOG_ERR("Specify one output path for EK cert file per EK public key");
        return tool_rc_option_error;
    }

    bool retval = get_web_ek_certificate();
    if (!retval) {
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc process_input(ESYS_CONTEXT *ectx) {

    if (ctx.ek_path) {
        ctx.out_public = malloc(sizeof(*ctx.out_public));
        ctx.out_public->size = 0;
        bool res = files_load_public(ctx.ek_path, ctx.out_public);
        if (!res) {
            LOG_ERR("Could not load EK public from file");
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (ctx.is_tpm2_device_active) {
        rc = get_tpm_properties(ectx);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    return print_intel_ek_certificate_warning();
}

static char *base64_decode(char **split, unsigned int cert_length) {

    *split += strlen("certficate\" : ");
    char *final_string = NULL;
    int outlen;
    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_unescape(curl, *split, cert_length, &outlen);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if(final_string) {
        size_t i;
        for (i = 0; i < strlen(final_string); i++) {
            final_string[i] = final_string[i] == '-' ? '+'  : final_string[i];
            final_string[i] = final_string[i] == '_' ? '/'  : final_string[i];
            final_string[i] = final_string[i] == '"' ? '\0' : final_string[i];
            final_string[i] = final_string[i] == '}' ? '\0' : final_string[i];
        }
    }

    return final_string;
}

#define PEM_BEGIN_CERT_LINE "\n-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CERT_LINE "\n-----END CERTIFICATE-----\n"
static tool_rc process_output(void) {

    /*
     * Check if the cert is from INTC based on certificated data containing
     * the EK public hash in addition to the certificate data.
     * If so set the flag.
     */
    if (ctx.rsa_cert_buffer) {
        ctx.is_intc_cert = ctx.is_intc_cert ? ctx.is_intc_cert :
        !(strncmp((const char *)ctx.rsa_cert_buffer,
            "{\"pubhash", strlen("{\"pubhash")));
    }

    if (ctx.ecc_cert_buffer) {
        ctx.is_intc_cert = ctx.is_intc_cert ? ctx.is_intc_cert :
        !(strncmp((const char *)ctx.ecc_cert_buffer,
            "{\"pubhash", strlen("{\"pubhash")));
    }

    /*
     *  Convert Intel EK certificates as received in the URL safe variant of
     *  Base 64: https://tools.ietf.org/html/rfc4648#section-5 to PEM
     */
    if (ctx.rsa_cert_buffer && ctx.is_intc_cert && !ctx.is_cert_raw) {
        char *split = strstr((const char *)ctx.rsa_cert_buffer, "certificate");
        char *copy_buffer = base64_decode(&split, ctx.rsa_cert_buffer_size);
        ctx.rsa_cert_buffer_size = strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer) + strlen(PEM_END_CERT_LINE);
        strcpy((char *)ctx.rsa_cert_buffer, PEM_BEGIN_CERT_LINE);
        strcpy((char *)ctx.rsa_cert_buffer + strlen(PEM_BEGIN_CERT_LINE),
            copy_buffer);
        strcpy((char *)ctx.rsa_cert_buffer + strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer), PEM_END_CERT_LINE);
        free(copy_buffer);
    }

    if (ctx.ecc_cert_buffer && ctx.is_intc_cert && !ctx.is_cert_raw) {
        char *split = strstr((const char *)ctx.ecc_cert_buffer, "certificate");
        char *copy_buffer = base64_decode(&split, ctx.ecc_cert_buffer_size);
        ctx.ecc_cert_buffer_size = strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer) + strlen(PEM_END_CERT_LINE);
        strcpy((char *)ctx.ecc_cert_buffer, PEM_BEGIN_CERT_LINE);
        strcpy((char *)ctx.ecc_cert_buffer + strlen(PEM_BEGIN_CERT_LINE),
            copy_buffer);
        strcpy((char *)ctx.ecc_cert_buffer + strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer), PEM_END_CERT_LINE);
        free(copy_buffer);
    }

    bool retval = true;
    if (ctx.rsa_cert_buffer) {
        retval = files_write_bytes(
            ctx.ec_cert_file_handle_1 ? ctx.ec_cert_file_handle_1 : stdout,
            ctx.rsa_cert_buffer, ctx.rsa_cert_buffer_size);
        if (!retval) {
            return tool_rc_general_error;
        }
    }

    if (ctx.ecc_cert_buffer) {
        retval = files_write_bytes(
            ctx.ec_cert_file_handle_2 ? ctx.ec_cert_file_handle_2 :
            ctx.rsa_cert_buffer ? stdout : ctx.ec_cert_file_handle_1,
            ctx.ecc_cert_buffer, ctx.ecc_cert_buffer_size);
        if (!retval) {
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static tool_rc check_input_options(void) {

    if (!ctx.ek_path && !ctx.is_cert_on_nv) {
        LOG_ERR("Must specify the EK public key path");
        return tool_rc_option_error;
    }

    if (!ctx.ek_server_addr && !ctx.is_cert_on_nv) {
        LOG_ERR("Must specify a valid remote server url!");
        return tool_rc_option_error;
    }

    if (ctx.ec_cert_path_1) {
        ctx.ec_cert_file_handle_1 = fopen(ctx.ec_cert_path_1, "wb");
        if (!ctx.ec_cert_file_handle_1) {
            LOG_ERR("Could not open file for writing: \"%s\"",
                ctx.ec_cert_path_1);
            return tool_rc_general_error;
        }
    }

    if (ctx.ec_cert_path_2) {
        ctx.ec_cert_file_handle_2 = fopen(ctx.ec_cert_path_2, "wb");
        if (!ctx.ec_cert_file_handle_2) {
            LOG_ERR("Could not open file for writing: \"%s\"",
                ctx.ec_cert_path_2);
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one remote server url, got: %d", argc);
        return false;
    }

    ctx.ek_server_addr = argv[0];
    ctx.is_cert_on_nv = false;

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        if (ctx.cert_count < 2) {
            ctx.cert_count++;
        } else {
            LOG_ERR("Specify only 2 outputs for RSA/ ECC certificates");
            return false;
        }
        if (ctx.cert_count == 1) {
            ctx.ec_cert_path_1 = value;
        }
        if (ctx.cert_count == 2) {
            ctx.ec_cert_path_2 = value;
        }
        break;
    case 'X':
        ctx.SSL_NO_VERIFY = 1;
        break;
    case 'u':
        ctx.ek_path = value;
        break;
    case 'x':
        ctx.is_tpm2_device_active = false;
        ctx.is_cert_on_nv = false;
        break;
    case 0:
        ctx.is_cert_raw = true;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] =
    {
        { "ek-certificate",   required_argument, NULL, 'o' },
        { "allow-unverified", no_argument,       NULL, 'X' },
        { "ek-public",        required_argument, NULL, 'u' },
        { "offline",          no_argument,       NULL, 'x' },
        { "raw",              no_argument,       NULL,  0  },
    };

    *opts = tpm2_options_new("o:u:Xx", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(ectx);

    tool_rc rc = check_input_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = process_input(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    ctx.verbose = flags.verbose;

    rc = get_ek_certificates(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return process_output();
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (ctx.ec_cert_file_handle_1) {
        fclose(ctx.ec_cert_file_handle_1);
    }

    if (ctx.ec_cert_file_handle_2) {
        fclose(ctx.ec_cert_file_handle_2);
    }

    if (ctx.rsa_cert_buffer) {
        free(ctx.rsa_cert_buffer);
    }

    if (ctx.ecc_cert_buffer) {
        free(ctx.ecc_cert_buffer);
    }

    return tool_rc_success;
}

static void tpm2_tool_onexit(void) {

    if (ctx.out_public) {
        free(ctx.out_public);
    }
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getekcertificate", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, tpm2_tool_onexit)
