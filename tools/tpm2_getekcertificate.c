/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h> 
#endif


/*
 * Sourced from TCG Vendor ID Registry v1.06:
 * https://trustedcomputinggroup.org/resource/vendor-id-registry/
 *
 */

typedef enum tpm_manufacturer tpm_manufacturer;
enum tpm_manufacturer {
    VENDOR_AMD       = 0x414D4400,
    VENDOR_ATMEL     = 0x41544D4C,
    VENDOR_BROADCOM  = 0x4252434D,
    VENDOR_CISCO     = 0x4353434F,
    VENDOR_FLYSLICE  = 0x464C5953,
    VENDOR_ROCKCHIP  = 0x524F4343,
    VENDOR_GOOGLE    = 0x474F4F47,
    VENDOR_HPE       = 0x48504500,
    VENDOR_HUAWEI    = 0x48495349,
    VENDOR_IBM       = 0x49424D00,
    VENDOR_IBMSIM    = 0x49424D20, // Used only by mssim/ibmswtpm2
    VENDOR_INFINEON  = 0x49465800,
    VENDOR_INTEL     = 0x494E5443,
    VENDOR_LENOVO    = 0x4C454E00,
    VENDOR_MICROSOFT = 0x4D534654,
    VENDOR_NSM       = 0x4E534D20,
    VENDOR_NATIONZ   = 0x4E545A00,
    VENDOR_NUVOTON   = 0x4E544300,
    VENDOR_QUALCOMM  = 0x51434F4D,
    VENDOR_SAMSUNG   = 0x534D534E,
    VENDOR_SINOSUN   = 0x534E5300,
    VENDOR_SMSC      = 0x534D5343,
    VENDOR_STM       = 0x53544D20,
    VENDOR_TXN       = 0x54584E00,
    VENDOR_WINBOND   = 0x57454300,
};

typedef enum pubkey_enc_mode pubkey_enc_mode;
enum pubkey_enc_mode {
    ENC_AUTO = 0,
    ENC_INTEL = 1,
    ENC_AMD = 2,
};

/*
 * Sourced from TCG PC Client Platform TPM Profile Specification v1.05 rev 14:
 * https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/
 *
 */

typedef enum ek_nv_index_enum ek_nv_index_enum;
enum ek_nv_index_enum {
  RSA_EK_CERT_NV_INDEX = 0x01C00002,
  ECC_EK_CERT_NV_INDEX = 0x01C0000A,
  RSA_2048_EK_CERT_NV_INDEX = 0x01C00012,
  RSA_3072_EK_CERT_NV_INDEX = 0x01C0001C,
  RSA_4096_EK_CERT_NV_INDEX = 0x01C0001E,
  ECC_NIST_P256_EK_CERT_NV_INDEX = 0x01C00014,
  ECC_NIST_P384_EK_CERT_NV_INDEX = 0x01C00016,
  ECC_NIST_P521_EK_CERT_NV_INDEX = 0x01C00018,
  ECC_SM2_P256_EK_CERT_NV_INDEX = 0x01C0001A,
};

typedef unsigned int ek_nv_index;

#define EK_SERVER_INTEL "https://ekop.intel.com/ekcertservice/"
#define EK_SERVER_AMD "https://ftpm.amd.com/pki/aia/"

typedef enum key_type key_type;
enum key_type {
    KTYPE_RSA = 0,
    KTYPE_ECC = 1,
};

typedef struct ek_index_map ek_index_map;
struct ek_index_map
{
  const char *name;
  key_type key_type;
  ek_nv_index index;
  TPMI_ALG_HASH hash_alg;
  bool found;
  unsigned char *cert_buffer;
  size_t cert_buffer_size;
};

static ek_index_map ek_index_maps[] = {
    {"rsa", KTYPE_RSA, RSA_EK_CERT_NV_INDEX, TPM2_ALG_SHA256, false, NULL, 0},
    {"rsa2048", KTYPE_RSA, RSA_2048_EK_CERT_NV_INDEX, TPM2_ALG_SHA256, false, NULL, 0},
    {"ecc", KTYPE_ECC, ECC_EK_CERT_NV_INDEX, TPM2_ALG_SHA256, false, NULL, 0},
    {"ecc_nist_p256", KTYPE_ECC, ECC_NIST_P256_EK_CERT_NV_INDEX, TPM2_ALG_SHA256, false, NULL, 0},
    {"rsa3072", KTYPE_RSA, RSA_3072_EK_CERT_NV_INDEX, TPM2_ALG_SHA384, false, NULL, 0},
    {"rsa4096", KTYPE_RSA, RSA_4096_EK_CERT_NV_INDEX, TPM2_ALG_SHA512, false, NULL, 0},
    {"ecc_nist_p384", KTYPE_ECC, ECC_NIST_P384_EK_CERT_NV_INDEX, TPM2_ALG_SHA384, false, NULL, 0},
    {"ecc_nist_p521", KTYPE_ECC, ECC_NIST_P521_EK_CERT_NV_INDEX, TPM2_ALG_SHA512, false, NULL, 0},
    {"ecc_sm2_p256", KTYPE_ECC, ECC_SM2_P256_EK_CERT_NV_INDEX, TPM2_ALG_SM3_256, false, NULL, 0},
};

typedef struct tpm_getekcertificate_ctx tpm_getekcertificate_ctx;
struct tpm_getekcertificate_ctx {
    // TPM Device properties
    bool is_tpm2_device_active;
    bool is_cert_on_nv;
    tpm_manufacturer manufacturer;
    bool is_tpmgeneratedeps;
    // Certificate data handling
    size_t cert_count;
    size_t nv_cert_count;
    char *ec_cert_paths[ARRAY_LEN(ek_index_maps)];
    FILE *ec_cert_file_handles[ARRAY_LEN(ek_index_maps)];
    unsigned char *web_cert_buffer;
    size_t web_cert_buffer_size;
    bool is_cert_raw;
    bool need_x509_trunc;
    size_t curl_buffer_size;
    // EK certificate hosting particulars
    char *ek_server_addr;
    unsigned int SSL_NO_VERIFY;
    char *ek_path;
    pubkey_enc_mode encoding;
    bool verbose;
    TPM2B_PUBLIC *out_public;
};

static tpm_getekcertificate_ctx ctx = {
    .is_tpm2_device_active = true,
    .is_cert_on_nv = false,
    .cert_count = 0,
    .encoding = ENC_AUTO,
    .need_x509_trunc = false,
};

static ek_index_map *lookup_ek_index_map(const TPMI_RH_NV_INDEX index) {
    size_t i;

    for (i = 0; i < ARRAY_LEN(ek_index_maps); i++)
    {
        if (index == ek_index_maps[i].index) {
            ek_index_maps[i].found = true;
            return &ek_index_maps[i];
        }
    }
    return NULL;
}


static char *get_ek_server_address(void) {
    if (ctx.ek_server_addr) // set by CLI
    {
        return ctx.ek_server_addr;
    }
    switch (ctx.manufacturer) {
        case VENDOR_INTEL:
            return EK_SERVER_INTEL;
        case VENDOR_AMD:
            return EK_SERVER_AMD;
        default:
            LOG_ERR("No EK server address found for manufacturer.");
            return NULL;
    }
}

#define AMD_EK_URI_LEN 16 // AMD EK takes first 16 hex chars of hash

static pubkey_enc_mode get_encoding(void) {
    /*
     * If one is explicitly set, use it.
     */
    if (ctx.encoding != ENC_AUTO) {
        return ctx.encoding;
    }
    /*
     * Currently it's assumed AMD is the only one with a different encoding.
     */
    if (ctx.manufacturer == VENDOR_AMD) {
        return ENC_AMD;
    } else {
        return ENC_INTEL;
    }
}

static unsigned char *hash_ek_public(void) {

    unsigned char *hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        LOG_ERR("OOM");
        return NULL;
    }

    EVP_MD_CTX *sha256 = EVP_MD_CTX_new();
    if (!hash) {
        LOG_ERR("OOM");
        goto evperr;
    }
    int is_success = EVP_DigestInit(sha256, EVP_sha256());
    if (!is_success) {
        LOG_ERR("EVP_DigestInit failed");
        goto err;
    }

    if (ctx.encoding == ENC_AMD) {
        switch (ctx.out_public->publicArea.type) {
        case TPM2_ALG_RSA: {
            /*
             * hash = sha256(00 00 22 22 || (uint32_t) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x22, 0x22 }; // Prefix
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            uint32_t exp = ctx.out_public->publicArea.parameters.rsaDetail.exponent;
            if (exp == 0) {
                exp = 0x00010001; // 0 indicates default
            } else {
                LOG_WARN("non-default exponent used");
            }
            buf[3] = (BYTE)exp;
            buf[2] = (BYTE)(exp>>=8);
            buf[1] = (BYTE)(exp>>=8);
            buf[0] = (BYTE)(exp>>8);
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.rsa.buffer,
                    ctx.out_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        case TPM2_ALG_ECC: {
            /*
             * hash = sha256(00 00 44 44 || (uint32_t) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x44, 0x44 }; // Prefix
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.x.buffer,
                    ctx.out_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.y.buffer,
                    ctx.out_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        default:
            LOG_ERR("unsupported EK algorithm");
            goto err;
        }
    } else {
        switch (ctx.out_public->publicArea.type) {
        case TPM2_ALG_RSA:
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.rsa.buffer,
                    ctx.out_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            if (ctx.out_public->publicArea.parameters.rsaDetail.exponent != 0) {
                LOG_ERR("non-default exponents unsupported");
                goto err;
            }
            BYTE buf[3] = { 0x1, 0x00, 0x01 }; // Exponent
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        case TPM2_ALG_ECC:
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.x.buffer,
                    ctx.out_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.y.buffer,
                    ctx.out_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        default:
            LOG_ERR("unsupported EK algorithm");
            goto err;
        }
    }

    is_success = EVP_DigestFinal_ex(sha256, hash, NULL);
    if (!is_success) {
        LOG_ERR("EVP_DigestFinal failed");
        goto err;
    }

    EVP_MD_CTX_free(sha256);
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
    EVP_MD_CTX_free(sha256);
evperr:
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

#define NULL_TERM_LEN 1 // '\0'

static char *encode_ek_public_amd(void) {
    unsigned char *hash = hash_ek_public();
    if (!hash) {
        LOG_ERR("EK hash is null");
        return NULL;
    }
    char *hash_str = malloc(AMD_EK_URI_LEN * 2 + NULL_TERM_LEN);
    if (!hash_str) {
        LOG_ERR("oom");
        return NULL;
    }
    for (size_t i = 0; i < AMD_EK_URI_LEN; i++)
    {
        sprintf((char*)(hash_str + (i*2)), "%02x", hash[i]);
    }
    hash_str[AMD_EK_URI_LEN * 2] = '\0';
    return hash_str;
}

static char *encode_ek_public_intel(void) {
    unsigned char *hash = hash_ek_public();
    char *b64 = base64_encode(hash);
    free(hash);
    if (!b64) {
        LOG_ERR("base64_encode returned null");
    }
    return b64;
}

static char *encode_ek_public(void) {
    if (ctx.encoding == ENC_AMD) {
        return encode_ek_public_amd();
    } else {
        return encode_ek_public_intel();
    }
}

static size_t writecallback(char *contents, size_t size, size_t nitems,
    void *userdata) {
    UNUSED(userdata);
    const size_t chunk_size = size * nitems;

    if (!chunk_size) {
      return 0;
    }

    const size_t new_used_size = ctx.web_cert_buffer_size + chunk_size;
    if (ctx.curl_buffer_size < new_used_size) {
        const size_t new_buf_size = ctx.curl_buffer_size + CURL_MAX_WRITE_SIZE;
        void *new_buf = realloc(ctx.web_cert_buffer, new_buf_size);
        if (!new_buf) {
            LOG_ERR("OOM when downloading EK cert");
            return 0;
        }
        ctx.web_cert_buffer = new_buf;
        ctx.curl_buffer_size = new_buf_size;
    }

    memcpy(ctx.web_cert_buffer + ctx.web_cert_buffer_size, contents, chunk_size);
    ctx.web_cert_buffer_size += chunk_size;
    return chunk_size;
}

static bool retrieve_web_endorsement_certificate(char *uri) {

    #define PATH_JOIN_CHAR_LEN 1            // '/'
    size_t len = strlen(ctx.ek_server_addr) + strlen(uri) + NULL_TERM_LEN +
        PATH_JOIN_CHAR_LEN;
    char *weblink = (char *) malloc(len);
    if (!weblink) {
        LOG_ERR("oom");
        return false;
    }

    bool ret = true;
    ctx.web_cert_buffer = malloc(CURL_MAX_WRITE_SIZE);
    if (!ctx.web_cert_buffer) {
        LOG_ERR("OOM");
        ret = false;
        goto out_memory;
    }
    ctx.curl_buffer_size = CURL_MAX_WRITE_SIZE;

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
        rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        if (rc != CURLE_OK) {
            LOG_ERR("curl_easy_setopt for CURLOPT_SSL_VERIFYPEER failed: %s",
                    curl_easy_strerror(rc));
            ret = false;
            goto out_easy_cleanup;
        }
    }

    bool is_slash_append_required =
        strncmp((ctx.ek_server_addr + strlen(ctx.ek_server_addr) - 1), "/", 1);
    if (is_slash_append_required) {
        snprintf(weblink, len, "%s%s%s", ctx.ek_server_addr, "/", uri);
    } else {
        snprintf(weblink, len, "%s%s", ctx.ek_server_addr, uri);
    }

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

    rc = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_FAILONERROR failed: %s",
                curl_easy_strerror(rc));
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
    if (!ret && ctx.web_cert_buffer) {
      free(ctx.web_cert_buffer);
      ctx.web_cert_buffer = NULL;
      ctx.web_cert_buffer_size = 0;
      ctx.curl_buffer_size = 0;
    }
    free(weblink);

    return ret;
}

static bool get_web_ek_certificate(void) {

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("TLS communication with the said TPM manufacturer server setup"
                 " with SSL_NO_VERIFY!");
    }

    bool ret = true;
    char *ek_uri = encode_ek_public();
    if (!ek_uri) {
        LOG_ERR("Failed to encode EK.");
        return false;
    }

    LOG_INFO("%s", ek_uri);

    ctx.ek_server_addr = get_ek_server_address();
    if (!ctx.ek_server_addr) {
        LOG_ERR("Please specify an EK server address on the command line.");
        ret = false;
        goto out;
    }

    ret = retrieve_web_endorsement_certificate(ek_uri);
 out:
    free(ek_uri);
    return ret;
}

static ssize_t x509_get_len(void *data, int len)
{
    const unsigned char *p, *p_save;
    p_save = p = data;

    d2i_X509(NULL, &p, len);

    return (ssize_t)(p - p_save);
}

static tool_rc nv_read(ESYS_CONTEXT *ectx, TPMI_RH_NV_INDEX nv_index) {

    /*
     * Typical NV Index holding EK certificate has an empty auth
     * with attributes:
     * ppwrite|ppread|ownerread|authread|no_da|written|platformcreate
     */
    ek_index_map *m = lookup_ek_index_map(nv_index);
    if (!m) {
        LOG_ERR("Unsupported NV INDEX, got \"%u\"", nv_index);
        return tool_rc_unsupported;
    }

    char index_string[11];
    snprintf(index_string, sizeof(index_string), "%u", m->index);
    tpm2_loaded_object object;
    tool_rc tmp_rc = tool_rc_success;
    tool_rc rc = tpm2_util_object_load_auth(ectx, index_string, NULL, &object,
        false, TPM2_HANDLE_FLAGS_NV);
    if (rc != tool_rc_success) {
        goto nv_read_out;
    }

    TPM2B_DIGEST cp_hash = { 0 };
    TPM2B_DIGEST rp_hash = { 0 };
    uint16_t nv_buf_size = 0;
    rc = tpm2_util_nv_read(ectx, nv_index, 0, 0, &object, &m->cert_buffer,
            &nv_buf_size, &cp_hash, &rp_hash, m->hash_alg, 0,
                           ESYS_TR_NONE, ESYS_TR_NONE, NULL);
    if (rc != tool_rc_success) {
        goto nv_read_out;
    }
    m->cert_buffer_size =  nv_buf_size;
    if (ctx.need_x509_trunc) {
        int len = (int)x509_get_len(m->cert_buffer, nv_buf_size);
        nv_buf_size = len;
    }

nv_read_out:
    tmp_rc = tpm2_session_close(&object.session);
    if (rc != tool_rc_success) {
        return tmp_rc;
    }

    return rc;
}

bool cmp_public_key(
    TPM2B_PUBLIC *key1,
    TPM2B_PUBLIC *key2)
{
    if (key1->publicArea.type != key2->publicArea.type)
        return false;
    switch (key1->publicArea.type) {
    case TPM2_ALG_RSA:
        if (key1->publicArea.unique.rsa.size != key2->publicArea.unique.rsa.size) {
            return false;
        }
        if (memcmp(&key1->publicArea.unique.rsa.buffer[0],
                   &key2->publicArea.unique.rsa.buffer[0],
                   key1->publicArea.unique.rsa.size) == 0)
            return true;
        else
            return false;
        break;
    case TPM2_ALG_ECC:
        if (key1->publicArea.unique.ecc.x.size != key2->publicArea.unique.ecc.x.size) {
            return false;
        }
        if (memcmp(&key1->publicArea.unique.ecc.x.buffer[0],
                   &key2->publicArea.unique.ecc.x.buffer[0],
                   key1->publicArea.unique.ecc.x.size) != 0)
            return false;
        if (key1->publicArea.unique.ecc.y.size != key2->publicArea.unique.ecc.y.size) {
            return false;
        }
        if (memcmp(&key1->publicArea.unique.ecc.y.buffer[0],
                   &key2->publicArea.unique.ecc.y.buffer[0],
                   key1->publicArea.unique.ecc.y.size) != 0)
            return false;
        else
            return true;
        break;

    default:
        return false;
    }
}

static int bn2binpad(const BIGNUM *bn, unsigned char *bin, int binSize)
{
    /* Check for NULL parameters */
    if (!bn || !bin) {
        return 0;
    }
    /* Convert bn */
    int bnSize = BN_num_bytes(bn);
    int offset = binSize - bnSize;
    memset(bin, 0, offset);
    BN_bn2bin(bn, bin + offset);
    return 1;
}

tool_rc get_rsa_tpm2b_public_from_evp(
    EVP_PKEY *publicKey,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    if (!publicKey) {
        LOG_ERR("publicKey is NULL");
        return tool_rc_general_error;
    }
    if (!tpmPublic) {
        LOG_ERR("tpmPublic is NULL");
        return tool_rc_general_error;
    }

    /* Extract the public information */
    tool_rc rc = tool_rc_success;
    int keyBits, keySize;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *e = NULL, *n = NULL;
    RSA *rsaKey = EVP_PKEY_get1_RSA(publicKey);
    if (!rsaKey) {
        LOG_ERR("Out of memory.");
        rc = tool_rc_general_error;
        goto cleanup;
    }
    keySize = RSA_size(rsaKey);
    keyBits = keySize * 8;
    RSA_get0_key(rsaKey, &n, &e, NULL);
#else
    BIGNUM *e = NULL, *n = NULL;

    keyBits = EVP_PKEY_get_bits(publicKey);
    keySize = (keyBits + 7) / 8;
    if (!EVP_PKEY_get_bn_param(publicKey, OSSL_PKEY_PARAM_RSA_N, &n)
            || !EVP_PKEY_get_bn_param(publicKey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        LOG_ERR("Retrieve pubkey failed");
        rc = tool_rc_general_error;
        goto cleanup;
    }
#endif
    tpmPublic->publicArea.unique.rsa.size = keySize;
    if (1 != bn2binpad(n, &tpmPublic->publicArea.unique.rsa.buffer[0],
                       keySize)) {
        LOG_ERR("Write big num byte buffer failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }
    tpmPublic->publicArea.parameters.rsaDetail.keyBits = keyBits;
    tpmPublic->publicArea.parameters.rsaDetail.exponent = BN_get_word(e);

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsaKey);
#else
    BN_free(e);
    BN_free(n);
#endif
    return rc;
}

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

tool_rc get_ecc_tpm2b_public_from_evp(
    EVP_PKEY *publicKey,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    if (!publicKey || !tpmPublic) {
        LOG_ERR("Bad reference.");
        return tool_rc_general_error;
    }

    /* Initialize variables that will contain the relevant information */
    tool_rc rc = tool_rc_success;
    int curveId;
    size_t ecKeySize;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    TPMI_ECC_CURVE tpmCurveId;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    const EC_GROUP *ecGroup;
    const EC_POINT *publicPoint;
    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(publicKey);
    if (!ecKey) {
        LOG_ERR("Out of memory.");
        return tool_rc_general_error;
    }

    /* Retrieve the relevant information and write it to tpmPublic */
    ecGroup = EC_KEY_get0_group(ecKey);
    publicPoint = EC_KEY_get0_public_key(ecKey);
    curveId = EC_GROUP_get_curve_name(ecGroup);
    ecKeySize = (EC_GROUP_get_degree(ecGroup) + 7) / 8;

    if (!(bnX = BN_new())) {
        LOG_ERR("Create bignum failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }

    if (!(bnY = BN_new())) {
        LOG_ERR("Create bignum failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }

    if (1 != EC_POINT_get_affine_coordinates_tss(ecGroup, publicPoint,
                                                 bnX, bnY, NULL)) {
        LOG_ERR("Get affine coordinates failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }
#else
    char curveName[80];

    if (!EVP_PKEY_get_utf8_string_param(publicKey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curveName, sizeof(curveName), NULL)
            || !EVP_PKEY_get_bn_param(publicKey, OSSL_PKEY_PARAM_EC_PUB_X, &bnX)
            || !EVP_PKEY_get_bn_param(publicKey, OSSL_PKEY_PARAM_EC_PUB_Y, &bnY)) {
        LOG_ERR("Get public key failde.");
        rc = tool_rc_general_error;
        goto cleanup;
     }
    curveId = OBJ_txt2nid(curveName);
    ecKeySize = (EVP_PKEY_bits(publicKey) + 7) / 8;
#endif
    tpmPublic->publicArea.unique.ecc.x.size = ecKeySize;
    tpmPublic->publicArea.unique.ecc.y.size = ecKeySize;
    if (1 != bn2binpad(bnX, &tpmPublic->publicArea.unique.ecc.x.buffer[0],
                       (int) ecKeySize)) {
        LOG_ERR("Write big num byte buffer failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }
    if (1 != bn2binpad(bnY, &tpmPublic->publicArea.unique.ecc.y.buffer[0],
                       (int) ecKeySize)) {
        LOG_ERR("Write big num byte buffer failed.");
        rc = tool_rc_general_error;
        goto cleanup;
    }
    switch (curveId) {
    case NID_X9_62_prime192v1:
        tpmCurveId = TPM2_ECC_NIST_P192;
        break;
    case NID_secp224r1:
        tpmCurveId = TPM2_ECC_NIST_P224;
        break;
    case NID_X9_62_prime256v1:
        tpmCurveId = TPM2_ECC_NIST_P256;
        break;
    case NID_secp384r1:
        tpmCurveId = TPM2_ECC_NIST_P384;
        break;
    case NID_secp521r1:
        tpmCurveId = TPM2_ECC_NIST_P521;
        break;
#ifdef NID_sm2
    case NID_sm2:
        tpmCurveId = TPM2_ECC_SM2_P256;
        break;
#endif
    default:
        LOG_ERR("Curve %i not implemented", curveId);
        rc = tool_rc_general_error;
        goto cleanup;
    }
    tpmPublic->publicArea.parameters.eccDetail.curveID = tpmCurveId;

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (ecKey) EC_KEY_free(ecKey);
#endif
    if (bnX) BN_free(bnX);
    if (bnY) BN_free(bnY);
    return rc;
}

tool_rc get_public_from_cert(X509 *cert, TPM2B_PUBLIC *tpm_public)
{
    tool_rc rc = tool_rc_success;
    EVP_PKEY *public_key = NULL;

    public_key = X509_get_pubkey(cert);
    if (!public_key) {
        LOG_ERR("Certificate did not contain a public key.");
        return  tool_rc_general_error;
    }

    if (EVP_PKEY_type(EVP_PKEY_id(public_key)) == EVP_PKEY_RSA) {
        tpm_public->publicArea.type = TPM2_ALG_RSA;
        rc = get_rsa_tpm2b_public_from_evp(public_key, tpm_public);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else if (EVP_PKEY_type(EVP_PKEY_id(public_key)) == EVP_PKEY_EC) {
        tpm_public->publicArea.type = TPM2_ALG_ECC;
        rc = get_ecc_tpm2b_public_from_evp(public_key, tpm_public);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        LOG_ERR("Wrong key type");
        rc = tool_rc_general_error;
    }
    EVP_PKEY_free(public_key);
    return rc;
}


tool_rc get_tpm_properties(ESYS_CONTEXT *ectx) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    tool_rc rc = tool_rc_success;
    unsigned char *cert_buffer;
    unsigned char *cert_buffer_ossl;
    size_t cert_buffer_size;
    X509 *cert = NULL;
    TPM2B_PUBLIC public_key;

    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        goto get_tpm_properties_out;
    }

    ctx.manufacturer = capability_data->data.tpmProperties.tpmProperty[0].value;

    if (ctx.manufacturer == VENDOR_IBMSIM) {
        LOG_WARN("The TPM device is a simulator —— Inspect the certificate chain and root certificate");
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
        TPM2_NV_INDEX_FIRST, TPM2_PT_NV_INDEX_MAX, NULL,
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
        ek_index_map *m = lookup_ek_index_map(index);
        if (!m) {
            continue;
        }

        if (ctx.ek_path) {
            /* Read possible certificate  */
            rc = nv_read(ectx, index);
            if (rc != tool_rc_success) {
                return rc;
            }
            cert_buffer = m->cert_buffer;
            cert_buffer_size =  m->cert_buffer_size;
            ctx.web_cert_buffer_size = m->cert_buffer_size;
            cert_buffer_ossl = cert_buffer;
            cert = d2i_X509(NULL, (const unsigned char **)&cert_buffer_ossl, cert_buffer_size);
            if (!cert) {
                free(cert_buffer);
                LOG_WARN("Invalid certificate found at %x", index);
            } else {
                /* Compare certificate with pub key. */
                rc = get_public_from_cert(cert, &public_key);
                X509_free(cert);
                if (rc != tool_rc_success) {
                    return rc;
                }
                if (cmp_public_key(ctx.out_public, &public_key)) {
                    ctx.is_cert_on_nv = true;
                    m->found = true;
                    ctx.nv_cert_count++;
                    break;
                } else {
                    free(cert_buffer);
                    m->cert_buffer = NULL;
                }
            }
        } else {
            /* Update certificate table */
            m->found = true;
            ctx.is_cert_on_nv = true;
            ctx.nv_cert_count++;
            if (m->key_type == KTYPE_RSA) {
                LOG_INFO("Found pre-provisioned RSA EK certificate at %u [type=%s]", index, m->name);
            }
            if (m->key_type == KTYPE_ECC) {
                LOG_INFO("Found pre-provisioned ECC EK certificate at %u [type=%s]", index, m->name);
            }
        }
    }

get_tpm_properties_out:
    free(capability_data);
    return rc;
}

static tool_rc get_nv_ek_certificate(ESYS_CONTEXT *ectx) {
    size_t i;

    if (!ctx.is_cert_on_nv) {
        LOG_ERR("TCG specified location for EK certs aren't defined.");
        return tool_rc_general_error;
    }

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("Ignoring -X or --allow-unverified if EK certificate found on NV");
    }

    tool_rc rc = tool_rc_success;

    for (i = 0; i < ARRAY_LEN(ek_index_maps); i++) { 
        if (ek_index_maps[i].found) {
            rc = nv_read(ectx, ek_index_maps[i].index);
            if (rc != tool_rc_success) {
                return rc;
            }
        }
    }
    return rc;
}

static tool_rc print_intel_ek_certificate_warning(void) {

    if (ctx.manufacturer == VENDOR_INTEL &&
    ctx.is_tpmgeneratedeps && !ctx.is_cert_on_nv) {

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
    /* if ek_path is defined certificate was already read. */
    if (ctx.is_cert_on_nv && ctx.ek_path) {
         return rc;
    }
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
        if (!ctx.out_public) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }
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
    size_t i, j;
    bool is_intel_cert = ctx.manufacturer == VENDOR_INTEL;

    if (!is_intel_cert && ctx.web_cert_buffer) {
        is_intel_cert = !(strncmp((const char *)ctx.web_cert_buffer,
            "{\"pubhash", strlen("{\"pubhash")));
    }

    /*
     * Intel EK certificates on the NV-index are already in standard DER format.
     */
    if (is_intel_cert && ctx.is_cert_on_nv) {
        ctx.is_cert_raw = true;
    }

    /*
     *  Convert Intel EK certificates as received in the URL safe variant of
     *  Base 64: https://tools.ietf.org/html/rfc4648#section-5 to PEM
     */
    if (ctx.web_cert_buffer && is_intel_cert && !ctx.is_cert_raw) {
        char *split = strstr((char *)ctx.web_cert_buffer, "certificate");
        char *copy_buffer = base64_decode(&split, ctx.web_cert_buffer_size);
        ctx.web_cert_buffer_size = strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer) + strlen(PEM_END_CERT_LINE);
        strcpy((char *)ctx.web_cert_buffer, PEM_BEGIN_CERT_LINE);
        strcpy((char *)ctx.web_cert_buffer + strlen(PEM_BEGIN_CERT_LINE),
            copy_buffer);
        strcpy((char *)ctx.web_cert_buffer + strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer), PEM_END_CERT_LINE);
        free(copy_buffer);
    }

    bool retval = true;
    if (ctx.web_cert_buffer) {
        retval = files_write_bytes(
            ctx.ec_cert_file_handles[0] ? ctx.ec_cert_file_handles[0] : stdout,
            ctx.web_cert_buffer, ctx.web_cert_buffer_size);
        if (!retval) {
            return tool_rc_general_error;
        }
        return tool_rc_success;
    }

    /*
     * Output of all NV certificates.
     */

    /* If possible first write a RSA certificate to achieve backward compatibility */
    j = 0; /* index to file handles. */
    for (i = 0; i < ARRAY_LEN(ek_index_maps); i++) {
        if (ek_index_maps[i].cert_buffer && ek_index_maps[i].key_type == KTYPE_RSA) {
            retval = files_write_bytes(
                ctx.ec_cert_file_handles[j] ? ctx.ec_cert_file_handles[j] : stdout,
                ek_index_maps[i].cert_buffer, ek_index_maps[i].cert_buffer_size);
            if (!retval) {
                return tool_rc_general_error;
            }
            free(ek_index_maps[i].cert_buffer);
            ek_index_maps[i].cert_buffer = NULL;
            j++;
            break;
        }
    }

    for (i = 0; i < ARRAY_LEN(ek_index_maps); i++) {
        if (ek_index_maps[i].cert_buffer) {
            if (!ctx.ec_cert_file_handles[j] && j > 0) {
                break;
            }
            retval = files_write_bytes(
                ctx.ec_cert_file_handles[j] ? ctx.ec_cert_file_handles[j] : stdout,
                ek_index_maps[i].cert_buffer, ek_index_maps[i].cert_buffer_size);
            if (!retval) {
                return tool_rc_general_error;
            }
            j++;
        }
    }

    if (ctx.cert_count < ctx.nv_cert_count) {
        LOG_WARN("Found %zu certificates on NV. Add another -o to save all certificates",
                 ctx.nv_cert_count);
    }

    if (ctx.cert_count > ctx.nv_cert_count){
        LOG_WARN("Ignoring the additional output file since only %zu certificates found on NV",
                  ctx.nv_cert_count);
    }
 
    return tool_rc_success;
}

static tool_rc check_input_options(void) {
    size_t i = 0;

    while (ctx.ec_cert_paths[i]) {
        int fd = open(ctx.ec_cert_paths[i], O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd == -1) {
             LOG_ERR("Could not open file for writing: \"%s\"",
                     ctx.ec_cert_paths[i]);
             return tool_rc_general_error;
        }
        ctx.ec_cert_file_handles[i] = fdopen(fd, "wb");
        if (!ctx.ec_cert_file_handles[i]) {
            LOG_ERR("Could not open file for writing: \"%s\"",
                ctx.ec_cert_paths[i]);
            return tool_rc_general_error;
        }
        i++;
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
        /* - add value to cert file table
           - check counter
           - increment counter
         */
        if (ctx.cert_count == ARRAY_LEN(ek_index_maps)) {
            LOG_ERR("Max %zu certificates can be specified", ARRAY_LEN(ek_index_maps));
            return false;
        }
        ctx.ec_cert_paths[ctx.cert_count] = value;
        ctx.cert_count++;
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
    case 'E':
        if (!value || !value[0]) {
            LOG_ERR("No encoding given.");
            return false;
        } 
        switch (value[0]) {
            case 'a':
                ctx.encoding = ENC_AMD;
                break;
            case 'i':
                ctx.encoding = ENC_INTEL;
                break;
            default:
                LOG_ERR("Must specify a (AMD) or i (Intel) for encoding.");
                return false;
        }
        break;
    case 't':
        ctx.need_x509_trunc = true;
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
        { "encoding",         required_argument, NULL, 'E' },
        { "raw",              no_argument,       NULL,  0  },
        { "x509-trunc",       no_argument,       NULL, 't' },
    };

    *opts = tpm2_options_new("o:u:XxE:t", ARRAY_LEN(topts), topts, on_option,
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
    ctx.encoding = get_encoding();

    rc = get_ek_certificates(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return process_output();
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    size_t i = 0;

    while(ctx.ec_cert_paths[i]) {
        fclose(ctx.ec_cert_file_handles[i]);
        i++;
    }

    free(ctx.web_cert_buffer);

    for (i = 0; i < ARRAY_LEN(ek_index_maps); i++)
    {
        free(ek_index_maps[i].cert_buffer);
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
