/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/hmac.h>
#else
#include <openssl/core_names.h>
#endif

#include "log.h"
#include "tpm2_kdfa.h"
#include "tpm2_openssl.h"

/*
 * Disable optimization because of an error in FORTIFY_SOURCE
 */

#ifdef _FORTIFY_SOURCE
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif

TSS2_RC tpm2_kdfa(TPMI_ALG_HASH hash_alg, TPM2B *key, char *label,
        TPM2B *context_u, TPM2B *context_v, UINT16 bits,
        TPM2B_MAX_BUFFER *result_key) {
    TPM2B_DIGEST tpm2b_label, tpm2b_bits, tpm2b_i_2;
    TPM2B_DIGEST *buffer_list[8];
    TSS2_RC rval = TPM2_RC_SUCCESS;
    int i, j;
    UINT16 bytes = bits / 8;

    result_key->size = 0;

    tpm2b_i_2.size = 4;

    tpm2b_bits.size = 4;
    UINT32 bits_be = tpm2_util_hton_32(bits);
    memcpy(&tpm2b_bits.buffer[0], &bits_be, sizeof(bits_be));

    for(i = 0; label[i] != 0 ;i++ );

    tpm2b_label.size = i + 1;
    for (i = 0; i < tpm2b_label.size; i++) {
        tpm2b_label.buffer[i] = label[i];
    }

    result_key->size = 0;

    i = 1;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(hash_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported for hmac: %x", hash_alg);
        return TPM2_RC_HASH;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX *ctx = HMAC_CTX_new();
#else
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
#endif
    if (!ctx) {
        LOG_ERR("HMAC context allocation failed");
        return TPM2_RC_MEMORY;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    int rc = HMAC_Init_ex(ctx, key->buffer, key->size, md, NULL);
#else
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST,
                                                 (char *)EVP_MD_get0_name(md), 0);
    params[1] = OSSL_PARAM_construct_end();
    int rc = EVP_MAC_init(ctx, key->buffer, key->size, params);
#endif
    if (!rc) {
        LOG_ERR("HMAC Init failed: %s", ERR_error_string(rc, NULL));
        rval = TPM2_RC_MEMORY;
        goto err;
    }

    // TODO Why is this a loop? It appears to only execute once.
    while (result_key->size < bytes) {
        TPM2B_DIGEST tmpResult;
        // Inner loop
        bits_be = tpm2_util_hton_32(i);
        memcpy(&tpm2b_i_2.buffer[0], &bits_be, sizeof(bits_be));

        j = 0;
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_i_2);
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_label);
        buffer_list[j++] = (TPM2B_DIGEST *) context_u;
        buffer_list[j++] = (TPM2B_DIGEST *) context_v;
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_bits);
        buffer_list[j] = (TPM2B_DIGEST *) 0;

        int c;
        for (c = 0; c < j; c++) {
            TPM2B_DIGEST *digest = buffer_list[c];
#if OPENSSL_VERSION_NUMBER < 0x30000000L
            int rc = HMAC_Update(ctx, digest->buffer, digest->size);
#else
            int rc = EVP_MAC_update(ctx, digest->buffer, digest->size);
#endif
            if (!rc) {
                LOG_ERR("HMAC Update failed: %s", ERR_error_string(rc, NULL));
                rval = TPM2_RC_MEMORY;
                goto err;
            }
        }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
        unsigned size = sizeof(tmpResult.buffer);
        int rc = HMAC_Final(ctx, tmpResult.buffer, &size);
#else
        size_t size;
        int rc = EVP_MAC_final(ctx, tmpResult.buffer, &size, sizeof(tmpResult.buffer));
#endif
        if (!rc) {
            LOG_ERR("HMAC Final failed: %s", ERR_error_string(rc, NULL));
            rval = TPM2_RC_MEMORY;
            goto err;
        }

        tmpResult.size = size;

        bool res = tpm2_util_concat_buffer(result_key, (TPM2B *) &tmpResult);
        if (!res) {
            rval = TSS2_SYS_RC_BAD_VALUE;
            goto err;
        }
    }

    // Truncate the result to the desired size.
    result_key->size = bytes;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX_free(ctx);
#else
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(hmac);
#endif

    return rval;
}
#ifdef _FORTIFY_SOURCE

#endif

#ifdef _FORTIFY_SOURCE
#pragma GCC pop_options
#endif



