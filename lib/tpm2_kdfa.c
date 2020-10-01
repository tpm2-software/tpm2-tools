/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "log.h"
#include "tpm2_kdfa.h"
#include "tpm2_openssl.h"

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

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(hash_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported for hmac: %x", hash_alg);
        return TPM2_RC_HASH;
    }

    HMAC_CTX *ctx = tpm2_openssl_hmac_new();
    if (!ctx) {
        LOG_ERR("HMAC context allocation failed");
        return TPM2_RC_MEMORY;
    }

    int rc = HMAC_Init_ex(ctx, key->buffer, key->size, md, NULL);
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
            int rc = HMAC_Update(ctx, digest->buffer, digest->size);
            if (!rc) {
                LOG_ERR("HMAC Update failed: %s", ERR_error_string(rc, NULL));
                rval = TPM2_RC_MEMORY;
                goto err;
            }
        }

        unsigned size = sizeof(tmpResult.buffer);
        int rc = HMAC_Final(ctx, tmpResult.buffer, &size);
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
    tpm2_openssl_hmac_free(ctx);

    return rval;
}
