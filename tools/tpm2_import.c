//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

#include <limits.h>
#include <sapi/tpm20.h>
#include <sapi/tss2_mu.h>

#include "log.h"
#include "files.h"
#include "tpm_kdfa.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#define SYM_KEY_SIZE 16
#define max_buffer_size  1024

#define RSA_2K_MODULUS_SIZE_IN_BYTES 256
#define RSA_2K_PUBLIC_MODULUS_OFFSET 28

typedef struct tpm_import_ctx tpm_import_ctx;
struct tpm_import_ctx {
    char *input_key_file;
    char *import_key_public_file;
    char *import_key_private_file;
    char *parent_key_public_file;
    uint8_t input_key_buffer[SYM_KEY_SIZE];
    //Parent public key for seed encryption
    TPM2B_PUBLIC_KEY_RSA parent_public_key;
    TPM2_HANDLE parent_key_handle;
    //External key public
    TPM2B_PUBLIC import_key_public;
    //External key name
    TPM2B_NAME import_key_public_name;
    //External key sensitive
    TPM2B_SENSITIVE import_key_sensitive;
    //External key private
    TPM2B_PRIVATE import_key_private;
    //Protection Seed and keys
    uint8_t protection_seed_data[TPM2_SHA256_DIGEST_SIZE]; //max tpm digest
    uint8_t encrypted_protection_seed_data[RSA_2K_MODULUS_SIZE_IN_BYTES];
    uint8_t protection_hmac_key[TPM2_SHA256_DIGEST_SIZE];
    uint8_t protection_enc_key[SYM_KEY_SIZE];
    uint8_t import_key_public_unique_data[TPM2_SHA256_DIGEST_SIZE];
    uint8_t outer_integrity_hmac[TPM2_SHA256_DIGEST_SIZE];
    TPM2B_DATA enc_sensitive_key;
    TPM2B_MAX_BUFFER encrypted_inner_integrity;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive;
    UINT32 objectAttributes;
};

static tpm_import_ctx ctx = { 
    .input_key_file = NULL, 
    .parent_key_handle = 0,
    .parent_public_key = TPM2B_INIT(RSA_2K_MODULUS_SIZE_IN_BYTES),
    .import_key_public = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea),
    .import_key_public_name = TPM2B_TYPE_INIT(TPM2B_NAME, name),
    .import_key_private = TPM2B_EMPTY_INIT,
};

#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER) /* OpenSSL 1.1.0 */
static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {

    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL)) {
        return 0;
    }

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }

    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }

    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif

static bool encrypt_seed_with_tpm2_rsa_public_key(void) {
    bool rval = false;

    //Public Modulus
    FILE *fp = fopen(ctx.parent_key_public_file, "rb");
    if (fp == NULL) {
        LOG_ERR("Failed accessing parent key public file.");
        return false;
    }
    if (fseek(fp, RSA_2K_PUBLIC_MODULUS_OFFSET, SEEK_SET) != 0) {
        LOG_ERR("Expected parent key public data file size failure");
        fclose(fp);
        return false;
    }
    unsigned char pub_modulus[RSA_2K_MODULUS_SIZE_IN_BYTES] = { 0 };
    int ret = fread(pub_modulus, 1, RSA_2K_MODULUS_SIZE_IN_BYTES, fp);
    if (ret != RSA_2K_MODULUS_SIZE_IN_BYTES) {
        LOG_ERR("Failed reading public modulus from parent key public file");
        fclose(fp);
        return false;
    }
    fclose(fp);
    RSA *rsa = NULL;
    unsigned char encoded[RSA_2K_MODULUS_SIZE_IN_BYTES];
    unsigned char label[10] = { 'D', 'U', 'P', 'L', 'I', 'C', 'A', 'T', 'E', 0 };
    int return_code = RSA_padding_add_PKCS1_OAEP_mgf1(encoded,
            RSA_2K_MODULUS_SIZE_IN_BYTES, ctx.protection_seed_data, 32, label, 10,
            EVP_sha256(), NULL);
    if (return_code != 1) {
        LOG_ERR("Failed RSA_padding_add_PKCS1_OAEP_mgf1\n");
        return false;
    }
    BIGNUM* bne = BN_new();
    if (!bne) {
        LOG_ERR("BN_new for bne failed\n");
        return false;
    }
    return_code = BN_set_word(bne, RSA_F4);
    if (return_code != 1) {
        LOG_ERR("BN_set_word failed\n");
        BN_free(bne);
        return false;
    }
    rsa = RSA_new();
    if (!rsa) {
        LOG_ERR("RSA_new failed\n");
        BN_free(bne);
        return false;
    }
    return_code = RSA_generate_key_ex(rsa, 2048, bne, NULL);
    BN_free(bne);
    if (return_code != 1) {
        LOG_ERR("RSA_generate_key_ex failed\n");
        goto error;
    }
    BIGNUM *n = BN_bin2bn(pub_modulus, RSA_2K_MODULUS_SIZE_IN_BYTES, NULL);
    if (n == NULL) {
        LOG_ERR("BN_bin2bn failed\n");
        goto error;
    }
    if (!RSA_set0_key(rsa, n, NULL, NULL)) {
        LOG_ERR("RSA_set0_key failed\n");
        BN_free(n);
        goto error;
    }
    // Encrypting
    return_code = RSA_public_encrypt(RSA_2K_MODULUS_SIZE_IN_BYTES, encoded,
            ctx.encrypted_protection_seed_data, rsa, RSA_NO_PADDING);
    if (return_code < 0) {
        LOG_ERR("Failed RSA_public_encrypt\n");
        goto error;
    }

    rval = true;

error:
    RSA_free(rsa);
    return rval;
}

static void aes_128_cfb_encrypt_buffers(uint8_t *buffer1, uint16_t buffer1_size,
        uint8_t *buffer2, uint16_t buffer2_size, uint8_t *encryption_key,
        uint8_t *encrypted_data) {
    //AES encryption
    uint8_t to_encrypt_buffer[max_buffer_size];
    memcpy(to_encrypt_buffer, buffer1, buffer1_size);
    memcpy(to_encrypt_buffer + buffer1_size, buffer2, buffer2_size);

    uint8_t iv_in[SYM_KEY_SIZE] = { 0 };
    AES_KEY aes;
    AES_set_encrypt_key(encryption_key, SYM_KEY_SIZE * 8, &aes);

    int block;
    int num = 0;
    for (block = 0; block < (buffer1_size + buffer2_size) / SYM_KEY_SIZE;
            block++) {
        AES_cfb128_encrypt(to_encrypt_buffer + (block * SYM_KEY_SIZE),
                encrypted_data + (block * SYM_KEY_SIZE),
                SYM_KEY_SIZE, &aes, iv_in, &num, AES_ENCRYPT);
    }
    AES_cfb128_encrypt(to_encrypt_buffer + (block * SYM_KEY_SIZE),
            encrypted_data + (block * SYM_KEY_SIZE),
            (buffer1_size + buffer2_size) % SYM_KEY_SIZE, &aes, iv_in, &num,
            AES_ENCRYPT);
}

static void hmac_outer_integrity(uint8_t *buffer1, uint16_t buffer1_size,
        uint8_t *buffer2, uint16_t buffer2_size, uint8_t *hmac_key,
        uint8_t *outer_integrity_hmac) {

    uint8_t to_hmac_buffer[max_buffer_size];
    memcpy(to_hmac_buffer, buffer1, buffer1_size);
    memcpy(to_hmac_buffer + buffer1_size, buffer2, buffer2_size);
    uint32_t size_in = 0;
    HMAC(EVP_sha256(), hmac_key, TPM2_SHA256_DIGEST_SIZE, to_hmac_buffer,
            buffer1_size + buffer2_size, outer_integrity_hmac, &size_in);
}

static void create_random_seed_and_sensitive_enc_key(void) {

    RAND_bytes(ctx.protection_seed_data, TPM2_SHA256_DIGEST_SIZE); //max tpm digest
    ctx.enc_sensitive_key.size = SYM_KEY_SIZE;
    RAND_bytes(ctx.enc_sensitive_key.buffer, SYM_KEY_SIZE);

}

static bool calc_sensitive_unique_data(void) {

    uint8_t *concatenated_seed_unique = malloc(
            TPM2_SHA256_DIGEST_SIZE + SYM_KEY_SIZE);
    if (!concatenated_seed_unique) {
        LOG_ERR("oom");
        return false;
    }

    memcpy(concatenated_seed_unique, ctx.protection_seed_data,
            TPM2_SHA256_DIGEST_SIZE);
    memcpy(concatenated_seed_unique + TPM2_SHA256_DIGEST_SIZE, ctx.input_key_buffer,
            SYM_KEY_SIZE);

    SHA256(concatenated_seed_unique, TPM2_SHA256_DIGEST_SIZE + SYM_KEY_SIZE,
            ctx.import_key_public_unique_data);

    free(concatenated_seed_unique);

    return true;
}

#define IMPORT_KEY_SYM_PUBLIC_AREA(X) \
    (X).publicArea.type = TPM2_ALG_SYMCIPHER; \
    (X).publicArea.nameAlg = TPM2_ALG_SHA256;\
    (X).publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;\
    (X).publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;\
    (X).publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;\
    (X).publicArea.objectAttributes |= TPMA_OBJECT_SIGN;\
    (X).publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDTPM;\
    (X).publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDPARENT;\
    (X).publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;\
    (X).publicArea.authPolicy.size = 0;\
    (X).publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;\
    (X).publicArea.parameters.symDetail.sym.keyBits.sym = 128;\
    (X).publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;\
    (X).publicArea.unique.sym.size = TPM2_SHA256_DIGEST_SIZE;\

static bool create_import_key_public_data_and_name(void) {

    IMPORT_KEY_SYM_PUBLIC_AREA(ctx.import_key_public)

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &ctx.import_key_public.publicArea.objectAttributes);

    if (ctx.objectAttributes) {
        ctx.import_key_public.publicArea.objectAttributes = ctx.objectAttributes;
    }

    tpm2_util_tpma_object_to_yaml(ctx.import_key_public.publicArea.objectAttributes);

    memcpy(ctx.import_key_public.publicArea.unique.sym.buffer,
            ctx.import_key_public_unique_data, TPM2_SHA256_DIGEST_SIZE);

    size_t public_area_marshalled_offset = 0;
    uint8_t *marshalled_bytes = malloc(sizeof(ctx.import_key_public));
    if (!marshalled_bytes) {
        LOG_ERR("oom");
        return false;
    }

    Tss2_MU_TPM2B_PUBLIC_Marshal(&ctx.import_key_public, marshalled_bytes,
            sizeof(ctx.import_key_public), &public_area_marshalled_offset);

    ctx.import_key_public_name.size = TPM2_SHA256_DIGEST_SIZE;
    size_t name_digest_alg_offset = 0;
    Tss2_MU_UINT16_Marshal(TPM2_ALG_SHA256, ctx.import_key_public_name.name,
            sizeof(TPM2_ALG_ID), &name_digest_alg_offset);
    ctx.import_key_public_name.size += name_digest_alg_offset;
    SHA256(marshalled_bytes + sizeof(uint16_t),
            public_area_marshalled_offset - sizeof(uint16_t),
            ctx.import_key_public_name.name + sizeof(TPM2_ALG_ID));
    free(marshalled_bytes);

    return true;
}

#define IMPORT_KEY_SYM_SENSITIVE_AREA(X) \
    (X).sensitiveArea.sensitiveType = TPM2_ALG_SYMCIPHER; \
    (X).sensitiveArea.authValue.size = 0; \
    (X).sensitiveArea.seedValue.size = TPM2_SHA256_DIGEST_SIZE; \
    (X).sensitiveArea.sensitive.sym.size = SYM_KEY_SIZE; \

static void create_import_key_sensitive_data(void) {

    IMPORT_KEY_SYM_SENSITIVE_AREA(ctx.import_key_sensitive);

    memcpy(ctx.import_key_sensitive.sensitiveArea.seedValue.buffer,
            ctx.protection_seed_data, TPM2_SHA256_DIGEST_SIZE); //max digest size

    memcpy(ctx.import_key_sensitive.sensitiveArea.sensitive.sym.buffer,
            ctx.input_key_buffer, SYM_KEY_SIZE);
}

#define PARENT_NAME_ALG TPM2_ALG_SHA256
static bool calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(void) {

    TPM2B null_2b = { .size = 0 };
    TPM2B_DIGEST to_TPM2B_seed = TPM2B_INIT(TPM2_SHA256_DIGEST_SIZE);
    memcpy(to_TPM2B_seed.buffer, ctx.protection_seed_data,
            TPM2_SHA256_DIGEST_SIZE); //max digest size
    TPM2B_MAX_BUFFER result_key;

    TSS2_RC rval = tpm_kdfa(PARENT_NAME_ALG, (TPM2B *)&to_TPM2B_seed, "INTEGRITY",
            &null_2b, &null_2b, TPM2_SHA256_DIGEST_SIZE * 8, &result_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }
    memcpy(ctx.protection_hmac_key, result_key.buffer, TPM2_SHA256_DIGEST_SIZE);

    rval = tpm_kdfa(PARENT_NAME_ALG, (TPM2B *)&to_TPM2B_seed, "STORAGE",
            (TPM2B *)&ctx.import_key_public_name, &null_2b, SYM_KEY_SIZE * 8,
            &result_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }
    memcpy(ctx.protection_enc_key, result_key.buffer, SYM_KEY_SIZE);

    return true;
}

static void calculate_inner_integrity(void) {

    //Marshal sensitive area
    uint8_t buffer_marshalled_sensitiveArea[max_buffer_size] = { 0 };
    size_t marshalled_sensitive_size = 0;
    Tss2_MU_TPMT_SENSITIVE_Marshal(&ctx.import_key_sensitive.sensitiveArea,
            buffer_marshalled_sensitiveArea + sizeof(uint16_t), max_buffer_size,
            &marshalled_sensitive_size);
    size_t marshalled_sensitive_size_info = 0;
    Tss2_MU_UINT16_Marshal(marshalled_sensitive_size, buffer_marshalled_sensitiveArea,
            sizeof(uint16_t), &marshalled_sensitive_size_info);

    //concatenate NAME
    memcpy(
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info,
            ctx.import_key_public_name.name,
            ctx.import_key_public_name.size);

    //Digest marshalled-sensitive || name
    uint8_t *marshalled_sensitive_and_name_digest =
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info
                    + ctx.import_key_public_name.size;
    size_t digest_size_info = 0;
    Tss2_MU_UINT16_Marshal(TPM2_SHA256_DIGEST_SIZE, marshalled_sensitive_and_name_digest,
            sizeof(uint16_t), &digest_size_info);

    SHA256(buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size
                    + ctx.import_key_public_name.size,
            marshalled_sensitive_and_name_digest + digest_size_info);

    //Inner integrity
    ctx.encrypted_inner_integrity.size = marshalled_sensitive_size_info
            + marshalled_sensitive_size + ctx.import_key_public_name.size;
    aes_128_cfb_encrypt_buffers(marshalled_sensitive_and_name_digest,
            TPM2_SHA256_DIGEST_SIZE + digest_size_info,
            buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size,
            ctx.enc_sensitive_key.buffer,
            &ctx.encrypted_inner_integrity.buffer[0]);
}

static void calculate_outer_integrity(void) {

    //Calculate dupSensitive
    ctx.encrypted_duplicate_sensitive.size =
            ctx.encrypted_inner_integrity.size;

    aes_128_cfb_encrypt_buffers(ctx.encrypted_inner_integrity.buffer,
            ctx.encrypted_inner_integrity.size, NULL, 0,
            ctx.protection_enc_key,
            &ctx.encrypted_duplicate_sensitive.buffer[0]);
    //Calculate outerHMAC
    hmac_outer_integrity(ctx.encrypted_duplicate_sensitive.buffer,
            ctx.encrypted_duplicate_sensitive.size,
            ctx.import_key_public_name.name,
            ctx.import_key_public_name.size, ctx.protection_hmac_key,
            ctx.outer_integrity_hmac);
}

static void create_import_key_private_data(void) {
    ctx.import_key_private.size = sizeof(uint16_t) + TPM2_SHA256_DIGEST_SIZE
            + ctx.encrypted_duplicate_sensitive.size;
    size_t hmac_size_offset = 0;
    Tss2_MU_UINT16_Marshal(TPM2_SHA256_DIGEST_SIZE, ctx.import_key_private.buffer,
            sizeof(uint16_t), &hmac_size_offset);
    memcpy(ctx.import_key_private.buffer + hmac_size_offset,
            ctx.outer_integrity_hmac, TPM2_SHA256_DIGEST_SIZE);
    memcpy(
            ctx.import_key_private.buffer + hmac_size_offset
                    + TPM2_SHA256_DIGEST_SIZE,
            ctx.encrypted_duplicate_sensitive.buffer,
            ctx.encrypted_duplicate_sensitive.size);
}

static bool import_external_key_and_save_public_private_data(TSS2_SYS_CONTEXT *sapi_context) {


    TSS2L_SYS_AUTH_COMMAND npsessionsData =
            TSS2L_SYS_AUTH_COMMAND_INIT(1, {TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)});

    TSS2L_SYS_AUTH_RESPONSE npsessionsDataOut;

    TPMT_SYM_DEF_OBJECT symmetricAlg = {
            .algorithm = TPM2_ALG_AES,
            .keyBits.aes = 128,
            .mode.aes = TPM2_ALG_CFB
    };

    TPM2B_PRIVATE importPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);
    TPM2B_ENCRYPTED_SECRET enc_inp_seed = TPM2B_INIT(RSA_2K_MODULUS_SIZE_IN_BYTES);

    memcpy(enc_inp_seed.secret, ctx.encrypted_protection_seed_data,
            RSA_2K_MODULUS_SIZE_IN_BYTES);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Import(sapi_context, ctx.parent_key_handle,
            &npsessionsData, &ctx.enc_sensitive_key, &ctx.import_key_public,
            &ctx.import_key_private, &enc_inp_seed, &symmetricAlg,
            &importPrivate, &npsessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Import, rval);
        return false;
    }

    bool res = files_save_public(&ctx.import_key_public, ctx.import_key_public_file);
    if(!res) {
        return false;
    }

    res = files_save_private(&importPrivate, ctx.import_key_private_file);
    if (!res) {
        return false;
    }

    return true;
}

static bool key_import(TSS2_SYS_CONTEXT *sapi_context) {

    create_random_seed_and_sensitive_enc_key();

    bool res = calc_sensitive_unique_data();
    if (!res) {
        return false;
    }

    res = create_import_key_public_data_and_name();
    if (!res) {
        return false;
    }

    create_import_key_sensitive_data();

    calc_outer_integrity_hmac_key_and_dupsensitive_enc_key();

    calculate_inner_integrity();

    calculate_outer_integrity();

    create_import_key_private_data();

    res = encrypt_seed_with_tpm2_rsa_public_key();
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return false;
    }
    res = import_external_key_and_save_public_private_data(sapi_context);
    if (!res) {
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'k':
        ctx.input_key_file = value;
        uint16_t input_key_buffer_length = SYM_KEY_SIZE;
        if (!files_load_bytes_from_path(ctx.input_key_file,
                ctx.input_key_buffer, &input_key_buffer_length)) {
            return false;
        }
        break;
    case 'H':
        if (!tpm2_util_string_to_uint32(value, &ctx.parent_key_handle)) {
            LOG_ERR("Failed retrieving parent-key-handle value");
            return false;
        }
        break;
    case 'f':
        ctx.parent_key_public_file = value;
        break;
    case 'q':
        ctx.import_key_public_file = value;
        break;
    case 'r':
        ctx.import_key_private_file = value;
        break;
    case 'A':
        if(!tpm2_util_string_to_uint32(value, &ctx.objectAttributes)) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "input-key-file",     required_argument, NULL, 'k'},
      { "parent-key-handle",  required_argument, NULL, 'H'},
      { "parent-key-public",  required_argument, NULL, 'f'},
      { "import-key-private", required_argument, NULL, 'r'},
      { "import-key-public",  required_argument, NULL, 'q'},
      { "object-attributes",  required_argument, NULL, 'A' },
    };

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    *opts = tpm2_options_new("k:H:f:q:r:A:", ARRAY_LEN(topts), topts, on_option,
                             NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.input_key_file || !ctx.parent_key_handle
            || !ctx.parent_key_public_file || !ctx.import_key_public_file
            || !ctx.import_key_private_file) {
        LOG_ERR("tpm2_import tool missing arguments: %s\n %08X\n %s\n %s\n %s\n",
             ctx.input_key_file, ctx.parent_key_handle, ctx.parent_key_public_file,
             ctx.import_key_public_file,ctx.import_key_private_file );
        return 1;
    }

    return !key_import(sapi_context);
}
