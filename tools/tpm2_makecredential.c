//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// Copyright (c) 2019 Massachusetts Institute of Technology
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
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#include "files.h"
#include "tpm2_options.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_identity_util.h"
#include "tpm2_util.h"

typedef struct tpm_makecred_ctx tpm_makecred_ctx;
struct tpm_makecred_ctx {
    TPM2_HANDLE rsa2048_handle;
    TPM2B_NAME object_name;
    char *out_file_path;
    TPM2B_PUBLIC public;
    TPM2B_DIGEST credential;
    struct {
        UINT8 e : 1;
        UINT8 s : 1;
        UINT8 n : 1;
        UINT8 o : 1;
    } flags;
};

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
};

static bool write_cred_and_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;

    FILE *fp = fopen(path, "wb+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    result = files_write_header(fp, 1);
    if (!result) {
        LOG_ERR("Could not write version header");
        goto out;
    }

    result = files_write_16(fp, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential size");
        goto out;
    }

    result = files_write_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential data");
        goto out;
    }

    result = files_write_16(fp, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret size");
        goto out;
    }

    result = files_write_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static bool make_external_credential_and_save() {

    /*
     * Get name_alg from the public key
     */
    TPMI_ALG_HASH name_alg = ctx.public.publicArea.nameAlg;


    /* 
     * Generate and encrypt seed
     */
    TPM2B_DIGEST seed = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    seed.size = tpm2_alg_util_get_hash_size(name_alg);
    RAND_bytes(seed.buffer, seed.size);

    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    unsigned char label[10] = { 'I', 'D', 'E', 'N', 'T', 'I', 'T', 'Y', 0 };
    bool res = tpm2_identity_util_encrypt_seed_with_public_key(&seed,
            &ctx.public, label, 9,
            &encrypted_seed);
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return false;
    }

    /* 
     * Perform identity structure calculations (off of the TPM)
     */
    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            &ctx.public,
            &ctx.object_name,
            &seed,
            &hmac_key,
            &enc_key);

    /*
     * The ctx.credential needs to be marshalled into struct with 
     * both size and contents together (to be encrypted as a block)
     */
    TPM2B_MAX_BUFFER marshalled_inner_integrity = TPM2B_EMPTY_INIT;
    marshalled_inner_integrity.size = ctx.credential.size + sizeof(ctx.credential.size);
    UINT16 credSize = ctx.credential.size;
    if (!tpm2_util_is_big_endian()) {
        credSize = tpm2_util_endian_swap_16(credSize);
    }
    memcpy(marshalled_inner_integrity.buffer, &credSize, sizeof(credSize));
    memcpy(&marshalled_inner_integrity.buffer[2], ctx.credential.buffer, ctx.credential.size);

    /*
     * Perform inner encryption (encIdentity) and outer HMAC (outerHMAC)
     */
    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(
            name_alg,
            &ctx.object_name,
            &marshalled_inner_integrity,
            &hmac_key,
            &enc_key,
            &ctx.public.publicArea.parameters.rsaDetail.symmetric,
            &encrypted_sensitive,
            &outer_hmac);

    /*
     * Package up the info to save
     * cred_bloc = outer_hmac || encrypted_sensitive
     * secret = encrypted_seed (with pubEK)
     */
    TPM2B_ID_OBJECT cred_blob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);

    UINT16 outer_hmac_size = outer_hmac.size;
    if (!tpm2_util_is_big_endian()) {
        outer_hmac_size = tpm2_util_endian_swap_16(outer_hmac_size);
    }
    int offset = 0;
    memcpy(cred_blob.credential + offset, &outer_hmac_size, sizeof(outer_hmac.size));offset += sizeof(outer_hmac.size);
    memcpy(cred_blob.credential + offset, outer_hmac.buffer, outer_hmac.size);offset += outer_hmac.size;
    //NOTE: do NOT include the encrypted_sensitive size, since it is encrypted with the blob!
    memcpy(cred_blob.credential + offset, encrypted_sensitive.buffer, encrypted_sensitive.size);

    cred_blob.size = outer_hmac.size + encrypted_sensitive.size + sizeof(outer_hmac.size);

    return write_cred_and_secret(ctx.out_file_path, &cred_blob, &encrypted_seed);
}

static bool make_credential_and_save(TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    TPM2B_NAME name_ext = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_ID_OBJECT cred_blob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);

    TPM2B_ENCRYPTED_SECRET secret = TPM2B_TYPE_INIT(TPM2B_ENCRYPTED_SECRET, secret);

    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_LoadExternal(sapi_context, 0, NULL, &ctx.public,
            TPM2_RH_NULL, &ctx.rsa2048_handle, &name_ext, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("LoadExternal failed. TPM Error:0x%x", rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_MakeCredential(sapi_context, ctx.rsa2048_handle, 0,
            &ctx.credential, &ctx.object_name, &cred_blob, &secret,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("MakeCredential failed. TPM Error:0x%x", rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx.rsa2048_handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Flush loaded key failed. TPM Error:0x%x", rval);
        return false;
    }

    return write_cred_and_secret(ctx.out_file_path, &cred_blob, &secret);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'e': {
        bool res = files_load_public(value, &ctx.public);
        if (!res) {
            return false;
        }
        ctx.flags.e = 1;
    } break;
    case 's':
        ctx.credential.size = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if (!files_load_bytes_from_path(value, ctx.credential.buffer,
                                        &ctx.credential.size)) {
            return false;
        }
        ctx.flags.s = 1;
        break;
    case 'n': {
        ctx.object_name.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q;
        if ((q = tpm2_util_hex_to_byte_structure(value, &ctx.object_name.size,
                                            ctx.object_name.name)) != 0) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
        ctx.flags.n = 1;
    } break;
    case 'o':
        ctx.out_file_path = optarg;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"enckey"  ,required_argument, NULL, 'e'},
      {"sec"     ,required_argument, NULL, 's'},
      {"name"    ,required_argument, NULL, 'n'},
      {"out-file" ,required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("e:s:n:o:", ARRAY_LEN(topts), topts,
            on_option, NULL, 
            TPM2_OPTIONS_SHOW_USAGE | TPM2_OPTIONS_OPTIONAL_SAPI);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.flags.e || !ctx.flags.n || !ctx.flags.o || !ctx.flags.s) {
        LOG_ERR("Expected options e, n, o and s");
        return false;
    }

    printf("make credential has SAPI CTX: %p", sapi_context);

    bool result = sapi_context ? make_credential_and_save(sapi_context) : 
            make_external_credential_and_save();

    return result != true;
}
