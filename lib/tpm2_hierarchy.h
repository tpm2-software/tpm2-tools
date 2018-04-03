//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#ifndef TOOLS_TPM2_HIERARCHY_H_
#define TOOLS_TPM2_HIERARCHY_H_

#include <stdbool.h>

#include <tss2/tss2_sys.h>

typedef enum tpm2_hierarchy_flags tpm2_hierarchy_flags;

enum tpm2_hierarchy_flags {
    TPM2_HIERARCHY_FLAGS_NONE = 0,
    TPM2_HIERARCHY_FLAGS_O    = 1 << 0,
    TPM2_HIERARCHY_FLAGS_P    = 1 << 1,
    TPM2_HIERARCHY_FLAGS_E    = 1 << 2,
    TPM2_HIERARCHY_FLAGS_N    = 1 << 3,
    TPM2_HIERARCHY_FLAGS_ALL  = 0x0F
};

bool tpm2_hierarchy_from_optarg(const char *value,
        TPMI_RH_PROVISION *hierarchy, tpm2_hierarchy_flags flags);

typedef struct tpm2_hierarchy_pdata tpm2_hierarchy_pdata;
struct tpm2_hierarchy_pdata {
    struct {
        TPMI_RH_HIERARCHY hierarchy;
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        TPM2B_DATA outside_info;
        TPML_PCR_SELECTION creation_pcr;
        TPM2_HANDLE object_handle;
    } in;
    struct {
        TPM2_HANDLE handle;
        TPM2B_PUBLIC public;
        TPM2B_DIGEST hash;
        struct {
            TPM2B_CREATION_DATA data;
            TPMT_TK_CREATION ticket;
        } creation;
        TPM2B_NAME name;
    } out;
};

#define _PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .nameAlg = TPM2_ALG_SHA256, \
        .type = TPM2_ALG_RSA, \
        .objectAttributes = \
            TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
            |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
            |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH, \
        .parameters = { \
            .rsaDetail = { \
                .exponent = 0, \
                .symmetric = { \
                    .algorithm = TPM2_ALG_AES, \
                    .keyBits = { .aes = 128 }, \
                    .mode = { .aes = TPM2_ALG_CFB }, \
                 }, \
            .scheme = { .scheme = TPM2_ALG_NULL }, \
            .keyBits = 2048 \
            }, \
        }, \
            .unique = { .rsa = { .size = 0 } } \
    }, \
}

#define TPM2_HIERARCHY_DATA_INIT { \
    .in = { \
        .public = _PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT, \
        .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT, \
        .hierarchy = TPM2_RH_OWNER \
    }, \
}

/**
 * Creates a primary object.
 * @param sapi_context
 *  The system api context
 * @param sdata
 *  The authorization data for the hierarchy the primary object
 *  is associated with.
 * @param objdata
 *  The objects data configuration.
 * @return
 *  True on success, False on error.
 *  Logs errors via LOG_ERR().
 */
bool tpm2_hierarchy_create_primary(TSS2_SYS_CONTEXT *sapi_context,
        TPMS_AUTH_COMMAND *sdata,
        tpm2_hierarchy_pdata *objdata);

#endif /* TOOLS_TPM2_HIERARCHY_H_ */
