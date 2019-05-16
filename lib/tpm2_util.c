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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

bool tpm2_util_get_digest_from_quote(TPM2B_ATTEST *quoted, TPM2B_DIGEST *digest, TPM2B_DATA *extraData) {
    TPM2_GENERATED magic;
    TPMI_ST_ATTEST type;
    UINT16 nameSize = 0;
    UINT32 i = 0;

    // Ensure required headers are at least there
    if (quoted->size < 6) {
        LOG_ERR("Malformed TPM2B_ATTEST headers");
        return false;
    }

    memcpy(&magic, &quoted->attestationData[i], 4);i += 4;
    memcpy(&type, &quoted->attestationData[i], 2);i += 2;
    if (!tpm2_util_is_big_endian()) {
        magic = tpm2_util_endian_swap_32(magic);
        type = tpm2_util_endian_swap_16(type);
    }

    if (magic != TPM2_GENERATED_VALUE) {
        LOG_ERR("Malformed TPM2_GENERATED magic value");
        return false;
    }

    if (type != TPM2_ST_ATTEST_QUOTE) {
        LOG_ERR("Malformed TPMI_ST_ATTEST quote value");
        return false;
    }

    // Qualified signer name (skip)
    if (i+2 >= quoted->size) {
        LOG_ERR("Malformed TPM2B_NAME value");
        return false;
    }
    memcpy(&nameSize, &quoted->attestationData[i], 2);i += 2;
    if (!tpm2_util_is_big_endian()) {
        nameSize = tpm2_util_endian_swap_16(nameSize);
    }
    i += nameSize;

    // Extra data (skip)
    if (i+2 >= quoted->size) {
        LOG_ERR("Malformed TPM2B_DATA value");
        return false;
    }
    memcpy(&extraData->size, &quoted->attestationData[i], 2);i += 2;
    if (!tpm2_util_is_big_endian()) {
        extraData->size = tpm2_util_endian_swap_16(extraData->size);
    }
    if (extraData->size+i > quoted->size) {
        LOG_ERR("Malformed extraData TPM2B_DATA value");
        return false;
    }
    memcpy(&extraData->buffer, &quoted->attestationData[i], extraData->size);i += extraData->size;

    // Clock info (skip)
    i += 17;
    if (i >= quoted->size) {
        LOG_ERR("Malformed TPMS_CLOCK_INFO value");
        return false;
    }

    // Firmware info (skip)
    i += 8;
    if (i >= quoted->size) {
        LOG_ERR("Malformed firmware version value");
        return false;
    }

    // PCR select info
    UINT8 sos;
    TPMI_ALG_HASH hashAlg;
    UINT32 pcrSelCount = 0, j = 0;
    if (i+4 >= quoted->size) {
        LOG_ERR("Malformed TPML_PCR_SELECTION value");
        return false;
    }
    memcpy(&pcrSelCount, &quoted->attestationData[i], 4);i += 4;
    if (!tpm2_util_is_big_endian()) {
        pcrSelCount = tpm2_util_endian_swap_32(pcrSelCount);
    }
    for (j = 0; j < pcrSelCount; j++) {
        // Hash 
        if (i+2 >= quoted->size) {
            LOG_ERR("Malformed TPMS_PCR_SELECTION value");
            return false;
        }
        memcpy(&hashAlg, &quoted->attestationData[i], 2);i += 2;
        if (!tpm2_util_is_big_endian()) {
            hashAlg = tpm2_util_endian_swap_16(hashAlg);
        }

        // SizeOfSelected
        if (i+1 >= quoted->size) {
            LOG_ERR("Malformed TPMS_PCR_SELECTION value");
            return false;
        }
        memcpy(&sos, &quoted->attestationData[i], 1);i += 1;

        // PCR Select (skip)
        i += sos;
        if (i >= quoted->size) {
            LOG_ERR("Malformed TPMS_PCR_SELECTION value");
            return false;
        }
    }

    // Digest
    if (i+2 >= quoted->size) {
        LOG_ERR("Malformed TPM2B_DIGEST value");
        return false;
    }
    memcpy(&digest->size, &quoted->attestationData[i], 2);i += 2;
    if (!tpm2_util_is_big_endian()) {
        digest->size = tpm2_util_endian_swap_16(digest->size);
    }

    if (digest->size+i > quoted->size) {
        LOG_ERR("Malformed TPM2B_DIGEST value");
        return false;
    }
    memcpy(&digest->buffer, &quoted->attestationData[i], digest->size);

    return true;
}

// verify that the quote digest equals the digest we calculated
bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcrDigest) {

    // Sanity check -- they should at least be same size!
    if (quoteDigest->size != pcrDigest->size) {
        LOG_ERR("FATAL ERROR: PCR values failed to match quote's digest!");
        return false;
    }

    // Compare running digest with quote's digest
    int k;
    for (k = 0; k < quoteDigest->size; k++) {
        if (quoteDigest->buffer[k] != pcrDigest->buffer[k]) {
            LOG_ERR("FATAL ERROR: PCR values failed to match quote's digest!");
            return false;
        }
    }

    return true;
}

bool tpm2_util_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append) {

    if (!result || !append) {
        return false;
    }

    if ((result->size + append->size) < result->size) {
        return false;
    }

    if ((result->size + append->size) > TPM2_MAX_DIGEST_BUFFER) {
        return false;
    }

    memcpy(&result->buffer[result->size], append->buffer, append->size);
    result->size += append->size;

    return true;
}

bool tpm2_util_string_to_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

int tpm2_util_hex_to_byte_structure(const char *inStr, UINT16 *byteLength,
        BYTE *byteBuffer) {
    int strLength; //if the inStr likes "1a2b...", no prefix "0x"
    int i = 0;
    if (inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    strLength = strlen(inStr);
    if (strLength % 2)
        return -2;
    for (i = 0; i < strLength; i++) {
        if (!isxdigit(inStr[i]))
            return -3;
    }

    if (*byteLength < strLength / 2)
        return -4;

    *byteLength = strLength / 2;

    for (i = 0; i < *byteLength; i++) {
        char tmpStr[4] = { 0 };
        tmpStr[0] = inStr[i * 2];
        tmpStr[1] = inStr[i * 2 + 1];
        byteBuffer[i] = strtol(tmpStr, NULL, 16);
    }
    return 0;
}

void tpm2_util_hexdump(BYTE *data, size_t len, bool plain) {

    if (!output_enabled) {
        return;
    }

    if (plain) {
        size_t i;
        for (i=0; i < len; i++) {
            printf("%02x", data[i]);
        }
        return;
    }

    size_t i;
    size_t j;
    for (i = 0; i < len; i += 16) {
        printf("%06zx: ", i);

        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" ");

        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%c", isprint(data[i + j]) ? data[i + j] : '.');
            }
        }
        printf("\n");
    }
}

/* TODO OPTIMIZE ME */
UINT16 tpm2_util_copy_tpm2b(TPM2B *dest, TPM2B *src) {
    int i;
    UINT16 rval = 0;

    if (dest != 0) {
        if (src == 0) {
            dest->size = 0;
            rval = 0;
        } else {
            dest->size = src->size;
            for (i = 0; i < src->size; i++)
                dest->buffer[i] = src->buffer[i];
            rval = (sizeof(UINT16) + src->size);
        }
    } else {
        rval = 0;
    }

    return rval;
}

bool tpm2_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) { \
    \
        UINT##size converted; \
        UINT8 *bytes = (UINT8 *)&data; \
        UINT8 *tmp = (UINT8 *)&converted; \
    \
        size_t i; \
        for(i=0; i < sizeof(UINT##size); i ++) { \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1]; \
        } \
        \
        return converted; \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)
STRING_BYTES_ENDIAN_CONVERT(64)

#define STRING_BYTES_ENDIAN_HTON(size) \
    UINT##size tpm2_util_hton_##size(UINT##size data) { \
    \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        if (is_big_endian) { \
           return data; \
        } \
    \
        return tpm2_util_endian_swap_##size(data); \
    }

STRING_BYTES_ENDIAN_HTON(16)
STRING_BYTES_ENDIAN_HTON(32)
STRING_BYTES_ENDIAN_HTON(64)

/*
 * Converting from host-to-network (hton) or network-to-host (ntoh) is
 * the same operation: if endianess differs between host and data, swap
 * endianess. Thus we can just call the hton routines, but have some nice
 * names for folks.
 */
UINT16 tpm2_util_ntoh_16(UINT16 data) {
    return tpm2_util_hton_16(data);
}

UINT32 tpm2_util_ntoh_32(UINT32 data) {
    return tpm2_util_hton_32(data);
}
UINT64 tpm2_util_ntoh_64(UINT64 data) {
    return tpm2_util_hton_64(data);
}

UINT32 tpm2_util_pop_count(UINT32 data) {

    static const UINT8 bits_per_nibble[] =
        {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

    UINT8 count = 0;
    UINT8 *d = (UINT8 *)&data;

    size_t i;
    for (i=0; i < sizeof(data); i++) {
        count += bits_per_nibble[d[i] & 0x0f];
        count += bits_per_nibble[d[i] >> 4];
    }

    return count;
}

#define TPM2_UTIL_KEYDATA_INIT { .len = 0 };

typedef struct tpm2_util_keydata tpm2_util_keydata;
struct tpm2_util_keydata {
    UINT16 len;
    struct {
        const char *name;
        TPM2B *value;
    } entries[2];
};

static void tpm2_util_public_to_keydata(TPM2B_PUBLIC *public, tpm2_util_keydata *keydata) {

    switch (public->publicArea.type) {
    case TPM2_ALG_RSA:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(public->publicArea.type);
        keydata->entries[0].value = (TPM2B *)&public->publicArea.unique.rsa;
        return;
    case TPM2_ALG_KEYEDHASH:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(public->publicArea.type);
        keydata->entries[0].value = (TPM2B *)&public->publicArea.unique.keyedHash;
        return;
    case TPM2_ALG_SYMCIPHER:
        keydata->len = 1;
        keydata->entries[0].name = tpm2_alg_util_algtostr(public->publicArea.type);
        keydata->entries[0].value = (TPM2B *)&public->publicArea.unique.sym;
        return;
    case TPM2_ALG_ECC:
        keydata->len = 2;
        keydata->entries[0].name = "x";
        keydata->entries[0].value = (TPM2B *)&public->publicArea.unique.ecc.x;
        keydata->entries[1].name = "y";
        keydata->entries[1].value = (TPM2B *)&public->publicArea.unique.ecc.y;
        return;
    default:
        LOG_WARN("The algorithm type(0x%4.4x) is not supported",
                public->publicArea.type);
    }

    return;
}

void tpm2_util_public_to_yaml(TPM2B_PUBLIC *public) {

    tpm2_tool_output("algorithm:\n");
    tpm2_tool_output("  value: %s\n", tpm2_alg_util_algtostr(public->publicArea.nameAlg));
    tpm2_tool_output("  raw: 0x%x\n", public->publicArea.nameAlg);

    char *attrs = tpm2_attr_util_obj_attrtostr(public->publicArea.objectAttributes);
    tpm2_tool_output("attributes:\n");
    tpm2_tool_output("  value: %s\n", attrs);
    tpm2_tool_output("  raw: 0x%x\n", public->publicArea.objectAttributes);

    tpm2_tool_output("type: \n");
    tpm2_tool_output("  value: %s\n", tpm2_alg_util_algtostr(public->publicArea.type));
    tpm2_tool_output("  raw: 0x%x\n", public->publicArea.type);

    tpm2_util_keydata keydata = TPM2_UTIL_KEYDATA_INIT;
    tpm2_util_public_to_keydata(public, &keydata);

    UINT16 i;
    /* if no keydata len will be 0 and it wont print */
    for (i=0; i < keydata.len; i++) {
        tpm2_tool_output("  %s: ", keydata.entries[i].name);
        tpm2_util_print_tpm2b(keydata.entries[i].value);
        tpm2_tool_output("\n");
    }

    if (public->publicArea.authPolicy.size) {
        tpm2_tool_output("authorization policy: ");
        tpm2_util_hexdump(public->publicArea.authPolicy.buffer,
                public->publicArea.authPolicy.size, true);
        tpm2_tool_output("\n");
    }

    free(attrs);
}
