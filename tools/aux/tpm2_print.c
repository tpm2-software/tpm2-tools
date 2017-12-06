//**********************************************************************;
// Copyright (c) 2017, National Instruments
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

#include <stdio.h>
#include "log.h"
#include "files.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"

#define FILE_2_SHORT_ERROR(filename) LOG_ERR("%s: File too short", (filename))

static void print_hex_buffer(const UINT8* buff, UINT32 size) {
    while(size-- > 0) {
        printf("%2.2x", (unsigned int)*buff);
        ++buff;
    }
    printf("\n");
}

static bool print_hex(FILE* fd, const char* const filename, UINT32 size) {
    UINT8 byte;
    while(size-- > 0) {
        if(fread(&byte, 1, 1, fd) != 1) {
            FILE_2_SHORT_ERROR(filename);
            printf("\n");
            return false;
        }
        printf("%2.2x", (unsigned int)byte);
    }
    printf("\n");
    return true;
}

static bool print_tpm2b_hex(FILE* fd, const char* const filename) {
    UINT16 size;
    if(!files_read_16(fd, &size)) {
        FILE_2_SHORT_ERROR(filename);
        return false;
    }
    return print_hex(fd, filename, size);
}

static bool print_clock_info(FILE* fd, const char* const filename, const char* const prefix) {
    union {
        UINT8  u8;
        UINT32 u32;
        UINT64 u64;
    } numb;

    if(!files_read_64(fd, &numb.u64)) {
        goto read_error;
    }
    printf("%s.clockInfo.clock=%llu\n", prefix, (long long unsigned int)numb.u64);

    if(!files_read_32(fd, &numb.u32)) {
        goto read_error;
    }
    printf("%s.clockInfo.resetCount=%lu\n", prefix, (long unsigned int)numb.u32);

    if(!files_read_32(fd, &numb.u32)) {
        goto read_error;
    }
    printf("%s.clockInfo.restartCount=%lu\n", prefix, (long unsigned int)numb.u32);

    if(fread(&numb.u8, 1, 1, fd) != 1) {
        goto read_error;
    }
    printf("%s.clockInfo.safe=%u\n", prefix, (unsigned int)numb.u8);

    // success
    return true;

    read_error:
    FILE_2_SHORT_ERROR(filename);
    return false;
}

static bool print_TPMS_QUOTE_INFO(FILE* fd, const char* const filename, const char* const prefix) {
    // read TPML_PCR_SELECTION count (UINT32)
    UINT32 pcr_selection_count;
    if(!files_read_32(fd, &pcr_selection_count)) {
        goto read_error;
    }
    printf("%s.pcrSelect.count=%lu\n", prefix, (long unsigned int)pcr_selection_count);

    // read TPML_PCR_SELECTION array (of size count)
    for(long unsigned int i = 0; i < pcr_selection_count; ++i) {
        // print hash type (TPMI_ALG_HASH)
        UINT16 hash_type;
        if(!files_read_16(fd, &hash_type)) {
            goto read_error;
        }
        if(!tpm2_alg_util_is_hash_alg(hash_type)) {
            LOG_ERR("%s: Invalid hash type in quote", filename);
            goto error;
        }
        const char* const hash_name = tpm2_alg_util_algtostr(hash_type);
        printf("%s.pcrSelect[%lu].hash=%u (%s)\n", prefix, i, (unsigned int)hash_type, hash_name);

        UINT8 sizeofSelect;
        if(fread(&sizeofSelect, 1, 1, fd) != 1) {
            goto read_error;
        }
        printf("%s.pcrSelect[%lu].sizeofSelect=%u\n", prefix, i, (unsigned int)sizeofSelect);

        // print PCR selection in hex
        printf("%s.pcrSelect[%lu].pcrSelect=", prefix, i);
        if(!print_hex(fd, filename, sizeofSelect)) {
            goto error;
        }
    }

    UINT16 digest_size;
    if(!files_read_16(fd, &digest_size)) {
        goto read_error;
    }
    printf("%s.pcrDigest.size=%lu\n", prefix, (long unsigned int)digest_size);

    // check digest size
    if(digest_size < 1) {
        LOG_ERR("%s: Digest missing (zero size)", filename);
        goto error;
    }

    // print digest in hex
    printf("%s.pcrDigest=", prefix);
    if(!print_hex(fd, filename, digest_size)) {
        goto error;
    }

    // success
    return true;

    read_error:
    FILE_2_SHORT_ERROR(filename);
    error:
    return false;
}

static bool print_TPMS_ATTEST(FILE* fd, const char* const filename) {
    // print magic without converting endianness
    UINT32 magic;
    if(!files_read_bytes(fd, (UINT8*)&magic, sizeof(UINT32))) {
        goto read_error;
    }
    printf("TPMS_ATTEST.magic=");
    print_hex_buffer((const UINT8*)&magic, sizeof(UINT32));
    magic = tpm2_util_ntoh_32(magic); // finally, convert endianness

    // check magic
    if(magic != TPM_GENERATED_VALUE) {
        LOG_ERR("%s: Bad magic", filename);
        goto error;
    }

    UINT16 type;
    if(!files_read_bytes(fd, (UINT8*)&type, sizeof(UINT16))) {
        goto read_error;
    }
    printf("TPMS_ATTEST.type=");
    print_hex_buffer((const UINT8*)&type, sizeof(UINT16));
    type = tpm2_util_ntoh_16(type); // finally, convert endianness

    printf("TPMS_ATTEST.qualifiedSigner=");
    if(!print_tpm2b_hex(fd, filename)) {
        goto error;
    }

    printf("TPMS_ATTEST.extraData=");
    if(!print_tpm2b_hex(fd, filename)) {
        goto error;
    }

    if(!print_clock_info(fd, filename, "TPMS_ATTEST")) {
        goto error;
    }

    printf("TPMS_ATTEST.firmwareVersion=");
    print_hex(fd, filename, sizeof(UINT64));

    switch(type) {
    case TPM_ST_ATTEST_QUOTE:
        if(!print_TPMS_QUOTE_INFO(fd, filename, "TPMS_ATTEST.attested.quote")) {
            goto error;
        }
        break;

    default:
        LOG_ERR("%s: Cannot print unsupported type 0x%x", filename, (unsigned int)type);
        goto error;
    }

    // success
    return true;

    read_error:
    FILE_2_SHORT_ERROR(filename);
    error:
    return false;
}

int main(int argc, char *argv[]) {
    const char* object_type = NULL;
    const char* filename = NULL;
    FILE* fd = NULL;

    if(argc == 3) {
        object_type = argv[1];
        filename = argv[2];
    }
    else {
        LOG_ERR("Usage: tpm2_print <object_type> <filename>");
        goto error;
    }

    printf("filename=%s\n", filename);
    fd = fopen(filename, "rb");
    if(!fd) {
        LOG_ERR("%s: Could not open file", filename);
        goto error;
    }

    if(strcmp(object_type, "TPMS_ATTEST") == 0) {
        if(!print_TPMS_ATTEST(fd, filename)) {
            goto error;
        }
    }
    else {
        LOG_ERR("Unsupported object_type %s; only TPMS_ATTEST is presently supported", object_type);
        goto error;
    }

    // print number of bytes read
    printf("ftell=%ld\n", ftell(fd));

    // check EOF by reading one more byte
    UINT8* garbage;
    int fread_result = fread(&garbage, 1, 1, fd);
    UNUSED(fread_result);
    printf("feof=%d\n", (feof(fd) != 0) ? 1 : 0);

    // success
    fclose(fd);
    return 0;

    error:
    if(fd) {
        fclose(fd);
    }
    return 1;
}
