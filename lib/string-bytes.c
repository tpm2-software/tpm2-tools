#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "string-bytes.h"

bool string_bytes_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append) {

    if (!result || !append) {
        return false;
    }

    if ((result->t.size + append->size) < result->t.size) {
        return false;
    }

    if ((result->t.size + append->size) > MAX_DIGEST_BUFFER) {
        return false;
    }

    memcpy(&result->t.buffer[result->t.size], append->buffer, append->size);
    result->t.size += append->size;

    return true;
}

bool string_bytes_get_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = string_bytes_get_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t)tmp;
    return true;
}

bool string_bytes_get_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    uint32_t tmp = strtoul(str, &endptr, 0);
    if (errno) {
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

    *value = tmp;
    return true;
}

int str2ByteStructure(const char *inStr, UINT16 *byteLength, BYTE *byteBuffer)
{
    if(inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    if(*byteLength <= strlen(inStr))
        return -2;

    *byteLength = strlen(inStr);
    memcpy(byteBuffer, inStr, *byteLength);
    byteBuffer[*byteLength] = '\0';
    return 0;
}

int hex2ByteStructure(const char *inStr, UINT16 *byteLength, BYTE *byteBuffer)
{
    int strLength;//if the inStr likes "1a2b...", no prefix "0x"
    int i = 0;
    if(inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    strLength = strlen(inStr);
    if(strLength%2)
        return -2;
    for(i = 0; i < strLength; i++)
    {
        if(!isxdigit(inStr[i]))
            return -3;
    }

    if(*byteLength < strLength/2)
        return -4;

    *byteLength = strLength/2;

    for(i = 0; i < *byteLength; i++)
    {
        char tmpStr[4] = {0};
        tmpStr[0] = inStr[i*2];
        tmpStr[1] = inStr[i*2+1];
        byteBuffer[i] = strtol(tmpStr, NULL, 16);
    }
    return 0;
}

void string_bytes_print_tpm2b(TPM2B *buffer) {

    unsigned i;
    for (i = 0; i < buffer->size; i++) {
        printf("%2.2x ", buffer->buffer[i]);

        if (((i + 1) % 16) == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

/* TODO OPTIMIZE ME */
UINT16 string_bytes_copy_tpm2b(TPM2B *dest, TPM2B *src) {
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

bool string_bytes_is_host_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size string_bytes_endian_convert_##size(UINT##size data) { \
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
    UINT##size string_bytes_endian_hton_##size(UINT##size data) { \
    \
        bool is_big_endian = string_bytes_is_host_big_endian(); \
        if (is_big_endian) { \
           return data; \
        } \
    \
        return string_bytes_endian_convert_##size(data); \
    }

STRING_BYTES_ENDIAN_HTON(16)
STRING_BYTES_ENDIAN_HTON(32)
STRING_BYTES_ENDIAN_HTON(64)

/*
 * Converting from host-to-network (hton) or network-to-host (ntoh) is
 * the same operation: if endianess differes between host and data, swap
 * endiness. This we can just call the hton routines, but have some nice
 * names for folks.
 */

UINT16 string_bytes_endian_ntoh_16(UINT16 data) {
    return string_bytes_endian_hton_16(data);
}

UINT32 string_bytes_endian_ntoh_32(UINT32 data) {
    return string_bytes_endian_hton_32(data);
}

UINT64 string_bytes_endian_ntoh_64(UINT64 data) {
    return string_bytes_endian_hton_64(data);
}
