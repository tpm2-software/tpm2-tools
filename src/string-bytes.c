#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "string-bytes.h"
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
        char tmpStr[3] = {0};
        tmpStr[0] = inStr[i*2];
        tmpStr[1] = inStr[i*2+1];
        byteBuffer[i] = strtol(tmpStr, NULL, 16);
    }
    return 0;
}
