#include "string-bytes.h"

#include <stdio.h>

int getSizeUint16Hex(const char *arg, UINT16 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    snprintf(tmpArg, sizeof(tmpArg), "%s", arg);
    tmpSize = strtol(tmpArg,&errPtr,16);
    if(strlen(errPtr) != 0)
        return -2;
    if( tmpSize > 0xffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint16(const char *arg, UINT16 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    snprintf(tmpArg, sizeof(tmpArg), "%s", arg);
    tmpSize = strtol(tmpArg,&errPtr,10);
    if(strlen(errPtr) != 0)
        return -2;
    if( tmpSize > 0xffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint32Hex(const char *arg, UINT32 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    snprintf(tmpArg, sizeof(tmpArg), "%s", arg);
    tmpSize = strtoll(tmpArg,&errPtr,16);
    if(strlen(errPtr) != 0)
        return -2;
    if(tmpSize > 0xffffffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint32(const char *arg, UINT32 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    snprintf(tmpArg, sizeof(tmpArg), "%s", arg);
    tmpSize = strtol(tmpArg,&errPtr,10);
    if(strlen(errPtr) != 0)
        return -2;
    if(tmpSize > 0xffffffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
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
