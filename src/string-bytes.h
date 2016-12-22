#ifndef STRING_BYTES_H
#define STRING_BYTES_H

#include <sapi/tpm20.h>

int getSizeUint16(const char *arg, UINT16 *num);
int getSizeUint16Hex(const char *arg, UINT16 *num);
int getSizeUint32(const char *arg, UINT32 *num);
int getSizeUint32Hex(const char *arg, UINT32 *num);
int str2ByteStructure(const char *inStr, UINT16 *byteLenth, BYTE *byteBuffer);
int hex2ByteStructure(const char *inStr, UINT16 *byteLenth, BYTE *byteBuffer);

#endif /* STRING_BYTES_H */
