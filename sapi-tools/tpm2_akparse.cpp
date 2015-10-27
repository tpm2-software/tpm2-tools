//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#ifdef _WIN32
#include "stdafx.h"
#else
#include <stdarg.h>
#endif

#ifndef UNICODE
#define UNICODE 1
#endif

#ifdef _WIN32
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define sprintf_s   snprintf
#define sscanf_s    sscanf
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include "tpm20.h"
#include "tpmsockets.h"
#include "common.h"

char akDataFile[PATH_MAX];
char akKeyFile[PATH_MAX];

#if 1
void PrintSizedBuffer( TPM2B *sizedBuffer  )
{
    int i;

    for( i = 0; i < sizedBuffer->size; i++  )
    {
        printf( "%2.2x ", sizedBuffer->buffer[i] );

        if( ( (i+1) % 16  ) == 0  )
        {
            printf( "\n" );

        }

    }
    printf( "\n" );
}
#endif

void SaveWithBigEndian(FILE *file, const UINT16 &data)
{
    BYTE tmp = (const BYTE)((data & 0xFF00) >> 8);
    fwrite(&tmp, sizeof(BYTE), 1, file);

    tmp = (const BYTE)(data & 0x00FF);
    fwrite(&tmp, sizeof(BYTE), 1, file);
}

// CPU is little endian, so bytes need to be swapped in order to use bt java.
template <typename T>
int SaveKeyToFile(const char keyfile[], UINT16 algType, const T &t)
{
    FILE *f;
    UINT32 count;
    if( (f = fopen(keyfile, "wb+")) == NULL )
    {
        printf("file(%s) open error.\n", keyfile);
        return -1;
    }
    printf("file(%s) open success.\n ", keyfile);

    SaveWithBigEndian(f, algType);
    SaveWithBigEndian(f, t.size);
//    fwrite(&algType, sizeof(UINT16), 1, f);// or we can use ChangeEndianWord() to swap the byte.
//    fwrite(&t.size, sizeof(UINT16), 1, f);

    if( ( count = fwrite(&t.buffer[0], sizeof(BYTE), t.size, f) ) != t.size )
    {
        printf("write key file error\n");
        fclose(f);
        return -2;
    }
    fclose(f);
    f = NULL;

    printf("write data count: %d, %s: \n", count, keyfile);
    PrintSizedBuffer((TPM2B *)&t);

    return 0;
}

int SaveEccKeyToFile(const char keyfile[], UINT16 algType, const TPMS_ECC_POINT &ecc)
{
    FILE *f;
    UINT16 count, size;

    if( (f = fopen(keyfile, "wb+")) == NULL )
    {
        printf("file(%s) open error.\n", keyfile);
        return -1;
    }
    printf("file(%s) open success.\n ", keyfile);

//    fwrite(&algType, sizeof(UINT16), 1, f);
    SaveWithBigEndian(f, algType);

    size = ecc.x.t.size;
//    fwrite(&size, sizeof(UINT16), 1, f);
    SaveWithBigEndian(f, size);

    if( ( count = fwrite(&ecc.x.t.buffer[0], sizeof(BYTE), size, f) ) != size )
    {
        printf("write X coordinate to file error\n");
        fclose(f);
        return -2;
    }
    printf("write X coordinate count: %d, X coordinate: \n", count);
    PrintSizedBuffer((TPM2B *)&ecc.x);

    size = ecc.y.t.size;
//    fwrite(&size, sizeof(UINT16), 1, f);
    SaveWithBigEndian(f, size);

    if( ( count = fwrite(&ecc.y.t.buffer[0], sizeof(BYTE), size, f) ) != size )
    {
        printf("write Y coordinate to file error\n");
        fclose(f);
        return -3;
    }
    printf("write Y coordinate count: %d, Y coordinate: \n", count);
    PrintSizedBuffer((TPM2B *)&ecc.y);

    fclose(f);
    f = NULL;

    return 0;
}

int parseAKPublicArea()
{
    TPM2B_PUBLIC outPublic;
    UINT16 size = sizeof(outPublic);
    if( loadDataFromFile(akDataFile, (UINT8 *)&outPublic, &size) )
    {
        return -1;
    }

    if( TPM_ALG_RSA == outPublic.t.publicArea.type )
    {
        if(SaveKeyToFile(akKeyFile, TPM_ALG_RSA, outPublic.t.publicArea.unique.rsa.t))
            return -2;
    }
    else if( TPM_ALG_ECC == outPublic.t.publicArea.type )
    {
        if(SaveEccKeyToFile(akKeyFile, TPM_ALG_ECC, outPublic.t.publicArea.unique.ecc))
            return -3;
    }
    else if( TPM_ALG_KEYEDHASH == outPublic.t.publicArea.type )
    {
        if(SaveKeyToFile(akKeyFile, TPM_ALG_KEYEDHASH, outPublic.t.publicArea.unique.keyedHash.t))
            return -4;
    }
    else if( TPM_ALG_SYMCIPHER == outPublic.t.publicArea.type )
    {
        if(SaveKeyToFile(akKeyFile, TPM_ALG_SYMCIPHER, outPublic.t.publicArea.unique.sym.t))
            return -5;
    }
    else
    {
        printf("\nThe algorithm type(0x%4.4x) is not supported\n", outPublic.t.publicArea.type);
        return -6;
    }

    return 0;
}

void showHelp(const char *name)
{
    showVersion(name);
    printf("\nUsed to parse the algorithm and key values in TPM2B_PUBLIC struct\n"
           "Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s [-f inputFile][-k akKeyFile]\n"
           "  -h\tDisplay command tool usage info.\n"
           "  -v\tDisplay command tool version info.\n"
           "  -f\tSpecifies the file used to be parsed.\n"
           "  -k\tSpecifies the file used to save ak key.\n"
           "\nFor Example:\n"
           "  %s -f ./ak.data -k ./ak.key\n"
           , name, name, name, name);
}

int main(int argc, char *argv[])
{
    int opt;
    int rval = 0;

    struct option sOpts[] =
    {
        { "file"     , required_argument, NULL, 'f' },
        { "keyFile"  , required_argument, NULL, 'k' },
        { "help"     , no_argument,       NULL, 'h' },
        { "version"  , no_argument,       NULL, 'v' },
        { NULL       , no_argument,       NULL,  0  },
    };

    if(argc <= 1)
    {
        showHelp(argv[0]);
        return -1;
    }

    if( argc > (int)(2*sizeof(sOpts)/sizeof(struct option)) )
    {
        showArgMismatch(argv[0]);
        return -2;
    }

    while ( ( opt = getopt_long( argc, argv, "f:k:hv", sOpts, NULL ) ) != -1 )
    {
        switch ( opt ) {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;

        case 'f':
            if( optarg == NULL )
            {
                printf("\nPlease input the file that used to be parsed.\n");
                return -3;
            }
            safeStrNCpy( &akDataFile[0], optarg, sizeof(akDataFile) );
            break;

        case 'k':
            if( optarg == NULL )
            {
                printf("\nPlease input the file that used to save ak key.\n");
                return -4;
            }
            safeStrNCpy( &akKeyFile[0], optarg, sizeof(akKeyFile) );
            break;

        default:
            showHelp(argv[0]);
            return -5;
        }
    }

    rval = parseAKPublicArea();

    return rval ? -6 : 0;
}

