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
#ifndef COMMON_H
#define COMMON_H

#include "files.h"
#include "options.h"
#include "pcr.h"
#include "string-bytes.h"

#ifdef __cplusplus
extern "C" {
#endif

extern TSS2_SYS_CONTEXT *sysContext;

void copyData( UINT8 *to, UINT8 *from, UINT32 length );
int CompareTPM2B( TPM2B *buffer1, TPM2B *buffer2 );
void PrintSizedBufferOpen( TPM2B *sizedBuffer );
void PrintSizedBuffer( TPM2B *sizedBuffer );
void ErrorHandler( UINT32 rval );
int prepareTest(const char *hostName, const int port, int debugLevel);
void finishTest();
int computeDataHash(BYTE *buffer, UINT16 length, TPMI_ALG_HASH halg, TPM2B_DIGEST *result);
int getPort(const char *arg, int *port);
int getDebugLevel(const char *arg, int *dl);


#ifdef __cplusplus
}
#endif

#endif // COMMON_H

