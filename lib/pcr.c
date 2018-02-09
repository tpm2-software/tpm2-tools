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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>
#include <stdbool.h>

#include "pcr.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"

static int pcr_get_id(const char *arg, UINT32 *pcrId)
{
    UINT32 n = 0;

    if(arg == NULL || pcrId == NULL)
        return -1;

    if(!tpm2_util_string_to_uint32(arg, &n))
        return -2;

    if(n > 23)
        return -3;

    *pcrId = n;

    return 0;
}

static bool pcr_parse_selection(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel) {
    const char *strLeft;
    char buf[7];

    if (str == NULL || len == 0 || strlen(str) == 0)
        return false;

    strLeft = memchr(str, ':', len);

    if (strLeft == NULL) {
        return false;
    }

    if ((size_t)(strLeft - str) > sizeof(buf) - 1) {
        return false;
    }

    snprintf(buf, strLeft - str + 1, "%s", str);

    pcrSel->hash = tpm2_alg_util_from_optarg(buf);

    if (pcrSel->hash == TPM2_ALG_ERROR) {
        return false;
    }

    strLeft++;

    if ((size_t)(strLeft - str) >= len) {
        return false;
    }

    if (!pcr_parse_list(strLeft, str + len - strLeft, pcrSel)) {
        return false;
    }

    return true;
}


bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels) {
    const char *strLeft = arg;
    const char *strCurrent = arg;
    int lenCurrent = 0;

    if (arg == NULL || pcrSels == NULL) {
        return false;
    }

    pcrSels->count = 0;

    do {
        strCurrent = strLeft;

        strLeft = strchr(strCurrent, '+');
        if (strLeft) {
            lenCurrent = strLeft - strCurrent;
            strLeft++;
        } else
            lenCurrent = strlen(strCurrent);

        if (!pcr_parse_selection(strCurrent, lenCurrent,
                &pcrSels->pcrSelections[pcrSels->count]))
            return false;

        pcrSels->count++;
    } while (strLeft);

    if (pcrSels->count == 0) {
        return false;
    }
    return true;
}

bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel) {
    char buf[4];
    const char *strCurrent;
    int lenCurrent;
    UINT32 pcr;

    if (str == NULL || len == 0 || strlen(str) == 0) {
        return false;
    }

    pcrSel->sizeofSelect = 3;
    pcrSel->pcrSelect[0] = 0;
    pcrSel->pcrSelect[1] = 0;
    pcrSel->pcrSelect[2] = 0;

    do {
        strCurrent = str;
        str = memchr(strCurrent, ',', len);
        if (str) {
            lenCurrent = str - strCurrent;
            str++;
            len -= lenCurrent + 1;
        } else {
            lenCurrent = len;
            len = 0;
        }

        if ((size_t)lenCurrent > sizeof(buf) - 1) {
            return false;
        }

        snprintf(buf, lenCurrent + 1, "%s", strCurrent);

        if (pcr_get_id(buf, &pcr) != 0) {
            return false;
        }

        pcrSel->pcrSelect[pcr / 8] |= (1 << (pcr % 8));
    } while (str);

    return true;
}
