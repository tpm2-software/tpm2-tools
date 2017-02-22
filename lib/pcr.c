#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "pcr.h"
#include "string-bytes.h"

static int pcr_get_id(const char *arg, UINT32 *pcrId)
{
    UINT32 n = 0;

    if(arg == NULL || pcrId == NULL)
        return -1;

    if(getSizeUint32(arg, &n))
        return -2;

    if(n > 23)
        return -3;

    *pcrId = n;

    return 0;
}

static int pcr_parse_selection(const char *str, int len, TPMS_PCR_SELECTION *pcrSel) {
    const char *strLeft;
    char buf[7];

    if (str == NULL || len == 0)
        return -1;

    strLeft = memchr(str, ':', len);

    if (strLeft == NULL) {
        return -1;
    }

    if (strLeft - str > sizeof(buf) - 1) {
        return -1;
    }

    snprintf(buf, strLeft - str + 1, "%s", str);

    if (getSizeUint16Hex(buf, &pcrSel->hash) != 0) {
        return -1;
    }

    strLeft++;

    if (strLeft - str >= len) {
        return -1;
    }

    if (pcr_parse_list(strLeft, str + len - strLeft, pcrSel)) {
        return -1;
    }

    return 0;
}


int pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels) {
    const char *strLeft = arg;
    const char *strCurrent = arg;
    int lenCurrent = 0;

    if (arg == NULL || pcrSels == NULL) {
        return -1;
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

        if (pcr_parse_selection(strCurrent, lenCurrent,
                &pcrSels->pcrSelections[pcrSels->count]))
            return -1;

        pcrSels->count++;
    } while (strLeft);

    if (pcrSels->count == 0) {
        return -1;
    }
    return 0;
}

int pcr_parse_list(const char *str, int len, TPMS_PCR_SELECTION *pcrSel) {
    char buf[3];
    const char *strCurrent;
    int lenCurrent;
    UINT32 pcr;

    if (str == NULL || len == 0) {
        return -1;
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

        if (lenCurrent > sizeof(buf) - 1) {
            return -1;
        }

        snprintf(buf, lenCurrent + 1, "%s", strCurrent);

        if (pcr_get_id(buf, &pcr) != 0) {
            return -1;
        }

        pcrSel->pcrSelect[pcr / 8] |= (1 << (pcr % 8));
    } while (str);

    return 0;
}
