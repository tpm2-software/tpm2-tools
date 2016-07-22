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

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "common.h"

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
    (pcrSelection).pcrSelect[0] = 0; \
    (pcrSelection).pcrSelect[1] = 0; \
    (pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
    (pcrSelection).sizeofSelect = size;

#define TEST_PCR_SELECT_BIT( pcrSelection, pcr ) \
    ((pcrSelection).pcrSelect[( (pcr)/8 )] & ( 1 << ( (pcr) % 8) ))

int debugLevel = 0;
FILE *fp = NULL;
char outFilePath[PATH_MAX];
const struct {
    TPMI_ALG_HASH alg;
    const char *desc;
} g_algs [] =
{
    {TPM_ALG_SHA1, "TPM_ALG_SHA1"},
    {TPM_ALG_SHA256, "TPM_ALG_SHA256"},
    {TPM_ALG_SHA384, "TPM_ALG_SHA384"},
    {TPM_ALG_SHA512, "TPM_ALG_SHA512"},
    {TPM_ALG_SM3_256, "TPM_ALG_SM3_256"},
    {TPM_ALG_NULL, "TPM_ALG_UNKOWN"}
};

static struct {
    int count;
    TPMI_ALG_HASH alg[8];
} g_banks = {3, {TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,}};

TPML_PCR_SELECTION g_pcrSelections;

static struct {
    int count;
    TPML_DIGEST pcrValues[24];
} g_pcrs = {0,};

int findAlgorithm(TPMI_ALG_HASH algId)
{
    int i;
    for(i = 0; g_algs[i].alg != TPM_ALG_NULL; i++)
        if( g_algs[i].alg == algId )
            break;

    return i;
}

void updatePcrSelections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2)
{
    for(int i2 = 0; i2 < s2->count; i2++)
    {
        for(int i1 = 0; i1 < s1->count; i1++)
        {
            if(s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for(int j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                    ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

bool emptyPcrSections(TPML_PCR_SELECTION *s)
{
    for(int i = 0; i < s->count; i++)
        for(int j = 0; j < s->pcrSelections[i].sizeofSelect; j++)
            if(s->pcrSelections[i].pcrSelect[j])
                return false;

    return true;
}

int readPcrValues()
{
    TPML_PCR_SELECTION pcrSelectionIn;
    TPML_PCR_SELECTION pcrSelectionOut;
    UINT32 pcrUpdateCounter;
    UINT32 rval;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcrSelectionIn, &g_pcrSelections, sizeof(pcrSelectionIn));

    //2. call pcr_read
    g_pcrs.count = 0;
    do
    {
        rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelectionIn,
                                  &pcrUpdateCounter, &pcrSelectionOut,
                                  &g_pcrs.pcrValues[g_pcrs.count], 0 );

        if(rval != TPM_RC_SUCCESS )
        {
            printf("read pcr failed. tpm error 0x%0x\n\n", rval);
            return -1;
        }

    //3. unmask pcrSelectionOut bits from pcrSelectionIn
        updatePcrSelections(&pcrSelectionIn, &pcrSelectionOut);

    //4. goto step 2 if pcrSelctionIn still has bits set
    } while(++g_pcrs.count < 24 && !emptyPcrSections(&pcrSelectionIn));

    if(g_pcrs.count >= 24 && !emptyPcrSections(&pcrSelectionIn))
    {
        printf("too much pcrs to get! try to split into multiple calls...\n\n");
        return -1;
    }

    return 0;
}

int preparePcrSelections_g(TPMI_ALG_HASH algId)
{
    UINT32 pcrId = 0;

    g_pcrSelections.count = 1;
    g_pcrSelections.pcrSelections[0].hash = algId;
    SET_PCR_SELECT_SIZE(g_pcrSelections.pcrSelections[0], 3);
    CLEAR_PCR_SELECT_BITS(g_pcrSelections.pcrSelections[0]);

    for(pcrId = 0; pcrId < 24; pcrId++)
    {
        SET_PCR_SELECT_BIT(g_pcrSelections.pcrSelections[0], pcrId );
    }
}

void preparePcrSelections()
{
    UINT32 pcrId = 0;

    g_pcrSelections.count = 0;
    for( int i = 0; i < g_banks.count; i++ )
    {
        g_pcrSelections.pcrSelections[i].hash = g_banks.alg[i];
        SET_PCR_SELECT_SIZE(g_pcrSelections.pcrSelections[i], 3);
        CLEAR_PCR_SELECT_BITS(g_pcrSelections.pcrSelections[i]);

        for(pcrId = 0; pcrId < 24; pcrId++)
        {
            SET_PCR_SELECT_BIT(g_pcrSelections.pcrSelections[i], pcrId );
        }
        g_pcrSelections.count++;
    }
}

// show all PCR banks according to g_pcrSelection & g_pcrs.
int showPcrValues()
{
    int vi = 0, di = 0;

    for( int i = 0; i < g_pcrSelections.count; i++)
    {
        int alg_i = findAlgorithm(g_pcrSelections.pcrSelections[i].hash);

        printf("\nBank/Algorithm: %s(0x%04x)\n",
               g_algs[alg_i].desc, g_pcrSelections.pcrSelections[i].hash);

        for(UINT32 pcrId = 0; pcrId < 24; pcrId++)
        {
            if(!TEST_PCR_SELECT_BIT(g_pcrSelections.pcrSelections[i], pcrId))
                continue;
            if(vi >= g_pcrs.count || di >= g_pcrs.pcrValues[vi].count)
            {
                printf("Something wrong, trying to print but nothing more\n");
                return -1;
            }

            printf("PCR_%02d:", pcrId);
            for(int k = 0; k < g_pcrs.pcrValues[vi].digests[di].t.size; k++)
                printf(" %02x", g_pcrs.pcrValues[vi].digests[di].t.buffer[k]);
            printf("\n");

            if(fp != NULL &&
               fwrite(g_pcrs.pcrValues[vi].digests[di].t.buffer,
                      g_pcrs.pcrValues[vi].digests[di].t.size, 1, fp) != 1)
            {
                printf("write to file %s failed!\n", outFilePath);
                return -1;
            }

            if(++di < g_pcrs.pcrValues[vi].count)
                continue;

            //printf("returned values[%d] are printed!\n", vi);

            di = 0;
            if(++vi < g_pcrs.count)
                continue;

            //printf("all returned values are printed!\n");
        }
    }

    return 0;
}

int showAllPcrValues()
{
    preparePcrSelections();

    if(readPcrValues())
        return -1;

    if(showPcrValues())
        return -1;

    return 0;
}

int showSelectedPcrValues()
{
    if(readPcrValues())
        return -1;

    if(showPcrValues())
        return -1;

    return 0;
}

int showAlgPcrValues(TPMI_ALG_HASH algId)
{
    preparePcrSelections_g(algId);

    if(readPcrValues())
        return -1;

    if(showPcrValues())
        return -1;

    return 0;
}

int getBanks()
{
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    UINT32 rval;

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_PCRS, 0, 1,
                                   &moreData, &capabilityData, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......GetCapability: Get PCR allocation status Error. TPM Error:0x%x......\n", rval);
        return -1;
    }

    for( int i=0; i < capabilityData.data.assignedPCR.count; i++ )
    {
        g_banks.alg[i] = capabilityData.data.assignedPCR.pcrSelections[i].hash;
    }
    g_banks.count = capabilityData.data.assignedPCR.count;

    return 0;
}

void showBanks()
{
    printf("Supported Bank/Algorithm:");
    for(int i = 0; i < g_banks.count; i++)
    {
        int j = findAlgorithm(g_banks.alg[i]);
        printf(" %s(0x%04x)", g_algs[j].desc, g_banks.alg[i]);
    }
    printf("\n");
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help                Display command tool usage info;\n"
            "-v, --version             Display command tool version info;\n"
            "-g, --algorithim <hexAlg>     The algorithm id, optional\n"
            "-o, --output  <filename>      The file to hold the PCR values in binary format, optional\n"
            "-p, --port    <port number>   The Port number, default is %d, optional\n"
            "-L, --selList <hexAlg1:num1,...,numN+hexAlg2:num2_1,...,num2_M+...>\n"
            "                              The list of pcr banks and selected PCRs' ids\n"
            "                              (0~23) for each bank\n"
            "-s, --algs                    Show the supported algs in the PCR banks\n"
            "-d, --debugLevel <0|1|2|3>    The level of debug message, default is 0, optional\n"
                "\t0 (high level test results)\n"
                "\t1 (test app send/receive byte streams)\n"
                "\t2 (resource manager send/receive byte streams)\n"
                "\t3 (resource manager tables)\n"
            "\n\tExample:\n"
            "display usage:\n"
            "    %s -h\n"
            "display version:\n"
            "    %s -v\n"
            "display all PCR values:\n"
            "    %s\n"
            "display the PCR values with specified bank:\n"
            "    %s -g 0x04\n"
            "display the PCR values with specified banks and store in a file:\n"
            "    %s -L 0x04:16,17,18+0x0b:16,17,18 -o pcrs\n"
            "display the supported algs in the PCR banks:\n"
            "    %s -s\n"
            , name, DEFAULT_RESMGR_TPM_PORT, name, name, name, name, name, name );
}

const char *findChar(const char *str, int len, char c)
{
    if(str == NULL || len <= 0)
        return NULL;

    for(int i = 0; i < len; i++)
    {
        if(str[i] == c)
            return &str[i];
    }

    return NULL;
}

int parsePCRList(const char *str, int len, TPMS_PCR_SELECTION *pcrSel)
{
    char buf[3];
    const char *strCurrent;
    int lenCurrent;
    UINT32 pcr;

    if(str == NULL || len == 0)
        return -1;

    pcrSel->sizeofSelect = 3;
    pcrSel->pcrSelect[0] = 0;
    pcrSel->pcrSelect[1] = 0;
    pcrSel->pcrSelect[2] = 0;

    do
    {
        strCurrent = str;
        str = findChar(strCurrent, len, ',');
        if(str)
        {
            lenCurrent = str - strCurrent;
            str++;
            len -= lenCurrent + 1;
        }
        else
        {
            lenCurrent = len;
            len = 0;
        }

        if(lenCurrent > sizeof(buf) - 1)
            return -1;

        safeStrNCpy(buf, strCurrent, lenCurrent + 1);

        if(getPcrId(buf, &pcr)!= 0)
            return -1;

        pcrSel->pcrSelect[pcr/8] |= (1 << (pcr % 8));
    } while(str);

    return 0;
}

int parsePCRSelection(const char *str, int len, TPMS_PCR_SELECTION *pcrSel)
{
    const char *strLeft;
    char buf[7];

    if(str == NULL || len == 0)
        return -1;

    strLeft = findChar(str, len, ':');

    if(strLeft == NULL)
        return -1;
    if(strLeft - str > sizeof(buf) - 1)
        return -1;

    safeStrNCpy(buf, str, strLeft - str + 1);
    if(getSizeUint16Hex(buf, &pcrSel->hash) != 0)
        return -1;

    strLeft++;

    if(strLeft - str >= len)
        return -1;

    if(parsePCRList(strLeft, str + len - strLeft, pcrSel))
        return -1;

    return 0;
}

int parsePCRSelections(const char *arg, TPML_PCR_SELECTION *pcrSels)
{
    const char *strLeft = arg;
    const char *strCurrent = arg;
    int lenCurrent = 0;

    if(arg == NULL || pcrSels == NULL)
        return -1;

    pcrSels->count = 0;

    do
    {
        strCurrent = strLeft;

        strLeft = findChar(strCurrent, strlen(strCurrent), '+');
        if(strLeft)
        {
            lenCurrent = strLeft - strCurrent;
            strLeft++;
        }
        else
            lenCurrent = strlen(strCurrent);

        if(parsePCRSelection(strCurrent, lenCurrent, &pcrSels->pcrSelections[pcrSels->count]))
            return -1;

        pcrSels->count++;
    } while(strLeft);

    if(pcrSels->count == 0)
        return -1;
    return 0;
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvg:p:d:o:L:s";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"algorithm",1,NULL,'g'},
        {"output",1,NULL,'o'},
        {"algs",0,NULL,'s'},
        {"selList",1,NULL,'L'},
        {"port",1,NULL,'p'},
        {"debugLevel",1,NULL,'d'},
        {0,0,0,0}
    };

    TPMI_ALG_HASH algorithmId;

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        o_flag = 0,
        L_flag = 0,
        s_flag = 0,
        g_flag = 0;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'h':
            h_flag = 1;
            break;
        case 'v':
            v_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&algorithmId) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            g_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -2;
                break;
            }
            o_flag = 1;
            break;
        case 'L':
            if(parsePCRSelections(optarg, &g_pcrSelections) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -10;
                break;
            }
            L_flag = 1;
            break;
        case 's':
            s_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -3;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -4;
            }
            break;
            //          case 0:
            //              break;
        case ':':
            //              printf("Argument %c needs a value!\n",optopt);
            returnVal = -5;
            break;
        case '?':
            //              printf("Unknown Argument: %c\n",optopt);
            returnVal = -6;
            break;
            //default:
            //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + g_flag + L_flag + s_flag;

    if(flagCnt > 1)
    {
        showArgMismatch(argv[0]);
        return -7;
    }

    if(h_flag)
    {
        showHelp(argv[0]);
        return 0;
    }
    else if(v_flag == 1)
    {
        showVersion(argv[0]);
        return 0;
    }

    if(o_flag)
    {
        fp = fopen(outFilePath,"w+");
        if(NULL == fp)
        {
            printf("OutFile: %s Can Not Be Created !\n",outFilePath);
            return -8;
        }
    }

    prepareTest(hostName, port, debugLevel);

    returnVal = getBanks();
    if(returnVal == 0)
    {
        if(s_flag)
            showBanks();
        else if(g_flag)
            returnVal = showAlgPcrValues(algorithmId);
        else if(L_flag)
            returnVal = showSelectedPcrValues();
        else
            returnVal = showAllPcrValues();
    }

    finishTest();

    if(fp)
        fclose(fp);
    if(returnVal)
        return -9;

    return 0;
}
