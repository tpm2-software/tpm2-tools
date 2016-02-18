#;**********************************************************************;
#
# Copyright (c) 2015, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

COMMON_SRC = \
    sapi-tools/debug.c \
    sapi-tools/syscontext.c
SAMPLE_SRC = \
    sapi-tools/CatSizedByteBuffer.c \
    sapi-tools/CopySizedBuffer.c \
    sapi-tools/DecryptEncrypt.c \
    sapi-tools/Entity.c \
    sapi-tools/kdfa.c \
    sapi-tools/LoadExternalHMACKey.c \
    sapi-tools/SessionHmac.c \
    sapi-tools/StartAuthSession.c \
    sapi-tools/TpmCalcPHash.c \
    sapi-tools/TpmHandleToName.c \
    sapi-tools/TpmHash.c \
    sapi-tools/TpmHmac.c

TPMTOOLS_COMMON_SRC = \
    $(SAMPLE_SRC) \
    $(COMMON_SRC) \
    sapi-tools/common.c

INCLUDE_DIRS = -I$(srcdir)

AM_CFLAGS   = -DSAPI_CLIENT $(INCLUDE_DIRS)
AM_CXXFLAGS = -DSAPI_CLIENT $(INCLUDE_DIRS)

noinst_PROGRAMS = sapi-tools/tpm2_listpcrs \
		  sapi-tools/tpm2_quote \
		  sapi-tools/tpm2_takeownership \
		  sapi-tools/tpm2_getpubek \
		  sapi-tools/tpm2_getpubak \
		  sapi-tools/tpm2_akparse \
		  sapi-tools/tpm2_makecredential \
		  sapi-tools/tpm2_activatecredential \
		  sapi-tools/tpm2_hash \
		  sapi-tools/tpm2_nvlist \
		  sapi-tools/tpm2_nvread \
		  sapi-tools/tpm2_nvwrite \
		  sapi-tools/tpm2_nvdefine \
		  sapi-tools/tpm2_nvrelease \
		  sapi-tools/tpm2_createprimary \
		  sapi-tools/tpm2_create \
		  sapi-tools/tpm2_hmac \
		  sapi-tools/tpm2_certify \
		  sapi-tools/tpm2_readpublic \
		  sapi-tools/tpm2_getrandom \
		  sapi-tools/tpm2_encryptdecrypt \
		  sapi-tools/tpm2_evictcontrol \
		  sapi-tools/tpm2_load \
		  sapi-tools/tpm2_loadexternal \
		  sapi-tools/tpm2_rsadecrypt \
		  sapi-tools/tpm2_rsaencrypt \
		  sapi-tools/tpm2_sign \
		  sapi-tools/tpm2_unseal \
		  sapi-tools/tpm2_verifysignature
LDADD = -ltss2 -ltctisocket
sapi_tools_tpm2_listpcrs_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_listpcrs.cpp
sapi_tools_tpm2_quote_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_quote.cpp
sapi_tools_tpm2_takeownership_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_takeownership.cpp
sapi_tools_tpm2_getpubek_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_getpubek.cpp
sapi_tools_tpm2_getpubak_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_getpubak.cpp
sapi_tools_tpm2_akparse_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_akparse.cpp
sapi_tools_tpm2_makecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_makecredential.cpp
sapi_tools_tpm2_activatecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_activatecredential.cpp
sapi_tools_tpm2_hash_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_hash.cpp
sapi_tools_tpm2_nvlist_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_nvlist.cpp
sapi_tools_tpm2_nvread_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_nvread.cpp
sapi_tools_tpm2_nvwrite_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_nvwrite.cpp
sapi_tools_tpm2_nvdefine_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_nvdefine.cpp
sapi_tools_tpm2_nvrelease_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_nvrelease.cpp
sapi_tools_tpm2_createprimary_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_createprimary.cpp
sapi_tools_tpm2_create_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_create.cpp
sapi_tools_tpm2_hmac_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_hmac.cpp
sapi_tools_tpm2_certify_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_certify.cpp
sapi_tools_tpm2_readpublic_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_readpublic.cpp
sapi_tools_tpm2_getrandom_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_getrandom.cpp
sapi_tools_tpm2_encryptdecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_encryptdecrypt.cpp
sapi_tools_tpm2_evictcontrol_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_evictcontrol.cpp
sapi_tools_tpm2_load_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_load.cpp
sapi_tools_tpm2_loadexternal_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_loadexternal.cpp
sapi_tools_tpm2_rsadecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_rsadecrypt.cpp
sapi_tools_tpm2_rsaencrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_rsaencrypt.cpp
sapi_tools_tpm2_sign_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_sign.cpp
sapi_tools_tpm2_unseal_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_unseal.cpp
sapi_tools_tpm2_verifysignature_SOURCES = $(TPMTOOLS_COMMON_SRC) sapi-tools/tpm2_verifysignature.cpp
