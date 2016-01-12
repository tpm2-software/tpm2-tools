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
    debug.c \
    platformcommand.c \
    syscontext.c
SAMPLE_SRC = \
    CatSizedByteBuffer.c \
    CopySizedBuffer.c \
    DecryptEncrypt.c \
    Entity.c \
    kdfa.c \
    LoadExternalHMACKey.c \
    SessionHmac.c \
    StartAuthSession.c \
    TpmCalcPHash.c \
    TpmHandleToName.c \
    TpmHash.c \
    TpmHmac.c

TPMTOOLS_COMMON_SRC = \
    $(SAMPLE_SRC) \
    $(COMMON_SRC) \
    common.cpp

INCLUDE_DIRS = -I$(srcdir)

AM_CFLAGS   = -DSAPI_CLIENT $(INCLUDE_DIRS)
AM_CXXFLAGS = -DSAPI_CLIENT $(INCLUDE_DIRS)

noinst_PROGRAMS = tpm2_listpcrs \
		  tpm2_quote \
		  tpm2_takeownership \
		  tpm2_getpubek \
		  tpm2_getpubak \
		  tpm2_akparse \
		  tpm2_makecredential \
		  tpm2_activatecredential \
		  tpm2_hash \
		  tpm2_nvlist \
		  tpm2_nvread \
		  tpm2_nvwrite \
		  tpm2_nvdefine \
		  tpm2_nvrelease \
		  tpm2_createprimary \
		  tpm2_create \
		  tpm2_hmac \
		  tpm2_certify \
		  tpm2_readpublic \
		  tpm2_getrandom \
		  tpm2_encryptdecrypt \
		  tpm2_evictcontrol \
		  tpm2_load \
		  tpm2_loadexternal \
		  tpm2_rsadecrypt \
		  tpm2_rsaencrypt \
		  tpm2_sign \
		  tpm2_unseal \
		  tpm2_verifysignature
LDADD = -ltpm2sapi -ltpm2tctisock
tpm2_listpcrs_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_listpcrs.cpp
tpm2_quote_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_quote.cpp
tpm2_takeownership_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_takeownership.cpp
tpm2_getpubek_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_getpubek.cpp
tpm2_getpubak_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_getpubak.cpp
tpm2_akparse_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_akparse.cpp
tpm2_makecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_makecredential.cpp
tpm2_activatecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_activatecredential.cpp
tpm2_hash_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_hash.cpp
tpm2_nvlist_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_nvlist.cpp
tpm2_nvread_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_nvread.cpp
tpm2_nvwrite_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_nvwrite.cpp
tpm2_nvdefine_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_nvdefine.cpp
tpm2_nvrelease_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_nvrelease.cpp
tpm2_createprimary_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_createprimary.cpp
tpm2_create_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_create.cpp
tpm2_hmac_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_hmac.cpp
tpm2_certify_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_certify.cpp
tpm2_readpublic_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_readpublic.cpp
tpm2_getrandom_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_getrandom.cpp
tpm2_encryptdecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_encryptdecrypt.cpp
tpm2_evictcontrol_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_evictcontrol.cpp
tpm2_load_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_load.cpp
tpm2_loadexternal_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_loadexternal.cpp
tpm2_rsadecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_rsadecrypt.cpp
tpm2_rsaencrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_rsaencrypt.cpp
tpm2_sign_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_sign.cpp
tpm2_unseal_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_unseal.cpp
tpm2_verifysignature_SOURCES = $(TPMTOOLS_COMMON_SRC) tpm2_verifysignature.cpp
