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
    src/debug.c \
    src/syscontext.c
SAMPLE_SRC = \
    src/CatSizedByteBuffer.c \
    src/CopySizedBuffer.c \
    src/DecryptEncrypt.c \
    src/Entity.c \
    src/kdfa.c \
    src/LoadExternalHMACKey.c \
    src/SessionHmac.c \
    src/StartAuthSession.c \
    src/TpmCalcPHash.c \
    src/TpmHandleToName.c \
    src/TpmHash.c \
    src/TpmHmac.c

TPMTOOLS_COMMON_SRC = \
    $(SAMPLE_SRC) \
    $(COMMON_SRC) \
    src/common.c

INCLUDE_DIRS = -I$(srcdir)

AM_CFLAGS   = -DSAPI_CLIENT $(INCLUDE_DIRS)
AM_CXXFLAGS = -DSAPI_CLIENT $(INCLUDE_DIRS)

noinst_PROGRAMS = src/tpm2_listpcrs \
		  src/tpm2_quote \
		  src/tpm2_takeownership \
		  src/tpm2_getpubek \
		  src/tpm2_getpubak \
		  src/tpm2_akparse \
		  src/tpm2_makecredential \
		  src/tpm2_activatecredential \
		  src/tpm2_hash \
		  src/tpm2_nvlist \
		  src/tpm2_nvread \
		  src/tpm2_nvwrite \
		  src/tpm2_nvdefine \
		  src/tpm2_nvrelease \
		  src/tpm2_createprimary \
		  src/tpm2_create \
		  src/tpm2_hmac \
		  src/tpm2_certify \
		  src/tpm2_readpublic \
		  src/tpm2_getrandom \
		  src/tpm2_encryptdecrypt \
		  src/tpm2_evictcontrol \
		  src/tpm2_load \
		  src/tpm2_loadexternal \
		  src/tpm2_rsadecrypt \
		  src/tpm2_rsaencrypt \
		  src/tpm2_sign \
		  src/tpm2_unseal \
		  src/tpm2_verifysignature
LDADD = -ltss2 -ltctisocket
src_tpm2_listpcrs_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_listpcrs.cpp
src_tpm2_quote_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_quote.cpp
src_tpm2_takeownership_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_takeownership.cpp
src_tpm2_getpubek_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_getpubek.cpp
src_tpm2_getpubak_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_getpubak.cpp
src_tpm2_akparse_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_akparse.cpp
src_tpm2_makecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_makecredential.cpp
src_tpm2_activatecredential_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_activatecredential.cpp
src_tpm2_hash_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_hash.cpp
src_tpm2_nvlist_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_nvlist.cpp
src_tpm2_nvread_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_nvread.cpp
src_tpm2_nvwrite_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_nvwrite.cpp
src_tpm2_nvdefine_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_nvdefine.cpp
src_tpm2_nvrelease_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_nvrelease.cpp
src_tpm2_createprimary_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_createprimary.cpp
src_tpm2_create_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_create.cpp
src_tpm2_hmac_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_hmac.cpp
src_tpm2_certify_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_certify.cpp
src_tpm2_readpublic_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_readpublic.cpp
src_tpm2_getrandom_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_getrandom.cpp
src_tpm2_encryptdecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_encryptdecrypt.cpp
src_tpm2_evictcontrol_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_evictcontrol.cpp
src_tpm2_load_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_load.cpp
src_tpm2_loadexternal_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_loadexternal.cpp
src_tpm2_rsadecrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_rsadecrypt.cpp
src_tpm2_rsaencrypt_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_rsaencrypt.cpp
src_tpm2_sign_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_sign.cpp
src_tpm2_unseal_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_unseal.cpp
src_tpm2_verifysignature_SOURCES = $(TPMTOOLS_COMMON_SRC) src/tpm2_verifysignature.cpp
