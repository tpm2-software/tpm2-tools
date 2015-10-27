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
    ../tss/common/debug.c ../tss/common/debug.h \
    ../tss/common/getcommands.c \
    ../tss/common/platformcommand.c ../tss/common/platform.h \
    ../tss/common/syscontext.c ../tss/common/syscontext.h
SAMPLE_SRC = \
    ../tss/test/common/sample/CatSizedByteBuffer.c \
    ../tss/test/common/sample/CopySizedBuffer.c \
    ../tss/test/common/sample/CreateNullSession.c \
    ../tss/test/common/sample/DecryptEncrypt.c \
    ../tss/test/common/sample/Entity.c \
    ../tss/test/common/sample/kdfa.c \
    ../tss/test/common/sample/LoadExternalHMACKey.c \
    ../tss/test/common/sample/sample.h \
    ../tss/test/common/sample/SessionHmac.c \
    ../tss/test/common/sample/SetLocality.c \
    ../tss/test/common/sample/StartAuthSession.c \
    ../tss/test/common/sample/TpmCalcPHash.c \
    ../tss/test/common/sample/TpmHandleToName.c \
    ../tss/test/common/sample/TpmHash.c \
    ../tss/test/common/sample/TpmHmac.c \
    ../tss/test/common/sample/sample.h
TPMSOCKETS_SRC = \
    ../tss/tcti/tpmsockets/tpmsockets.cpp \
    ../tss/tcti/tpmsockets/tpmsockets.h
SYSAPI_SRC = \
    ../tss/sysapi/include/basetypes.h \
    ../tss/sysapi/include/endianConv.h \
    ../tss/sysapi/include/implementation.h \
    ../tss/sysapi/include/tpm20.h \
    ../tss/sysapi/include/tpmb.h \
    ../tss/sysapi/include/tss2_common.h \
    ../tss/sysapi/include/tss2_sys_api_marshalUnmarshal.h \
    ../tss/sysapi/include/tss2_sys_api_part3.h \
    ../tss/sysapi/include/tss2_sysapi_util.h \
    ../tss/sysapi/include/tss2_sys.h \
    ../tss/sysapi/include/tss2_tcti.h \
    ../tss/sysapi/include/tss2_tcti_util.h \
    ../tss/sysapi/include/tss2_tpm2_types.h

TPMTOOLS_COMMON_SRC = \
    ../tss/test/tpmclient/tpmclient.h \
    $(SAMPLE_SRC) \
    $(SYSAPI_SRC) \
    $(COMMON_SRC) \
    $(TPMSOCKETS_SRC) \
    common.cpp common.h

INCLUDE_DIRS = -I$(srcdir)/../tss/sysapi/include -I$(srcdir) \
    -I$(srcdir)/../tss/tcti/tpmsockets -I$(srcdir)/../tss/common \
    -I$(srcdir)/../tss/test/common/sample -I$(srcdir)/../tss/resourcemgr \
    -I$(srcdir)/../tss/test/tpmclient

AM_CFLAGS   = -DSAPI_CLIENT $(INCLUDE_DIRS)
AM_CXXFLAGS = -DSAPI_CLIENT $(INCLUDE_DIRS)

LIBTPM = ../tss/sysapi/libtpm.a

$(LIBTPM):
	$(MAKE) -C ../tss/

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
LDADD = $(LIBTPM)
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
