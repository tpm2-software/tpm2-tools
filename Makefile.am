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

ACLOCAL_AMFLAGS = -I m4

INCLUDE_DIRS = -I$(srcdir)/src

AM_CFLAGS   = -DSAPI_CLIENT $(INCLUDE_DIRS) $(TPM20_TSS_CFLAGS)
CLEANFILES  = $(man8_MANS)
LDADD = src/libcommon.a $(TPM20_TSS_LIBS) $(TCTI_SOCK_LIBS) $(TCTI_DEV_LIBS)
TESTS = $(check_PROGRAMS)

noinst_LIBRARIES = src/libcommon.a
sbin_PROGRAMS = \
    src/tpm2_create \
    src/tpm2_createprimary \
    src/tpm2_load \
    src/tpm2_send_command \
    src/tpm2_dump_capability \
    src/tpm2_listpcrs \
    src/tpm2_listpersistent \
    src/tpm2_startup \
    src/tpm2_rc_decode \
    src/tpm2_verifysignature \
    src/tpm2_getmanufec \
    src/tpm2_quote \
    src/tpm2_takeownership \
    src/tpm2_getpubek

COMMON_SRC = \
    src/context-util.c \
    src/files.c \
    src/log.c \
    src/options.c \
    src/pcr.c \
    src/string-bytes.c \
    src/tpm2-header.c \
    src/tpm_hash.c

# The tools within this conditional are hard coded to the socket TCTI.
# As they're migrated to support dynamic TCTI configuration they should be
# removed from this block and added directly to the sbin_PROGRAMS variable
# above.
if HAVE_TCTI_SOCK
sbin_PROGRAMS += \
		  src/tpm2_getpubak \
		  src/tpm2_akparse \
		  src/tpm2_makecredential \
		  src/tpm2_activatecredential \
		  src/tpm2_hash \
		  src/tpm2_nvlist \
		  src/tpm2_nvread \
		  src/tpm2_nvreadlock \
		  src/tpm2_nvwrite \
		  src/tpm2_nvdefine \
		  src/tpm2_nvrelease \
		  src/tpm2_hmac \
		  src/tpm2_certify \
		  src/tpm2_readpublic \
		  src/tpm2_getrandom \
		  src/tpm2_encryptdecrypt \
		  src/tpm2_evictcontrol \
		  src/tpm2_loadexternal \
		  src/tpm2_rsadecrypt \
		  src/tpm2_rsaencrypt \
		  src/tpm2_sign \
		  src/tpm2_unseal

COMMON_SRC += \
    src/common.c \
    src/syscontext.c \
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

endif

man8_MANS = \
    man/man8/tpm2_createprimary.8 \
    man/man8/tpm2_dump_capability.8 \
    man/man8/tpm2_send_command.8 \
    man/man8/tpm2_startup.8 \
    man/man8/tpm2_listpcrs.8 \
    man/man8/tpm2_quote.8 \
    man/man8/tpm2_takeownership.8 \
    man/man8/tpm2_getpubek.8 \
    man/man8/tpm2_getpubak.8 \
    man/man8/tpm2_getmanufec.8 \
    man/man8/tpm2_akparse.8 \
    man/man8/tpm2_makecredential.8 \
    man/man8/tpm2_activatecredential.8 \
    man/man8/tpm2_hash.8 \
    man/man8/tpm2_nvlist.8 \
    man/man8/tpm2_nvread.8 \
    man/man8/tpm2_nvreadlock.8 \
    man/man8/tpm2_nvwrite.8 \
    man/man8/tpm2_nvdefine.8 \
    man/man8/tpm2_nvrelease.8 \
    man/man8/tpm2_create.8 \
    man/man8/tpm2_hmac.8 \
    man/man8/tpm2_certify.8 \
    man/man8/tpm2_readpublic.8 \
    man/man8/tpm2_getrandom.8 \
    man/man8/tpm2_encryptdecrypt.8 \
    man/man8/tpm2_evictcontrol.8 \
    man/man8/tpm2_load.8 \
    man/man8/tpm2_loadexternal.8 \
    man/man8/tpm2_rsadecrypt.8 \
    man/man8/tpm2_rsaencrypt.8 \
    man/man8/tpm2_sign.8 \
    man/man8/tpm2_unseal.8 \
    man/man8/tpm2_verifysignature.8 \
    man/man8/tpm2_listpersistent.8 \
    man/man8/tpm2_rc_decode.8

src_libcommon_a_SOURCES = $(COMMON_SRC)
if HAVE_TCTI_SOCK
src_tpm2_getpubak_SOURCES = src/tpm2_getpubak.c
src_tpm2_akparse_SOURCES = src/tpm2_akparse.c
src_tpm2_makecredential_SOURCES = src/tpm2_makecredential.c
src_tpm2_activatecredential_SOURCES = src/tpm2_activatecredential.c
src_tpm2_hash_SOURCES = src/tpm2_hash.c
src_tpm2_nvlist_SOURCES = src/tpm2_nvlist.c
src_tpm2_nvread_SOURCES = src/tpm2_nvread.c
src_tpm2_nvreadlock_SOURCES = src/tpm2_nvreadlock.c
src_tpm2_nvwrite_SOURCES = src/tpm2_nvwrite.c
src_tpm2_nvdefine_SOURCES = src/tpm2_nvdefine.c
src_tpm2_nvrelease_SOURCES = src/tpm2_nvrelease.c
src_tpm2_hmac_SOURCES = src/tpm2_hmac.c
src_tpm2_certify_SOURCES = src/tpm2_certify.c
src_tpm2_readpublic_SOURCES = src/tpm2_readpublic.c
src_tpm2_getrandom_SOURCES = src/tpm2_getrandom.c
src_tpm2_encryptdecrypt_SOURCES = src/tpm2_encryptdecrypt.c
src_tpm2_evictcontrol_SOURCES = src/tpm2_evictcontrol.c
src_tpm2_loadexternal_SOURCES = src/tpm2_loadexternal.c
src_tpm2_rsadecrypt_SOURCES = src/tpm2_rsadecrypt.c
src_tpm2_rsaencrypt_SOURCES = src/tpm2_rsaencrypt.c
src_tpm2_sign_SOURCES = src/tpm2_sign.c
src_tpm2_unseal_SOURCES = src/tpm2_unseal.c
endif
src_tpm2_create_SOURCES = src/tpm2_create.c src/main.c
src_tpm2_createprimary_SOURCES = src/tpm2_createprimary.c src/main.c
src_tpm2_dump_capability_SOURCES = src/tpm2_dump_capability.c src/main.c
src_tpm2_listpcrs_SOURCES = src/tpm2_listpcrs.c src/main.c
src_tpm2_listpersistent_SOURCES = src/tpm2_listpersistent.c src/main.c
src_tpm2_load_SOURCES = src/tpm2_load.c src/main.c
src_tpm2_send_command_SOURCES = src/tpm2_send_command.c src/main.c
src_tpm2_startup_SOURCES = src/tpm2_startup.c src/main.c
src_tpm2_verifysignature_SOURCES = src/tpm2_verifysignature.c src/main.c
src_tpm2_getmanufec_CFLAG = $(AM_CFLAGS) $(CURL_CFLAGS)
src_tpm2_getmanufec_LDADD = $(LDADD) $(CURL_LIBS)
src_tpm2_getmanufec_SOURCES = src/tpm2_getmanufec.c src/main.c
src_tpm2_quote_SOURCES = src/tpm2_quote.c src/main.c
src_tpm2_takeownership_SOURCES = src/tpm2_takeownership.c src/main.c
src_tpm2_getpubek_SOURCES = src/tpm2_getpubek.c src/main.c

# rc_decode does not use common main, since it does not need a dynamic TCTI.
src_tpm2_rc_decode_SOURCES = src/rc-decode.c src/tpm2_rc_decode.c

if UNIT
test_unit_tpm2_rc_decode_unit_CFLAGS  = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_tpm2_rc_decode_unit_LDADD   = $(CMOCKA_LIBS)
test_unit_tpm2_rc_decode_unit_SOURCES = test/unit/tpm2-rc-decode_unit.c

test_unit_tpm2_rc_entry_unit_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_tpm2_rc_entry_unit_LDADD    = $(CMOCKA_LIBS)
test_unit_tpm2_rc_entry_unit_SOURCES  = src/rc-decode.c test/unit/tpm2-rc-entry_unit.c

check_PROGRAMS = \
    test/unit/tpm2-rc-decode_unit \
    test/unit/tpm2-rc-entry_unit
endif

man/man8/%.8 : man/%.8.in man/tcti-options.troff man/tcti-environment.troff
	rm -f $@
	mkdir -p man/man8
if HAVE_TCTI_DEV
	echo ".nr HAVE_TCTI_DEV 1" >> $@
endif
if HAVE_TCTI_SOCK
	echo ".nr HAVE_TCTI_SOCK 1" >> $@
endif
	sed -e '/@COMMON_OPTIONS_INCLUDE@/r man/common-options.troff' \
	    -e '/@COMMON_OPTIONS_INCLUDE@/d' \
	    -e '/@TCTI_OPTIONS_INCLUDE@/r man/tcti-options.troff' \
	    -e '/@TCTI_OPTIONS_INCLUDE@/d' \
	    -e '/@TCTI_ENVIRONMENT_INCLUDE@/r man/tcti-environment.troff' \
	    -e '/@TCTI_ENVIRONMENT_INCLUDE@/d' \
	    < $< >> $@
