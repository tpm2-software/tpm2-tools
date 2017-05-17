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

INCLUDE_DIRS = -I$(srcdir)/src -I$(srcdir)/lib
LIB_COMMON := lib/libcommon.a

AM_CFLAGS    := $(INCLUDE_DIRS) $(TPM20_TSS_CFLAGS) $(EXTRA_CFLAGS) $(TCTI_TABRMD_CFLAGS)
AM_LDFLAGS   := $(EXTRA_LDFLAGS)

LDADD = $(LIB_COMMON) $(TPM20_TSS_LIBS) $(TCTI_SOCK_LIBS) $(TCTI_DEV_LIBS) $(TCTI_TABRMD_LIBS)

sbin_PROGRAMS = \
    tools/tpm2_create \
    tools/tpm2_createprimary \
    tools/tpm2_load \
    tools/tpm2_send_command \
    tools/tpm2_dump_capability \
    tools/tpm2_listpcrs \
    tools/tpm2_listpersistent \
    tools/tpm2_startup \
    tools/tpm2_rc_decode \
    tools/tpm2_verifysignature \
    tools/tpm2_getmanufec \
    tools/tpm2_quote \
    tools/tpm2_takeownership \
    tools/tpm2_getpubek \
    tools/tpm2_getpubak \
    tools/tpm2_akparse \
    tools/tpm2_hash \
    tools/tpm2_activatecredential \
    tools/tpm2_makecredential \
    tools/tpm2_nvlist \
    tools/tpm2_nvread \
    tools/tpm2_nvreadlock \
    tools/tpm2_nvwrite \
    tools/tpm2_nvdefine \
    tools/tpm2_nvrelease \
    tools/tpm2_hmac \
    tools/tpm2_certify \
    tools/tpm2_readpublic \
    tools/tpm2_getrandom \
    tools/tpm2_encryptdecrypt \
    tools/tpm2_evictcontrol \
    tools/tpm2_loadexternal \
    tools/tpm2_rsadecrypt \
    tools/tpm2_rsaencrypt \
    tools/tpm2_sign \
    tools/tpm2_unseal \
    tools/tpm2_dictionarylockout \
    tools/tpm2_createpolicy

noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = \
    lib/context-util.c \
    lib/files.c \
    lib/log.c \
    lib/options.c \
    lib/password_util.c \
    lib/pcr.c \
    lib/rc-decode.c \
    lib/string-bytes.c \
    lib/tpm2-header.c \
    lib/tpm_hash.c \
    lib/tpm_hmac.c \
    lib/tpm_kdfa.c \
    lib/tpm_session.c

tools_tpm2_create_SOURCES = tools/tpm2_create.c tools/main.c
tools_tpm2_createprimary_SOURCES = tools/tpm2_createprimary.c tools/main.c
tools_tpm2_dump_capability_SOURCES = tools/tpm2_dump_capability.c tools/main.c
tools_tpm2_listpcrs_SOURCES = tools/tpm2_listpcrs.c tools/main.c
tools_tpm2_listpersistent_SOURCES = tools/tpm2_listpersistent.c tools/main.c
tools_tpm2_load_SOURCES = tools/tpm2_load.c tools/main.c
tools_tpm2_send_command_SOURCES = tools/tpm2_send_command.c tools/main.c
tools_tpm2_startup_SOURCES = tools/tpm2_startup.c tools/main.c
tools_tpm2_verifysignature_SOURCES = tools/tpm2_verifysignature.c tools/main.c
tools_tpm2_getmanufec_CFLAG = $(AM_CFLAGS) $(CURL_CFLAGS)
tools_tpm2_getmanufec_LDADD = $(LDADD) $(CURL_LIBS)
tools_tpm2_getmanufec_SOURCES = tools/tpm2_getmanufec.c tools/main.c
tools_tpm2_quote_SOURCES = tools/tpm2_quote.c tools/main.c
tools_tpm2_takeownership_SOURCES = tools/tpm2_takeownership.c tools/main.c
tools_tpm2_getpubek_SOURCES = tools/tpm2_getpubek.c tools/main.c
tools_tpm2_getpubak_SOURCES = tools/tpm2_getpubak.c tools/main.c
tools_tpm2_akparse_SOURCES = tools/tpm2_akparse.c tools/main.c
tools_tpm2_hash_SOURCES = tools/tpm2_hash.c tools/main.c
tools_tpm2_activatecredential_SOURCES = tools/tpm2_activatecredential.c tools/main.c
tools_tpm2_makecredential_SOURCES = tools/tpm2_makecredential.c tools/main.c
tools_tpm2_nvlist_SOURCES = tools/tpm2_nvlist.c tools/main.c
tools_tpm2_nvread_SOURCES = tools/tpm2_nvread.c tools/main.c
tools_tpm2_nvreadlock_SOURCES = tools/tpm2_nvreadlock.c tools/main.c
tools_tpm2_nvwrite_SOURCES = tools/tpm2_nvwrite.c tools/main.c
tools_tpm2_nvdefine_SOURCES = tools/tpm2_nvdefine.c tools/main.c
tools_tpm2_nvrelease_SOURCES = tools/tpm2_nvrelease.c tools/main.c
tools_tpm2_hmac_SOURCES = tools/tpm2_hmac.c tools/main.c
tools_tpm2_certify_SOURCES = tools/tpm2_certify.c tools/main.c
tools_tpm2_readpublic_SOURCES = tools/tpm2_readpublic.c tools/main.c
tools_tpm2_getrandom_SOURCES = tools/tpm2_getrandom.c tools/main.c
tools_tpm2_encryptdecrypt_SOURCES = tools/tpm2_encryptdecrypt.c tools/main.c
tools_tpm2_evictcontrol_SOURCES = tools/tpm2_evictcontrol.c tools/main.c
tools_tpm2_loadexternal_SOURCES = tools/tpm2_loadexternal.c tools/main.c
tools_tpm2_rsadecrypt_SOURCES = tools/tpm2_rsadecrypt.c tools/main.c
tools_tpm2_rsaencrypt_SOURCES = tools/tpm2_rsaencrypt.c tools/main.c
tools_tpm2_sign_SOURCES = tools/tpm2_sign.c tools/main.c
tools_tpm2_unseal_SOURCES = tools/tpm2_unseal.c tools/main.c
tools_tpm2_dictionarylockout_SOURCES = tools/tpm2_dictionarylockout.c tools/main.c
tools_tpm2_createpolicy_SOURCES = tools/tpm2_createpolicy.c tools/main.c

# rc_decode does not use common main, since it does not need a dynamic TCTI.
tools_tpm2_rc_decode_SOURCES = lib/rc-decode.c tools/tpm2_rc_decode.c

if UNIT
TESTS = $(check_PROGRAMS)
check_PROGRAMS = \
    test/unit/tpm2-rc-decode_unit \
    test/unit/tpm2-rc-entry_unit \
    test/unit/test_string_bytes \
    test/unit/test_files

test_unit_tpm2_rc_decode_unit_CFLAGS  = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_tpm2_rc_decode_unit_LDADD   = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_tpm2_rc_decode_unit_SOURCES = test/unit/tpm2-rc-decode_unit.c

test_unit_tpm2_rc_entry_unit_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_tpm2_rc_entry_unit_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_tpm2_rc_entry_unit_SOURCES  = test/unit/tpm2-rc-entry_unit.c

test_unit_test_string_bytes_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_string_bytes_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_string_bytes_SOURCES  = test/unit/test_string_bytes.c

test_unit_test_files_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_files_LDADD    = $(LIB_COMMON) $(CMOCKA_LIBS) $(TPM20_TSS_LIBS) \
	$(TCTI_SOCK_LIBS) $(TCTI_DEV_LIBS)
test_unit_test_files_SOURCES  = test/unit/test_files.c

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
    man/man8/tpm2_rc_decode.8 \
    man/man8/tpm2_dictionarylockout.8 \
    man/man8/tpm2_createpolicy.8

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

CLEANFILES = $(man8_MANS)
