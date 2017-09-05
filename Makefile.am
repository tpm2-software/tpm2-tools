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

INCLUDE_DIRS = -I$(top_srcdir)/src -I$(top_srcdir)/lib -I$(top_srcdir)/lib/tcti
LIB_COMMON := lib/libcommon.a

AM_CFLAGS := \
    $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(SAPI_CFLAGS) $(TCTI_SOCK_CFLAGS) \
    $(TCTI_TABRMD_CFLAGS) $(TCTI_DEV_CFLAGS) $(CRYPTO_CFLAGS)

AM_LDFLAGS   := $(EXTRA_LDFLAGS)

LDADD = \
    $(LIB_COMMON) $(SAPI_LIBS) $(TCTI_SOCK_LIBS) $(TCTI_TABRMD_LIBS) \
    $(TCTI_DEV_LIBS) $(CRYPTO_LIBS)

# keep me sorted
bin_PROGRAMS = \
    tools/tpm2_activatecredential \
    tools/tpm2_akparse \
    tools/tpm2_hash \
    tools/tpm2_certify \
    tools/tpm2_create \
    tools/tpm2_createpolicy \
    tools/tpm2_createprimary \
    tools/tpm2_dictionarylockout \
    tools/tpm2_dump_capability \
    tools/tpm2_encryptdecrypt

# NEED TO PORT
#    tools/tpm2_evictcontrol \
#    tools/tpm2_getmanufec \
#    tools/tpm2_getpubak \
#    tools/tpm2_getpubek \
#    tools/tpm2_getrandom \
#    tools/tpm2_hash \
#    tools/tpm2_hmac \
#    tools/tpm2_listpersistent \
#    tools/tpm2_load \
#    tools/tpm2_loadexternal \
#    tools/tpm2_makecredential \
#    tools/tpm2_nvdefine \
#    tools/tpm2_nvlist \
#    tools/tpm2_nvread \
#    tools/tpm2_nvreadlock \
#    tools/tpm2_nvrelease \
#    tools/tpm2_nvwrite \
#    tools/tpm2_pcrevent \
#    tools/tpm2_pcrextend \
#    tools/tpm2_pcrlist \
#    tools/tpm2_quote \
#    tools/tpm2_rc_decode \
#    tools/tpm2_readpublic \
#    tools/tpm2_rsadecrypt \
#    tools/tpm2_rsaencrypt \
#    tools/tpm2_send_command \
#    tools/tpm2_sign \
#    tools/tpm2_startup \
#    tools/tpm2_takeownership \
#    tools/tpm2_unseal \
#    tools/tpm2_verifysignature

tcti_src = ""
if HAVE_TCTI_DEV
tcti_src += lib/tcti/tpm2_tools_tcti_device.c
endif
if HAVE_TCTI_SOCK
tcti_src += lib/tcti/tpm2_tools_tcti_socket.c
endif
if HAVE_TCTI_TABRMD
tcti_src += lib/tcti/tpm2_tools_tcti_abrmd.c
endif


noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = \
	$(tcti_src) \
    lib/files.c \
    lib/files.h \
    lib/log.c \
    lib/log.h \
    lib/pcr.c \
    lib/pcr.h \
    lib/rc-decode.c \
    lib/rc-decode.h \
    lib/tpm2_alg_util.c \
    lib/tpm2_alg_util.h \
    lib/tpm2_header.h \
    lib/tpm2_nv_util.c \
    lib/tpm2_nv_util.h \
    lib/tpm2_password_util.c \
    lib/tpm2_password_util.h \
    lib/tpm2_policy.c \
    lib/tpm2_policy.h \
    lib/tpm2_util.c \
    lib/tpm2_util.h \
    lib/tpm_hash.c \
    lib/tpm_hash.h \
    lib/tpm_hmac.c \
    lib/tpm_hmac.h \
    lib/tpm_kdfa.c \
    lib/tpm_kdfa.h \
    lib/tpm2_options.c \
    lib/tpm2_options.h \
    lib/tpm_session.c \
    lib/tpm_session.h

TOOL_SRC := tools/tpm2_tool.c tools/tool.h

tools_tpm2_create_SOURCES = tools/tpm2_create.c $(TOOL_SRC)
tools_tpm2_createprimary_SOURCES = tools/tpm2_createprimary.c $(TOOL_SRC)
tools_tpm2_dump_capability_SOURCES = tools/tpm2_dump_capability.c $(TOOL_SRC)
tools_tpm2_pcrlist_SOURCES = tools/tpm2_pcrlist.c $(TOOL_SRC)
tools_tpm2_listpersistent_SOURCES = tools/tpm2_listpersistent.c $(TOOL_SRC)
tools_tpm2_load_SOURCES = tools/tpm2_load.c $(TOOL_SRC)
tools_tpm2_send_command_SOURCES = tools/tpm2_send_command.c $(TOOL_SRC)
tools_tpm2_startup_SOURCES = tools/tpm2_startup.c $(TOOL_SRC)
tools_tpm2_verifysignature_SOURCES = tools/tpm2_verifysignature.c $(TOOL_SRC)
tools_tpm2_getmanufec_CFLAG = $(AM_CFLAGS) $(CURL_CFLAGS)
tools_tpm2_getmanufec_LDADD = $(LDADD) $(CURL_LIBS)
tools_tpm2_getmanufec_SOURCES = tools/tpm2_getmanufec.c $(TOOL_SRC)
tools_tpm2_quote_SOURCES = tools/tpm2_quote.c $(TOOL_SRC)
tools_tpm2_takeownership_SOURCES = tools/tpm2_takeownership.c $(TOOL_SRC)
tools_tpm2_getpubek_SOURCES = tools/tpm2_getpubek.c $(TOOL_SRC)
tools_tpm2_getpubak_SOURCES = tools/tpm2_getpubak.c $(TOOL_SRC)
tools_tpm2_akparse_SOURCES = tools/tpm2_akparse.c $(TOOL_SRC)
tools_tpm2_hash_SOURCES = tools/tpm2_hash.c $(TOOL_SRC)
tools_tpm2_activatecredential_SOURCES = tools/tpm2_activatecredential.c $(TOOL_SRC)
tools_tpm2_makecredential_SOURCES = tools/tpm2_makecredential.c $(TOOL_SRC)
tools_tpm2_nvlist_SOURCES = tools/tpm2_nvlist.c $(TOOL_SRC)
tools_tpm2_nvread_SOURCES = tools/tpm2_nvread.c $(TOOL_SRC)
tools_tpm2_nvreadlock_SOURCES = tools/tpm2_nvreadlock.c $(TOOL_SRC)
tools_tpm2_nvwrite_SOURCES = tools/tpm2_nvwrite.c $(TOOL_SRC)
tools_tpm2_nvdefine_SOURCES = tools/tpm2_nvdefine.c $(TOOL_SRC)
tools_tpm2_nvrelease_SOURCES = tools/tpm2_nvrelease.c $(TOOL_SRC)
tools_tpm2_hmac_SOURCES = tools/tpm2_hmac.c $(TOOL_SRC)
tools_tpm2_certify_SOURCES = tools/tpm2_certify.c $(TOOL_SRC)
tools_tpm2_readpublic_SOURCES = tools/tpm2_readpublic.c $(TOOL_SRC)
tools_tpm2_getrandom_SOURCES = tools/tpm2_getrandom.c $(TOOL_SRC)
tools_tpm2_encryptdecrypt_SOURCES = tools/tpm2_encryptdecrypt.c $(TOOL_SRC)
tools_tpm2_evictcontrol_SOURCES = tools/tpm2_evictcontrol.c $(TOOL_SRC)
tools_tpm2_loadexternal_SOURCES = tools/tpm2_loadexternal.c $(TOOL_SRC)
tools_tpm2_rsadecrypt_SOURCES = tools/tpm2_rsadecrypt.c $(TOOL_SRC)
tools_tpm2_rsaencrypt_SOURCES = tools/tpm2_rsaencrypt.c $(TOOL_SRC)
tools_tpm2_sign_SOURCES = tools/tpm2_sign.c $(TOOL_SRC)
tools_tpm2_unseal_SOURCES = tools/tpm2_unseal.c $(TOOL_SRC)
tools_tpm2_dictionarylockout_SOURCES = tools/tpm2_dictionarylockout.c $(TOOL_SRC)
tools_tpm2_createpolicy_SOURCES = tools/tpm2_createpolicy.c $(TOOL_SRC)
tools_tpm2_pcrextend_SOURCES = tools/tpm2_pcrextend.c $(TOOL_SRC)
tools_tpm2_pcrevent_SOURCES = tools/tpm2_pcrevent.c $(TOOL_SRC)

# rc_decode does not use common main, since it does not need a dynamic TCTI.
tools_tpm2_rc_decode_SOURCES = lib/rc-decode.c tools/tpm2_rc_decode.c

if UNIT
TESTS = $(check_PROGRAMS)
check_PROGRAMS = \
    test/unit/tpm2-rc-decode_unit \
    test/unit/tpm2-rc-entry_unit \
    test/unit/test_string_bytes \
    test/unit/test_files \
    test/unit/test_tpm2_header \
    test/unit/test_tpm2_nv_util \
    test/unit/test_tpm2_alg_util \
    test/unit/test_pcr \
    test/unit/test_tpm2_password_util

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
test_unit_test_files_LDADD    = $(LIB_COMMON) $(CMOCKA_LIBS) $(TCTI_SOCK_LIBS) \
                                $(TCTI_DEV_LIBS)
test_unit_test_files_SOURCES  = test/unit/test_files.c

test_unit_test_tpm2_header_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_header_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_tpm2_header_SOURCES  = test/unit/test_tpm2_header.c

test_unit_test_tpm2_nv_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_nv_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_tpm2_nv_util_SOURCES  = test/unit/test_tpm2_nv_util.c

test_unit_test_tpm2_alg_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_alg_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_tpm2_alg_util_SOURCES  = test/unit/test_tpm2_alg_util.c

test_unit_test_pcr_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_pcr_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_pcr_SOURCES  = test/unit/test_pcr.c

test_unit_test_tpm2_password_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_password_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON)
test_unit_test_tpm2_password_util_SOURCES  = test/unit/test_tpm2_password_util.c

endif

EXTRA_DIST = $(top_srcdir)/man

man8_MANS = \
    man/man8/tpm2_createprimary.8 \
    man/man8/tpm2_dump_capability.8 \
    man/man8/tpm2_send_command.8 \
    man/man8/tpm2_startup.8 \
    man/man8/tpm2_pcrlist.8 \
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
    man/man8/tpm2_createpolicy.8 \
    man/man8/tpm2_pcrextend.8 \
    man/man8/tpm2_pcrevent.8

MAN_DEPS := man/common-options.troff man/tcti-options.troff \
           man/tcti-environment.troff man/alg-common.troff \
           man/hash-alg-common.troff man/object-alg-common.troff \
           man/sign-alg-common.troff man/password-fmt-common.troff \
           man/alg-notes-common.troff

# DEPRECATED - No more raw troff files for manpages, use markdown (below).
man/man8/%.8 : man/%.8.in $(MAN_DEPS)
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
	    -e '/@ALG_COMMON_INCLUDE@/r man/alg-common.troff' \
	    -e '/@ALG_COMMON_INCLUDE@/d' \
	    -e '/@HASH_ALG_COMMON_INCLUDE@/r man/hash-alg-common.troff' \
	    -e '/@HASH_ALG_COMMON_INCLUDE@/d' \
	    -e '/@OBJECT_ALG_COMMON_INCLUDE@/r man/object-alg-common.troff' \
	    -e '/@OBJECT_ALG_COMMON_INCLUDE@/d' \
	    -e '/@SIGN_ALG_COMMON_INCLUDE@/r man/sign-alg-common.troff' \
	    -e '/@SIGN_ALG_COMMON_INCLUDE@/d' \
	    -e '/@PASSWORD_FORMAT_COMMON_INCLUDE@/r man/password-fmt-common.troff' \
	    -e '/@PASSWORD_FORMAT_COMMON_INCLUDE@/d' \
	    -e '/@ALG_NOTES_COMMON_INCLUDE@/r man/alg-notes-common.troff' \
	    -e '/@ALG_NOTES_COMMON_INCLUDE@/d' \
	    < $< >> $@

MARKDOWN_COMMON_DEPS = \
	man/common/options.md \
	man/common/tcti.md

man/man8/%.8 : man/%.8.md $(MARKDOWN_COMMON_DEPS)
	rm -f $@
	mkdir -p man/man8
	sed -e '/@COMMON_OPTIONS@/r man/common/options.md' \
	    -e '/@COMMON_OPTIONS@/d' \
	    -e '/@COMMON_TCTI@/r man/common/tcti.md' \
	    -e '/@COMMON_TCTI@/d' \
	    < $< | md2man-roff > $@

CLEANFILES = $(man8_MANS)
