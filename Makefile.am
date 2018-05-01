#;**********************************************************************;
#
# Copyright (c) 2018, Intel Corporation
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
@CODE_COVERAGE_RULES@

include src_vars.mk

ACLOCAL_AMFLAGS = -I m4

INCLUDE_DIRS = -I$(top_srcdir)/tools -I$(top_srcdir)/lib
LIB_COMMON := lib/libcommon.a

AM_CFLAGS := \
    $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_SYS_CFLAGS) $(CRYPTO_CFLAGS) \
    $(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS   := $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

LDADD = \
    $(LIB_COMMON) $(TSS2_SYS_LIBS) $(CRYPTO_LIBS) -ldl

# keep me sorted
bin_PROGRAMS = \
    tools/aux/tpm2_print \
    tools/aux/tpm2_rc_decode \
    tools/tpm2_activatecredential \
    tools/tpm2_certify \
    tools/tpm2_changeauth \
    tools/tpm2_clear \
    tools/tpm2_clearlock \
    tools/tpm2_create \
    tools/tpm2_createak \
    tools/tpm2_createek \
    tools/tpm2_createpolicy \
    tools/tpm2_createprimary \
    tools/tpm2_dictionarylockout \
    tools/tpm2_getcap \
    tools/tpm2_encryptdecrypt \
    tools/tpm2_evictcontrol \
    tools/tpm2_flushcontext \
    tools/tpm2_getmanufec \
    tools/tpm2_getrandom \
    tools/tpm2_hash \
    tools/tpm2_hmac \
    tools/tpm2_import \
    tools/tpm2_listpersistent \
    tools/tpm2_load \
    tools/tpm2_loadexternal \
    tools/tpm2_makecredential \
    tools/tpm2_nvdefine \
    tools/tpm2_nvlist \
    tools/tpm2_nvread \
    tools/tpm2_nvreadlock \
    tools/tpm2_nvrelease \
    tools/tpm2_nvwrite \
    tools/tpm2_pcrevent \
    tools/tpm2_pcrextend \
    tools/tpm2_pcrlist \
    tools/tpm2_policypcr \
    tools/tpm2_policyrestart \
    tools/tpm2_quote \
    tools/tpm2_readpublic \
    tools/tpm2_rsadecrypt \
    tools/tpm2_rsaencrypt \
    tools/tpm2_send \
    tools/tpm2_sign \
    tools/tpm2_startauthsession \
    tools/tpm2_startup \
    tools/tpm2_unseal \
    tools/tpm2_verifysignature

noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = $(LIB_SRC)
TOOL_SRC := tools/tpm2_tool.c tools/tpm2_tool.h

tools_aux_tpm2_print_SOURCES = tools/aux/tpm2_print.c $(TOOL_SRC)
tools_aux_tpm2_rc_decode_SOURCES = tools/aux/tpm2_rc_decode.c $(TOOL_SRC)

tools_tpm2_clear_SOURCES = tools/tpm2_clear.c $(TOOL_SRC)
tools_tpm2_clearlock_SOURCES = tools/tpm2_clearlock.c $(TOOL_SRC)
tools_tpm2_create_SOURCES = tools/tpm2_create.c $(TOOL_SRC)
tools_tpm2_createprimary_SOURCES = tools/tpm2_createprimary.c $(TOOL_SRC)
tools_tpm2_getcap_SOURCES = tools/tpm2_getcap.c $(TOOL_SRC)
tools_tpm2_pcrlist_SOURCES = tools/tpm2_pcrlist.c $(TOOL_SRC)
tools_tpm2_listpersistent_SOURCES = tools/tpm2_listpersistent.c $(TOOL_SRC)
tools_tpm2_load_SOURCES = tools/tpm2_load.c $(TOOL_SRC)
tools_tpm2_send_SOURCES = tools/tpm2_send.c $(TOOL_SRC)
tools_tpm2_startup_SOURCES = tools/tpm2_startup.c $(TOOL_SRC)
tools_tpm2_verifysignature_SOURCES = tools/tpm2_verifysignature.c $(TOOL_SRC)
tools_tpm2_getmanufec_CFLAG = $(AM_CFLAGS) $(CURL_CFLAGS)
tools_tpm2_getmanufec_LDADD = $(LDADD) $(CURL_LIBS)
tools_tpm2_getmanufec_SOURCES = tools/tpm2_getmanufec.c $(TOOL_SRC)
tools_tpm2_quote_SOURCES = tools/tpm2_quote.c $(TOOL_SRC)
tools_tpm2_changeauth_SOURCES = tools/tpm2_changeauth.c $(TOOL_SRC)
tools_tpm2_createek_SOURCES = tools/tpm2_createek.c $(TOOL_SRC)
tools_tpm2_createak_SOURCES = tools/tpm2_createak.c $(TOOL_SRC)
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
tools_tpm2_import_SOURCES = tools/tpm2_import.c $(TOOL_SRC)
tools_tpm2_flushcontext_SOURCES = tools/tpm2_flushcontext.c $(TOOL_SRC)
tools_tpm2_startauthsession_SOURCES = tools/tpm2_startauthsession.c $(TOOL_SRC)
tools_tpm2_policypcr_SOURCES = tools/tpm2_policypcr.c $(TOOL_SRC)
tools_tpm2_policyrestart_SOURCES = tools/tpm2_policyrestart.c $(TOOL_SRC)

if UNIT
TESTS = $(check_PROGRAMS)
check_PROGRAMS = \
    test/unit/test_string_bytes \
    test/unit/test_files \
    test/unit/test_tpm2_header \
    test/unit/test_tpm2_attr_util \
    test/unit/test_tpm2_alg_util \
    test/unit/test_pcr \
    test/unit/test_tpm2_auth_util \
    test/unit/test_tpm2_errata \
    test/unit/test_tpm2_session \
    test/unit/test_tpm2_policy \
    test/unit/test_tpm2_hierarchy \
    test/unit/test_tpm2_error

TESTS += $(ALL_SYSTEM_TESTS)

test_unit_test_string_bytes_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_string_bytes_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_string_bytes_SOURCES  = test/unit/test_string_bytes.c

test_unit_test_files_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_files_LDADD    = $(LIB_COMMON) $(CMOCKA_LIBS) $(LDADD)
test_unit_test_files_SOURCES  = test/unit/test_files.c

test_unit_test_tpm2_header_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_header_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_header_SOURCES  = test/unit/test_tpm2_header.c

test_unit_test_tpm2_attr_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_attr_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_attr_util_SOURCES  = test/unit/test_tpm2_attr_util.c

test_unit_test_tpm2_alg_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_alg_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_alg_util_SOURCES  = test/unit/test_tpm2_alg_util.c

test_unit_test_pcr_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_pcr_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_pcr_SOURCES  = test/unit/test_pcr.c

test_unit_test_tpm2_auth_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_auth_util_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_auth_util_SOURCES  = test/unit/test_tpm2_auth_util.c

test_unit_test_tpm2_errata_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_errata_LDFLAGS  = -Wl,--wrap=Tss2_Sys_GetCapability
test_unit_test_tpm2_errata_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_errata_SOURCES  = test/unit/test_tpm2_errata.c

test_unit_test_tpm2_session_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_session_LDFLAGS  = -Wl,--wrap=Tss2_Sys_StartAuthSession \
                                       -Wl,--wrap=Tss2_Sys_ContextSave \
                                       -Wl,--wrap=Tss2_Sys_ContextLoad \
                                       -Wl,--wrap=Tss2_Sys_PolicyRestart

test_unit_test_tpm2_session_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_session_SOURCES  = test/unit/test_tpm2_session.c

test_unit_test_tpm2_policy_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_policy_LDFLAGS  = -Wl,--wrap=Tss2_Sys_StartAuthSession \
                                      -Wl,--wrap=Tss2_Sys_PolicyPCR \
                                      -Wl,--wrap=Tss2_Sys_PCR_Read \
                                      -Wl,--wrap=Tss2_Sys_PolicyGetDigest
test_unit_test_tpm2_policy_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_policy_SOURCES  = test/unit/test_tpm2_policy.c

test_unit_test_tpm2_hierarchy_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_hierarchy_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_hierarchy_SOURCES  = test/unit/test_tpm2_hierarchy.c

test_unit_test_tpm2_error_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_error_LDADD    = $(CMOCKA_LIBS) $(LIB_COMMON) $(LDADD)
test_unit_test_tpm2_error_SOURCES  = test/unit/test_tpm2_error.c

#
# We need absolute paths to the builddir and srcdir locations so we can
# find the binaries to test with and the scripts/artifacts needed.
#
# abs_top_dir is defined, but the build dir is not, so create it.
#
abs_build_dir=$(abspath $(builddir))

AM_TESTS_ENVIRONMENT =	\
	TPM2_ABRMD="tpm2-abrmd" \
	TPM2_SIM="tpm_server" \
	PATH=$(abs_build_dir)/tools:$(abs_build_dir)/tools/aux:$(abs_top_srcdir)/test/integration:$(PATH) \
	TPM2_TOOLS_TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures
endif

check-hook:
	rm -rf .lock_file

EXTRA_DIST = $(top_srcdir)/man \
	     AUTHORS.md \
	     CHANGELOG.md \
	     CONTRIBUTING.md \
	     INSTALL.md \
	     LICENSE \
	     MAINTAINERS.md \
	     README.md \
	     RELEASE.md \
	     test/integration

if HAVE_PANDOC
    man1_MANS := \
    man/man1/tpm2_activatecredential.1 \
    man/man1/tpm2_certify.1 \
    man/man1/tpm2_changeauth.1 \
    man/man1/tpm2_clear.1 \
    man/man1/tpm2_clearlock.1 \
    man/man1/tpm2_create.1 \
    man/man1/tpm2_createak.1 \
    man/man1/tpm2_createek.1 \
    man/man1/tpm2_createpolicy.1 \
    man/man1/tpm2_createprimary.1 \
    man/man1/tpm2_dictionarylockout.1 \
    man/man1/tpm2_getcap.1 \
    man/man1/tpm2_encryptdecrypt.1 \
    man/man1/tpm2_evictcontrol.1 \
    man/man1/tpm2_flushcontext.1 \
    man/man1/tpm2_getmanufec.1 \
    man/man1/tpm2_getrandom.1 \
    man/man1/tpm2_hash.1 \
    man/man1/tpm2_hmac.1 \
    man/man1/tpm2_import.1 \
    man/man1/tpm2_listpersistent.1 \
    man/man1/tpm2_load.1 \
    man/man1/tpm2_loadexternal.1 \
    man/man1/tpm2_makecredential.1 \
    man/man1/tpm2_nvdefine.1 \
    man/man1/tpm2_nvlist.1 \
    man/man1/tpm2_nvread.1 \
    man/man1/tpm2_nvreadlock.1 \
    man/man1/tpm2_nvrelease.1 \
    man/man1/tpm2_nvwrite.1 \
    man/man1/tpm2_pcrevent.1 \
    man/man1/tpm2_pcrextend.1 \
    man/man1/tpm2_pcrlist.1 \
    man/man1/tpm2_policypcr.1 \
    man/man1/tpm2_policyrestart.1 \
    man/man1/tpm2_quote.1 \
    man/man1/tpm2_rc_decode.1 \
    man/man1/tpm2_readpublic.1 \
    man/man1/tpm2_rsadecrypt.1 \
    man/man1/tpm2_rsaencrypt.1 \
    man/man1/tpm2_send.1 \
    man/man1/tpm2_sign.1 \
    man/man1/tpm2_startauthsession.1 \
    man/man1/tpm2_startup.1 \
    man/man1/tpm2_unseal.1 \
    man/man1/tpm2_verifysignature.1

# If pandoc is enabled, we want to generate the manpages for the dist tarball
EXTRA_DIST += $(man1_MANS)
else
# If pandoc is not enabled, we want to complain that you need pandoc for make dist,
# so hook the target and complain.
dist-hook:
	@(>&2 echo "You do not have pandoc, a requirement for the distribution of manpages")
	@exit 1
endif

MARKDOWN_COMMON_DEPS = \
	man/common/alg.md \
	man/common/authorizations.md \
	man/common/footer.md \
	man/common/hash.md \
	man/common/obj-attrs.md \
	man/common/object-alg.md \
	man/common/options.md \
	man/common/pubkey.md \
	man/common/sign-alg.md \
	man/common/signature.md \
	man/common/signschemes.md \
	man/common/tcti.md

man/man1/%.1 : man/%.1.md $(MARKDOWN_COMMON_DEPS)
	$(AM_V_GEN)rm -f $@ && \
	mkdir -p man/man1 && \
	sed -e '/\[common options\]/r man/common/options.md' \
	    -e '/\[common options\]/d' \
	    -e '/\[common tcti options\]/r man/common/tcti.md' \
	    -e '/\[common tcti options\]/d' \
	    -e '/\[authorization formatting\]/r man/common/authorizations.md' \
	    -e '/\[authorization formatting\]/d' \
	    -e '/\[supported hash algorithms\]/r man/common/hash.md' \
	    -e '/\[supported hash algorithms\]/d' \
	    -e '/\[algorithm specifiers\]/r man/common/alg.md' \
	    -e '/\[algorithm specifiers\]/d' \
	    -e '/\[supported public object algorithms\]/r man/common/object-alg.md' \
	    -e '/\[supported public object algorithms\]/d' \
	    -e '/\[supported signing algorithms\]/r man/common/sign-alg.md' \
	    -e '/\[supported signing algorithms\]/d' \
	    -e '/\[nv attributes\]/r man/common/nv-attrs.md' \
	    -e '/\[nv attributes\]/d' \
	    -e '/\[pcr bank specifiers\]/r man/common/pcr.md' \
	    -e '/\[pcr bank specifiers\]/d' \
	    -e '/\[pubkey options\]/r man/common/pubkey.md' \
	    -e '/\[pubkey options\]/d' \
	    -e '/\[signature format specifiers\]/r man/common/signature.md' \
	    -e '/\[signature format specifiers\]/d' \
	    -e '/\[object attribute specifiers\]/r man/common/obj-attrs.md' \
	    -e '/\[object attribute specifiers\]/d' \
	    -e '/\[supported signing schemes\]/r man/common/signschemes.md' \
	    -e '/\[supported signing schemes\]/d' \
	    -e '/\[footer\]/r man/common/footer.md' \
	    -e '/\[footer\]/d' \
	    < $< | pandoc -s -t man > $@

CLEANFILES = $(man1_MANS)
