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

# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

include src_vars.mk

ACLOCAL_AMFLAGS = -I m4 --install

INCLUDE_DIRS = -I$(top_srcdir)/tools -I$(top_srcdir)/lib
LIB_COMMON := lib/libcommon.a

AM_CFLAGS := \
    $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) \
    $(CRYPTO_CFLAGS) $(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS   := $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

LDADD = \
    $(LIB_COMMON) $(TSS2_ESYS_LIBS) $(CRYPTO_LIBS) $(LIBDL_LDFLAGS)

# keep me sorted
bin_PROGRAMS = \
    tools/misc/tpm2_checkquote \
    tools/misc/tpm2_print \
    tools/misc/tpm2_rc_decode \
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
    tools/tpm2_gettestresult \
    tools/tpm2_encryptdecrypt \
    tools/tpm2_evictcontrol \
    tools/tpm2_flushcontext \
    tools/tpm2_getmanufec \
    tools/tpm2_getrandom \
    tools/tpm2_hash \
    tools/tpm2_hmac \
    tools/tpm2_import \
    tools/tpm2_incrementalselftest \
    tools/tpm2_listpersistent \
    tools/tpm2_load \
    tools/tpm2_loadexternal \
    tools/tpm2_makecredential \
    tools/tpm2_nvdefine \
    tools/tpm2_nvincrement \
    tools/tpm2_nvlist \
    tools/tpm2_nvread \
    tools/tpm2_nvreadlock \
    tools/tpm2_nvrelease \
    tools/tpm2_nvwrite \
    tools/tpm2_pcrallocate \
    tools/tpm2_pcrevent \
    tools/tpm2_pcrextend \
    tools/tpm2_pcrlist \
    tools/tpm2_pcrreset \
    tools/tpm2_policypcr \
    tools/tpm2_policyauthorize \
    tools/tpm2_policyor \
    tools/tpm2_policypassword \
    tools/tpm2_policysecret \
    tools/tpm2_policyrestart \
    tools/tpm2_policycommandcode \
    tools/tpm2_policyduplicationselect \
    tools/tpm2_policylocality \
    tools/tpm2_quote \
    tools/tpm2_readpublic \
    tools/tpm2_rsadecrypt \
    tools/tpm2_rsaencrypt \
    tools/tpm2_send \
    tools/tpm2_selftest \
    tools/tpm2_sign \
    tools/tpm2_startauthsession \
    tools/tpm2_startup \
    tools/tpm2_stirrandom \
    tools/tpm2_testparms \
    tools/tpm2_unseal \
    tools/tpm2_verifysignature


noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = $(LIB_SRC)
lib_libcommon_a_CFLAGS = -fPIC $(AM_CFLAGS)

tools_tpm2_getmanufec_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS)
tools_tpm2_getmanufec_LDADD = $(LDADD) $(CURL_LIBS)

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
    test/unit/test_tpm2_error \
    test/unit/test_tpm2_util

TESTS += $(ALL_SYSTEM_TESTS)

test_unit_test_string_bytes_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_string_bytes_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_files_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_files_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_header_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_header_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_attr_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_attr_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_alg_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_alg_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_pcr_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_pcr_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_auth_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_auth_util_LDFLAGS  = -Wl,--wrap=Esys_TR_SetAuth \
                                         -Wl,--wrap=Esys_StartAuthSession
test_unit_test_tpm2_auth_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_errata_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_errata_LDFLAGS  = -Wl,--wrap=Esys_GetCapability
test_unit_test_tpm2_errata_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_session_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_session_LDFLAGS  = -Wl,--wrap=Esys_StartAuthSession \
                                       -Wl,--wrap=Esys_ContextSave \
                                       -Wl,--wrap=Esys_ContextLoad \
                                       -Wl,--wrap=Esys_PolicyRestart \
                                       -Wl,--wrap=Esys_TR_GetName

test_unit_test_tpm2_session_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_policy_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_policy_LDFLAGS  = -Wl,--wrap=Esys_StartAuthSession \
                                      -Wl,--wrap=Esys_PolicyPCR \
                                      -Wl,--wrap=Esys_PCR_Read \
                                      -Wl,--wrap=Esys_PolicyGetDigest
test_unit_test_tpm2_policy_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_hierarchy_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_hierarchy_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_error_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_error_LDADD    = $(CMOCKA_LIBS) $(LDADD)
test_unit_test_tpm2_util_CFLAGS	   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_util_LDADD     = $(CMOCKA_LIBS) $(LDADD)

#
# We need absolute paths to the builddir and srcdir locations so we can
# find the binaries to test with and the scripts/artifacts needed.
#
# abs_top_dir is defined, but the build dir is not, so create it.
#
abs_build_dir=$(abspath $(builddir))

AM_TESTS_ENVIRONMENT =	\
	TPM2_ABRMD=tpm2-abrmd; export TPM2_ABRMD; \
	TPM2_SIM=tpm_server; export TPM2_SIM; \
	PATH=$(abs_build_dir)/tools:$(abs_build_dir)/tools/misc:$(abs_top_srcdir)/test/integration:$(PATH); \
	TPM2_TOOLS_TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures; \
	export TPM2_TOOLS_TEST_FIXTURES;

SH_LOG_COMPILER = dbus-run-session
AM_SH_LOG_FLAGS = --
endif

TEST_EXTENSIONS = .sh

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
if HAVE_MAN_PAGES
    dist_man1_MANS := \
    man/man1/tpm2_activatecredential.1 \
    man/man1/tpm2_certify.1 \
    man/man1/tpm2_changeauth.1 \
    man/man1/tpm2_checkquote.1 \
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
    man/man1/tpm2_gettestresult.1 \
    man/man1/tpm2_hash.1 \
    man/man1/tpm2_hmac.1 \
    man/man1/tpm2_import.1 \
    man/man1/tpm2_incrementalselftest.1 \
    man/man1/tpm2_listpersistent.1 \
    man/man1/tpm2_load.1 \
    man/man1/tpm2_loadexternal.1 \
    man/man1/tpm2_makecredential.1 \
    man/man1/tpm2_nvdefine.1 \
    man/man1/tpm2_nvincrement.1 \
    man/man1/tpm2_nvlist.1 \
    man/man1/tpm2_nvread.1 \
    man/man1/tpm2_nvreadlock.1 \
    man/man1/tpm2_nvrelease.1 \
    man/man1/tpm2_nvwrite.1 \
    man/man1/tpm2_pcrallocate.1 \
    man/man1/tpm2_pcrevent.1 \
    man/man1/tpm2_pcrextend.1 \
    man/man1/tpm2_pcrlist.1 \
    man/man1/tpm2_pcrreset.1 \
    man/man1/tpm2_policypcr.1 \
    man/man1/tpm2_policyrestart.1 \
    man/man1/tpm2_policycommandcode.1 \
    man/man1/tpm2_policyduplicationselect.1 \
    man/man1/tpm2_policylocality.1 \
    man/man1/tpm2_policyauthorize.1 \
    man/man1/tpm2_policyor.1 \
    man/man1/tpm2_policypassword.1 \
    man/man1/tpm2_policysecret.1 \
    man/man1/tpm2_quote.1 \
    man/man1/tpm2_rc_decode.1 \
    man/man1/tpm2_readpublic.1 \
    man/man1/tpm2_rsadecrypt.1 \
    man/man1/tpm2_rsaencrypt.1 \
    man/man1/tpm2_send.1 \
    man/man1/tpm2_selftest.1 \
    man/man1/tpm2_sign.1 \
    man/man1/tpm2_startauthsession.1 \
    man/man1/tpm2_startup.1 \
    man/man1/tpm2_stirrandom.1 \
    man/man1/tpm2_testparms.1 \
    man/man1/tpm2_unseal.1 \
    man/man1/tpm2_verifysignature.1
endif

if !HAVE_PANDOC
# If pandoc is not enabled, we want to complain that you need pandoc for make dist,
# so hook the target and complain.
dist-hook:
	@(>&2 echo "You do not have pandoc, a requirement for the distribution of manpages")
	@exit 1
endif

MARKDOWN_COMMON_DEPS = \
	man/common/alg.md \
	man/common/authorizations.md \
	man/common/ctxobj.md \
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
	    -e '/\[context object format\]/r man/common/ctxobj.md' \
	    -e '/\[context object format\]/d' \
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

CLEANFILES = $(dist_man1_MANS)

bashcompdir=@bashcompdir@
dist_bashcomp_DATA=dist/bash-completion/tpm2-tools/tpm2_completion.bash

install-data-hook:
	cd $(DESTDIR)$(bashcompdir) && \
	for tool in $(bin_PROGRAMS); do \
		$(LN_S) -f tpm2_completion.bash $${tool##*/}; \
	done

uninstall-hook:
	cd $(DESTDIR)$(bashcompdir) && \
	for tool in $(bin_PROGRAMS); do \
		[ -L $${tool##*/} ] && rm -f $${tool##*/}; \
	done
