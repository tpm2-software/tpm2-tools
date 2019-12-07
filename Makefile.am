# SPDX-License-Identifier: BSD-3-Clause

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
    $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) $(TSS2_MU_CFLAGS) \
    $(CRYPTO_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(TSS2_TCTILDR_CFLAGS) \
    $(TSS2_RC_CFLAGS)

AM_LDFLAGS   := $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

LDADD = \
    $(LIB_COMMON) $(TSS2_ESYS_LIBS) $(TSS2_MU_LIBS) $(CRYPTO_LIBS) $(TSS2_TCTILDR_LIBS) \
    $(TSS2_RC_LIBS)

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bashcompdir='$$(datarootdir)/bash-completion/completions'

# keep me sorted
bin_PROGRAMS = \
    tools/misc/tpm2_checkquote \
    tools/misc/tpm2_print \
    tools/misc/tpm2_rc_decode \
    tools/tpm2_activatecredential \
    tools/tpm2_certify \
    tools/tpm2_changeauth \
    tools/tpm2_changeeps \
    tools/tpm2_changepps \
    tools/tpm2_clear \
    tools/tpm2_clearcontrol \
    tools/tpm2_clockrateadjust \
    tools/tpm2_create \
    tools/tpm2_createak \
    tools/tpm2_createek \
    tools/tpm2_createpolicy \
    tools/tpm2_setprimarypolicy \
    tools/tpm2_createprimary \
    tools/tpm2_dictionarylockout \
    tools/tpm2_duplicate \
    tools/tpm2_getcap \
    tools/tpm2_gettestresult \
    tools/tpm2_encryptdecrypt \
    tools/tpm2_evictcontrol \
    tools/tpm2_flushcontext \
    tools/tpm2_getekcertificate \
    tools/tpm2_getrandom \
    tools/tpm2_gettime \
    tools/tpm2_hash \
    tools/tpm2_hierarchycontrol \
    tools/tpm2_hmac \
    tools/tpm2_import \
    tools/tpm2_incrementalselftest \
    tools/tpm2_load \
    tools/tpm2_loadexternal \
    tools/tpm2_makecredential \
    tools/tpm2_nvdefine \
    tools/tpm2_nvextend \
    tools/tpm2_nvincrement \
    tools/tpm2_nvreadpublic \
    tools/tpm2_nvread \
    tools/tpm2_nvreadlock \
    tools/tpm2_nvundefine \
    tools/tpm2_nvwrite \
    tools/tpm2_nvwritelock \
    tools/tpm2_nvsetbits \
    tools/tpm2_pcrallocate \
    tools/tpm2_pcrevent \
    tools/tpm2_pcrextend \
    tools/tpm2_pcrread \
    tools/tpm2_pcrreset \
    tools/tpm2_policypcr \
    tools/tpm2_policyauthorize \
    tools/tpm2_policyauthorizenv \
    tools/tpm2_policynv \
    tools/tpm2_policycountertimer \
    tools/tpm2_policyor \
    tools/tpm2_policynamehash \
    tools/tpm2_policytemplate \
    tools/tpm2_policypassword \
    tools/tpm2_policysigned \
    tools/tpm2_policyticket \
    tools/tpm2_policyauthvalue \
    tools/tpm2_policysecret \
    tools/tpm2_policyrestart \
    tools/tpm2_policycommandcode \
    tools/tpm2_policynvwritten \
    tools/tpm2_policyduplicationselect \
    tools/tpm2_policylocality \
    tools/tpm2_quote \
    tools/tpm2_readclock \
    tools/tpm2_readpublic \
    tools/tpm2_rsadecrypt \
    tools/tpm2_rsaencrypt \
    tools/tpm2_send \
    tools/tpm2_selftest \
    tools/tpm2_setclock \
    tools/tpm2_shutdown \
    tools/tpm2_sign \
    tools/tpm2_certifycreation \
    tools/tpm2_nvcertify \
    tools/tpm2_startauthsession \
    tools/tpm2_startup \
    tools/tpm2_stirrandom \
    tools/tpm2_testparms \
    tools/tpm2_unseal \
    tools/tpm2_verifysignature


noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = $(LIB_SRC)
lib_libcommon_a_CFLAGS = -fPIC $(AM_CFLAGS)
TOOL_SRC := tools/tpm2_tool.c tools/tpm2_tool.h

tools_misc_tpm2_checkquote_SOURCES = tools/misc/tpm2_checkquote.c $(TOOL_SRC)
tools_misc_tpm2_print_SOURCES = tools/misc/tpm2_print.c $(TOOL_SRC)
tools_misc_tpm2_rc_decode_SOURCES = tools/misc/tpm2_rc_decode.c $(TOOL_SRC)

tools_tpm2_clear_SOURCES = tools/tpm2_clear.c $(TOOL_SRC)
tools_tpm2_clearcontrol_SOURCES = tools/tpm2_clearcontrol.c $(TOOL_SRC)
tools_tpm2_create_SOURCES = tools/tpm2_create.c $(TOOL_SRC)
tools_tpm2_createprimary_SOURCES = tools/tpm2_createprimary.c $(TOOL_SRC)
tools_tpm2_getcap_SOURCES = tools/tpm2_getcap.c $(TOOL_SRC)
tools_tpm2_pcrread_SOURCES = tools/tpm2_pcrread.c $(TOOL_SRC)
tools_tpm2_load_SOURCES = tools/tpm2_load.c $(TOOL_SRC)
tools_tpm2_send_SOURCES = tools/tpm2_send.c $(TOOL_SRC)
tools_tpm2_startup_SOURCES = tools/tpm2_startup.c $(TOOL_SRC)
tools_tpm2_verifysignature_SOURCES = tools/tpm2_verifysignature.c $(TOOL_SRC)
tools_tpm2_getekcertificate_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS)
tools_tpm2_getekcertificate_LDADD = $(LDADD) $(CURL_LIBS)
tools_tpm2_getekcertificate_SOURCES = tools/tpm2_getekcertificate.c $(TOOL_SRC)
tools_tpm2_quote_SOURCES = tools/tpm2_quote.c $(TOOL_SRC)
tools_tpm2_changeauth_SOURCES = tools/tpm2_changeauth.c $(TOOL_SRC)
tools_tpm2_changeeps_SOURCES = tools/tpm2_changeeps.c $(TOOL_SRC)
tools_tpm2_changepps_SOURCES = tools/tpm2_changepps.c $(TOOL_SRC)
tools_tpm2_createek_SOURCES = tools/tpm2_createek.c $(TOOL_SRC)
tools_tpm2_createak_SOURCES = tools/tpm2_createak.c $(TOOL_SRC)
tools_tpm2_hash_SOURCES = tools/tpm2_hash.c $(TOOL_SRC)
tools_tpm2_activatecredential_SOURCES = tools/tpm2_activatecredential.c $(TOOL_SRC)
tools_tpm2_makecredential_SOURCES = tools/tpm2_makecredential.c $(TOOL_SRC)
tools_tpm2_nvreadpublic_SOURCES = tools/tpm2_nvreadpublic.c $(TOOL_SRC)
tools_tpm2_nvread_SOURCES = tools/tpm2_nvread.c $(TOOL_SRC)
tools_tpm2_nvreadlock_SOURCES = tools/tpm2_nvreadlock.c $(TOOL_SRC)
tools_tpm2_nvwrite_SOURCES = tools/tpm2_nvwrite.c $(TOOL_SRC)
tools_tpm2_nvdefine_SOURCES = tools/tpm2_nvdefine.c $(TOOL_SRC)
tools_tpm2_nvincrement_SOURCES = tools/tpm2_nvincrement.c $(TOOL_SRC)
tools_tpm2_nvundefine_SOURCES = tools/tpm2_nvundefine.c $(TOOL_SRC)
tools_tpm2_hmac_SOURCES = tools/tpm2_hmac.c $(TOOL_SRC)
tools_tpm2_certify_SOURCES = tools/tpm2_certify.c $(TOOL_SRC)
tools_tpm2_readpublic_SOURCES = tools/tpm2_readpublic.c $(TOOL_SRC)
tools_tpm2_getrandom_SOURCES = tools/tpm2_getrandom.c $(TOOL_SRC)
tools_tpm2_encryptdecrypt_SOURCES = tools/tpm2_encryptdecrypt.c $(TOOL_SRC)
tools_tpm2_evictcontrol_SOURCES = tools/tpm2_evictcontrol.c $(TOOL_SRC)
tools_tpm2_loadexternal_SOURCES = tools/tpm2_loadexternal.c $(TOOL_SRC)
tools_tpm2_rsadecrypt_SOURCES = tools/tpm2_rsadecrypt.c $(TOOL_SRC)
tools_tpm2_rsaencrypt_SOURCES = tools/tpm2_rsaencrypt.c $(TOOL_SRC)
tools_tpm2_selftest_SOURCES = tools/tpm2_selftest.c $(TOOL_SRC)
tools_tpm2_sign_SOURCES = tools/tpm2_sign.c $(TOOL_SRC)
tools_tpm2_certifycreation_SOURCES = tools/tpm2_certifycreation.c $(TOOL_SRC)
tools_tpm2_nvcertify_SOURCES = tools/tpm2_nvcertify.c $(TOOL_SRC)
tools_tpm2_unseal_SOURCES = tools/tpm2_unseal.c $(TOOL_SRC)
tools_tpm2_dictionarylockout_SOURCES = tools/tpm2_dictionarylockout.c $(TOOL_SRC)
tools_tpm2_createpolicy_SOURCES = tools/tpm2_createpolicy.c $(TOOL_SRC)
tools_tpm2_setprimarypolicy_SOURCES = tools/tpm2_setprimarypolicy.c $(TOOL_SRC)
tools_tpm2_hierarchycontrol_SOURCES = tools/tpm2_hierarchycontrol.c $(TOOL_SRC)
tools_tpm2_pcrallocate_SOURCES = tools/tpm2_pcrallocate.c $(TOOL_SRC)
tools_tpm2_pcrextend_SOURCES = tools/tpm2_pcrextend.c $(TOOL_SRC)
tools_tpm2_pcrevent_SOURCES = tools/tpm2_pcrevent.c $(TOOL_SRC)
tools_tpm2_pcrreset_SOURCES = tools/tpm2_pcrreset.c $(TOOL_SRC)
tools_tpm2_import_SOURCES = tools/tpm2_import.c $(TOOL_SRC)
tools_tpm2_duplicate_SOURCES = tools/tpm2_duplicate.c $(TOOL_SRC)
tools_tpm2_flushcontext_SOURCES = tools/tpm2_flushcontext.c $(TOOL_SRC)
tools_tpm2_startauthsession_SOURCES = tools/tpm2_startauthsession.c $(TOOL_SRC)
tools_tpm2_policypcr_SOURCES = tools/tpm2_policypcr.c $(TOOL_SRC)
tools_tpm2_policyauthorize_SOURCES = tools/tpm2_policyauthorize.c $(TOOL_SRC)
tools_tpm2_policyauthorizenv_SOURCES = tools/tpm2_policyauthorizenv.c $(TOOL_SRC)
tools_tpm2_policynv_SOURCES = tools/tpm2_policynv.c $(TOOL_SRC)
tools_tpm2_policycountertimer_SOURCES = tools/tpm2_policycountertimer.c $(TOOL_SRC)
tools_tpm2_policyor_SOURCES = tools/tpm2_policyor.c $(TOOL_SRC)
tools_tpm2_policynamehash_SOURCES = tools/tpm2_policynamehash.c $(TOOL_SRC)
tools_tpm2_policytemplate_SOURCES = tools/tpm2_policytemplate.c $(TOOL_SRC)
tools_tpm2_policypassword_SOURCES = tools/tpm2_policypassword.c $(TOOL_SRC)
tools_tpm2_policysigned_SOURCES = tools/tpm2_policysigned.c $(TOOL_SRC)
tools_tpm2_policyticket_SOURCES = tools/tpm2_policyticket.c $(TOOL_SRC)
tools_tpm2_policyauthvalue_SOURCES = tools/tpm2_policyauthvalue.c $(TOOL_SRC)
tools_tpm2_policysecret_SOURCES = tools/tpm2_policysecret.c $(TOOL_SRC)
tools_tpm2_policyrestart_SOURCES = tools/tpm2_policyrestart.c $(TOOL_SRC)
tools_tpm2_policycommandcode_SOURCES = tools/tpm2_policycommandcode.c $(TOOL_SRC)
tools_tpm2_policynvwritten_SOURCES = tools/tpm2_policynvwritten.c $(TOOL_SRC)
tools_tpm2_stirrandom_SOURCES = tools/tpm2_stirrandom.c $(TOOL_SRC)
tools_tpm2_policyduplicationselect_SOURCES = tools/tpm2_policyduplicationselect.c $(TOOL_SRC)
tools_tpm2_policylocality_SOURCES = tools/tpm2_policylocality.c $(TOOL_SRC)
tools_tpm2_testparms_SOURCES = tools/tpm2_testparms.c $(TOOL_SRC)
tools_tpm2_incrementalselftest_SOURCES = tools/tpm2_incrementalselftest.c $(TOOL_SRC)
tools_tpm2_gettestresult_SOURCES = tools/tpm2_gettestresult.c $(TOOL_SRC)
tools_tpm2_readclock_SOURCES = tools/tpm2_readclock.c $(TOOL_SRC)
tools_tpm2_setclock_SOURCES = tools/tpm2_setclock.c $(TOOL_SRC)
tools_tpm2_shutdown_SOURCES = tools/tpm2_shutdown.c $(TOOL_SRC)
tools_tpm2_clockrateadjust_SOURCES = tools/tpm2_clockrateadjust.c $(TOOL_SRC)
tools_tpm2_nvwritelock_SOURCES = tools/tpm2_nvwritelock.c $(TOOL_SRC)
tools_tpm2_nvsetbits_SOURCES = tools/tpm2_nvsetbits.c $(TOOL_SRC)
tools_tpm2_nvextend_SOURCES = tools/tpm2_nvextend.c $(TOOL_SRC)
tools_tpm2_gettime_SOURCES = tools/tpm2_gettime.c $(TOOL_SRC)

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
    test/unit/test_tpm2_util \
    test/unit/test_options \
    test/unit/test_cc_util

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
                                         -Wl,--wrap=Esys_StartAuthSession \
                                         -Wl,--wrap=fopen \
                                         -Wl,--wrap=fread \
                                         -Wl,--wrap=fseek \
                                         -Wl,--wrap=ftell \
                                         -Wl,--wrap=fclose
test_unit_test_tpm2_auth_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_errata_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_errata_LDFLAGS  = -Wl,--wrap=Esys_GetCapability
test_unit_test_tpm2_errata_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_session_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_session_LDFLAGS  = -Wl,--wrap=Esys_StartAuthSession \
                                       -Wl,--wrap=tpm2_context_save \
                                       -Wl,--wrap=Esys_ContextLoad \
                                       -Wl,--wrap=Esys_PolicyRestart \
                                       -Wl,--wrap=Esys_TR_GetName \
                                       -Wl,--wrap=tpm2_flush_context

test_unit_test_tpm2_session_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_policy_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_policy_LDFLAGS  = -Wl,--wrap=Esys_StartAuthSession \
                                      -Wl,--wrap=Esys_PolicyPCR \
                                      -Wl,--wrap=Esys_PCR_Read \
                                      -Wl,--wrap=Esys_PolicyGetDigest \
                                      -Wl,--wrap=Esys_FlushContext

test_unit_test_tpm2_policy_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_options_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_options_LDFLAGS  = -Wl,--wrap=Tss2_TctiLdr_Initialize \
                               -Wl,--wrap=tpm2_util_getenv
test_unit_test_options_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_cc_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_cc_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

AM_TESTS_ENVIRONMENT =	\
	TPM2_ABRMD=tpm2-abrmd; export TPM2_ABRMD; \
	TPM2_SIM=tpm_server; export TPM2_SIM; \
	PATH=$(abs_builddir)/tools:$(abs_builddir)/tools/misc:$(abs_top_srcdir)/test/integration:$(PATH); \
	TPM2_TOOLS_TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures; \
	export TPM2_TOOLS_TEST_FIXTURES;

SH_LOG_COMPILER = dbus-run-session bash
AM_SH_LOG_FLAGS = --
endif

TEST_EXTENSIONS = .sh

check-hook:
	rm -rf .lock_file

EXTRA_DIST_IGNORE = \
    .gitignore \
    .deps

EXTRA_DIST = \
    bootstrap \
    AUTHORS.md \
    CHANGELOG.md \
    CONTRIBUTING.md \
    INSTALL.md \
    LICENSE \
    MAINTAINERS.md \
    README.md \
    RELEASE.md \
    man \
    scripts \
    test

if HAVE_MAN_PAGES
    dist_man1_MANS := \
    man/man1/tpm2_activatecredential.1 \
    man/man1/tpm2_certify.1 \
    man/man1/tpm2_changeauth.1 \
    man/man1/tpm2_changeeps.1 \
    man/man1/tpm2_changepps.1 \
    man/man1/tpm2_checkquote.1 \
    man/man1/tpm2_clear.1 \
    man/man1/tpm2_clearcontrol.1 \
	man/man1/tpm2_clockrateadjust.1 \
    man/man1/tpm2_create.1 \
    man/man1/tpm2_createak.1 \
    man/man1/tpm2_createek.1 \
    man/man1/tpm2_createpolicy.1 \
    man/man1/tpm2_setprimarypolicy.1 \
    man/man1/tpm2_createprimary.1 \
    man/man1/tpm2_dictionarylockout.1 \
    man/man1/tpm2_duplicate.1 \
    man/man1/tpm2_getcap.1 \
    man/man1/tpm2_encryptdecrypt.1 \
    man/man1/tpm2_evictcontrol.1 \
    man/man1/tpm2_flushcontext.1 \
    man/man1/tpm2_getekcertificate.1 \
    man/man1/tpm2_getrandom.1 \
    man/man1/tpm2_gettestresult.1 \
    man/man1/tpm2_gettime.1 \
    man/man1/tpm2_hierarchycontrol.1 \
    man/man1/tpm2_hash.1 \
    man/man1/tpm2_hmac.1 \
    man/man1/tpm2_import.1 \
    man/man1/tpm2_incrementalselftest.1 \
    man/man1/tpm2_load.1 \
    man/man1/tpm2_loadexternal.1 \
    man/man1/tpm2_makecredential.1 \
    man/man1/tpm2_nvdefine.1 \
    man/man1/tpm2_nvextend.1 \
    man/man1/tpm2_nvincrement.1 \
    man/man1/tpm2_nvreadpublic.1 \
    man/man1/tpm2_nvread.1 \
    man/man1/tpm2_nvreadlock.1 \
    man/man1/tpm2_nvundefine.1 \
    man/man1/tpm2_nvwrite.1 \
    man/man1/tpm2_nvwritelock.1 \
    man/man1/tpm2_nvsetbits.1 \
    man/man1/tpm2_pcrallocate.1 \
    man/man1/tpm2_pcrevent.1 \
    man/man1/tpm2_pcrextend.1 \
    man/man1/tpm2_pcrread.1 \
    man/man1/tpm2_pcrreset.1 \
    man/man1/tpm2_policypcr.1 \
    man/man1/tpm2_policyrestart.1 \
    man/man1/tpm2_policycommandcode.1 \
    man/man1/tpm2_policynvwritten.1 \
    man/man1/tpm2_policyduplicationselect.1 \
    man/man1/tpm2_policylocality.1 \
    man/man1/tpm2_policyauthorize.1 \
    man/man1/tpm2_policyauthorizenv.1 \
    man/man1/tpm2_policynv.1 \
    man/man1/tpm2_policycountertimer.1 \
    man/man1/tpm2_policyor.1 \
    man/man1/tpm2_policynamehash.1 \
    man/man1/tpm2_policytemplate.1 \
    man/man1/tpm2_policypassword.1 \
    man/man1/tpm2_policysigned.1 \
    man/man1/tpm2_policyticket.1 \
    man/man1/tpm2_policyauthvalue.1 \
    man/man1/tpm2_policysecret.1 \
    man/man1/tpm2_print.1 \
    man/man1/tpm2_quote.1 \
    man/man1/tpm2_rc_decode.1 \
    man/man1/tpm2_readclock.1 \
    man/man1/tpm2_readpublic.1 \
    man/man1/tpm2_rsadecrypt.1 \
    man/man1/tpm2_rsaencrypt.1 \
    man/man1/tpm2_send.1 \
    man/man1/tpm2_selftest.1 \
    man/man1/tpm2_setclock.1 \
    man/man1/tpm2_shutdown.1 \
    man/man1/tpm2_sign.1 \
    man/man1/tpm2_certifycreation.1 \
    man/man1/tpm2_nvcertify.1 \
    man/man1/tpm2_startauthsession.1 \
    man/man1/tpm2_startup.1 \
    man/man1/tpm2_stirrandom.1 \
    man/man1/tpm2_testparms.1 \
    man/man1/tpm2_unseal.1 \
    man/man1/tpm2_verifysignature.1
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
	man/common/policy-limitations.md \
	man/common/pubkey.md \
	man/common/returns.md \
	man/common/sign-alg.md \
	man/common/signature.md \
	man/common/signschemes.md \
	man/common/tcti.md

man/man1/%.1 : man/%.1.md $(MARKDOWN_COMMON_DEPS)
	$(AM_V_GEN)rm -f $@ && \
	mkdir -p man/man1 && \
	sed -e '/\[common options\]/r $(top_srcdir)/man/common/options.md' \
	    -e '/\[common options\]/d' \
	    -e '/\[common tcti options\]/r $(top_srcdir)/man/common/tcti.md' \
	    -e '/\[common tcti options\]/d' \
	    -e '/\[authorization formatting\]/r $(top_srcdir)/man/common/authorizations.md' \
	    -e '/\[authorization formatting\]/d' \
	    -e '/\[context object format\]/r $(top_srcdir)/man/common/ctxobj.md' \
	    -e '/\[context object format\]/d' \
	    -e '/\[supported hash algorithms\]/r $(top_srcdir)/man/common/hash.md' \
	    -e '/\[supported hash algorithms\]/d' \
	    -e '/\[algorithm specifiers\]/r $(top_srcdir)/man/common/alg.md' \
	    -e '/\[algorithm specifiers\]/d' \
	    -e '/\[supported public object algorithms\]/r $(top_srcdir)/man/common/object-alg.md' \
	    -e '/\[supported public object algorithms\]/d' \
	    -e '/\[supported signing algorithms\]/r $(top_srcdir)/man/common/sign-alg.md' \
	    -e '/\[supported signing algorithms\]/d' \
	    -e '/\[nv attributes\]/r $(top_srcdir)/man/common/nv-attrs.md' \
	    -e '/\[nv attributes\]/d' \
	    -e '/\[pcr bank specifiers\]/r $(top_srcdir)/man/common/pcr.md' \
	    -e '/\[pcr bank specifiers\]/d' \
	    -e '/\[pubkey options\]/r $(top_srcdir)/man/common/pubkey.md' \
	    -e '/\[pubkey options\]/d' \
	    -e '/\[signature format specifiers\]/r $(top_srcdir)/man/common/signature.md' \
	    -e '/\[signature format specifiers\]/d' \
	    -e '/\[object attribute specifiers\]/r $(top_srcdir)/man/common/obj-attrs.md' \
	    -e '/\[object attribute specifiers\]/d' \
	    -e '/\[supported signing schemes\]/r $(top_srcdir)/man/common/signschemes.md' \
	    -e '/\[supported signing schemes\]/d' \
	    -e '/\[limitations\]/r $(top_srcdir)/man/common/policy-limitations.md' \
	    -e '/\[limitations\]/d' \
	    -e '/\[returns\]/r $(top_srcdir)/man/common/returns.md' \
	    -e '/\[returns\]/d' \
	    -e '/\[footer\]/r $(top_srcdir)/man/common/footer.md' \
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

dist-hook:
	for f in $(EXTRA_DIST_IGNORE); do \
		rm -rf `find $(distdir) -name $$f`; \
	done;
if !HAVE_PANDOC
# If pandoc is not enabled, we want to complain that you need pandoc for make dist,
# so hook the target and complain.
	@(>&2 echo "You do not have pandoc, a requirement for the distribution of manpages")
	@exit 1
endif
