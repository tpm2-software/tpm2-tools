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
    $(TSS2_RC_CFLAGS) $(TSS2_SYS_CFLAGS) $(CURL_CFLAGS)

AM_LDFLAGS   := $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

LDADD = \
    $(LIB_COMMON) $(TSS2_ESYS_LIBS) $(TSS2_MU_LIBS) $(CRYPTO_LIBS) $(TSS2_TCTILDR_LIBS) \
    $(TSS2_RC_LIBS) $(TSS2_SYS_LIBS) $(EFIVAR_LIBS)

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bashcompdir='$$(datarootdir)/bash-completion/completions'

# keep me sorted
bin_PROGRAMS =
FAPI_CFLAGS = $(EXTRA_CFLAGS) $(TSS2_FAPI_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(CRYPTO_CFLAGS)
TESTS =

if HAVE_FAPI

bin_PROGRAMS += tools/fapi/tss2

endif

noinst_LIBRARIES = $(LIB_COMMON)
lib_libcommon_a_SOURCES = $(LIB_SRC)
lib_libcommon_a_CFLAGS = -fPIC $(AM_CFLAGS)

tools_fapi_tss2_CFLAGS = $(FAPI_CFLAGS) -DTSS2_TOOLS_MAX="$(words $(tss2_tools))"
tools_fapi_tss2_LDFLAGS = $(EXTRA_LDFLAGS) $(TSS2_FAPI_LIBS)
tools_fapi_tss2_SOURCES = \
	tools/fapi/tss2_template.c \
	tools/fapi/tss2_template.h \
	$(tss2_tools)

tss2_tools = \
    tools/fapi/tss2_decrypt.c \
    tools/fapi/tss2_encrypt.c \
    tools/fapi/tss2_list.c \
    tools/fapi/tss2_changeauth.c \
    tools/fapi/tss2_delete.c \
    tools/fapi/tss2_import.c \
    tools/fapi/tss2_getinfo.c \
    tools/fapi/tss2_createkey.c \
    tools/fapi/tss2_createseal.c \
    tools/fapi/tss2_exportkey.c \
    tools/fapi/tss2_getcertificate.c \
    tools/fapi/tss2_getplatformcertificates.c \
    tools/fapi/tss2_gettpmblobs.c \
    tools/fapi/tss2_getappdata.c \
    tools/fapi/tss2_gettpm2object.c \
    tools/fapi/tss2_setappdata.c \
    tools/fapi/tss2_setcertificate.c \
    tools/fapi/tss2_sign.c \
    tools/fapi/tss2_verifysignature.c \
    tools/fapi/tss2_verifyquote.c \
    tools/fapi/tss2_createnv.c \
    tools/fapi/tss2_nvextend.c \
    tools/fapi/tss2_nvincrement.c \
    tools/fapi/tss2_nvread.c \
    tools/fapi/tss2_nvsetbits.c \
    tools/fapi/tss2_nvwrite.c \
    tools/fapi/tss2_getdescription.c \
    tools/fapi/tss2_setdescription.c \
    tools/fapi/tss2_pcrextend.c \
    tools/fapi/tss2_quote.c \
    tools/fapi/tss2_pcrread.c \
    tools/fapi/tss2_authorizepolicy.c \
    tools/fapi/tss2_exportpolicy.c \
    tools/fapi/tss2_import.c \
    tools/fapi/tss2_provision.c \
    tools/fapi/tss2_getrandom.c \
    tools/fapi/tss2_unseal.c \
    tools/fapi/tss2_writeauthorizenv.c


# Bundle all the tools into a single program similar to busybox
bin_PROGRAMS += tools/tpm2
tools_tpm2_LDADD = $(LDADD) $(CURL_LIBS)
tools_tpm2_CFLAGS = $(AM_CFLAGS) -DTPM2_TOOLS_MAX="$(words $(tpm2_tools))"
tools_tpm2_SOURCES = \
	tools/tpm2_tool.c \
	tools/tpm2_tool.h \
	$(tpm2_tools)

tpm2_tools = \
    tools/misc/tpm2_certifyX509certutil.c \
    tools/misc/tpm2_checkquote.c \
    tools/misc/tpm2_encodeobject.c \
    tools/misc/tpm2_eventlog.c \
    tools/misc/tpm2_print.c \
    tools/misc/tpm2_rc_decode.c \
    tools/misc/tpm2_tr_encode.c \
    tools/tpm2_activatecredential.c \
    tools/tpm2_certify.c \
    tools/tpm2_changeauth.c \
    tools/tpm2_changeeps.c \
    tools/tpm2_changepps.c \
    tools/tpm2_clear.c \
    tools/tpm2_clearcontrol.c \
    tools/tpm2_clockrateadjust.c \
    tools/tpm2_create.c \
    tools/tpm2_createak.c \
    tools/tpm2_createek.c \
    tools/tpm2_createpolicy.c \
    tools/tpm2_setprimarypolicy.c \
    tools/tpm2_createprimary.c \
    tools/tpm2_dictionarylockout.c \
    tools/tpm2_duplicate.c \
    tools/tpm2_getcap.c \
    tools/tpm2_gettestresult.c \
    tools/tpm2_encryptdecrypt.c \
    tools/tpm2_evictcontrol.c \
    tools/tpm2_flushcontext.c \
    tools/tpm2_getekcertificate.c \
    tools/tpm2_getrandom.c \
    tools/tpm2_gettime.c \
    tools/tpm2_hash.c \
    tools/tpm2_hierarchycontrol.c \
    tools/tpm2_hmac.c \
    tools/tpm2_import.c \
    tools/tpm2_incrementalselftest.c \
    tools/tpm2_load.c \
    tools/tpm2_loadexternal.c \
    tools/tpm2_makecredential.c \
    tools/tpm2_nvdefine.c \
    tools/tpm2_nvextend.c \
    tools/tpm2_nvincrement.c \
    tools/tpm2_nvreadpublic.c \
    tools/tpm2_nvread.c \
    tools/tpm2_nvreadlock.c \
    tools/tpm2_nvundefine.c \
    tools/tpm2_nvwrite.c \
    tools/tpm2_nvwritelock.c \
    tools/tpm2_nvsetbits.c \
    tools/tpm2_pcrallocate.c \
    tools/tpm2_pcrevent.c \
    tools/tpm2_pcrextend.c \
    tools/tpm2_pcrread.c \
    tools/tpm2_pcrreset.c \
    tools/tpm2_policypcr.c \
    tools/tpm2_policyauthorize.c \
    tools/tpm2_policyauthorizenv.c \
    tools/tpm2_policynv.c \
    tools/tpm2_policycountertimer.c \
    tools/tpm2_policyor.c \
    tools/tpm2_policynamehash.c \
    tools/tpm2_policytemplate.c \
    tools/tpm2_policycphash.c \
    tools/tpm2_policypassword.c \
    tools/tpm2_policysigned.c \
    tools/tpm2_policyticket.c \
    tools/tpm2_policyauthvalue.c \
    tools/tpm2_policysecret.c \
    tools/tpm2_policyrestart.c \
    tools/tpm2_policycommandcode.c \
    tools/tpm2_policynvwritten.c \
    tools/tpm2_policyduplicationselect.c \
    tools/tpm2_policylocality.c \
    tools/tpm2_quote.c \
    tools/tpm2_readclock.c \
    tools/tpm2_readpublic.c \
    tools/tpm2_rsadecrypt.c \
    tools/tpm2_rsaencrypt.c \
    tools/tpm2_send.c \
    tools/tpm2_selftest.c \
    tools/tpm2_setclock.c \
    tools/tpm2_shutdown.c \
    tools/tpm2_sign.c \
    tools/tpm2_certifycreation.c \
    tools/tpm2_nvcertify.c \
    tools/tpm2_startauthsession.c \
    tools/tpm2_startup.c \
    tools/tpm2_stirrandom.c \
    tools/tpm2_testparms.c \
    tools/tpm2_unseal.c \
    tools/tpm2_verifysignature.c \
    tools/tpm2_setcommandauditstatus.c \
    tools/tpm2_getcommandauditdigest.c \
    tools/tpm2_getsessionauditdigest.c \
    tools/tpm2_geteccparameters.c \
    tools/tpm2_ecephemeral.c \
    tools/tpm2_commit.c \
    tools/tpm2_ecdhkeygen.c \
    tools/tpm2_ecdhzgen.c \
    tools/tpm2_zgen2phase.c \
    tools/tpm2_sessionconfig.c \
    tools/tpm2_getpolicydigest.c

# Create the symlinks for each tool to the tpm2 and optional tss2 bundled executables
install-exec-hook:
	for tool in $(notdir $(basename $(tpm2_tools))) ; do \
		$(LN_S) -f \
		"tpm2$(EXEEXT)" \
		"$(DESTDIR)$(bindir)/$$tool$(EXEEXT)" ; \
	done
if HAVE_FAPI
	for tool in $(notdir $(basename $(tss2_tools))) ; do \
		$(LN_S) -f \
		"tss2$(EXEEXT)" \
		"$(DESTDIR)$(bindir)/$$tool$(EXEEXT)" ; \
	done
endif

if UNIT
check_SCRIPTS =
TESTS += $(check_PROGRAMS)
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
    test/unit/test_cc_util \
    test/unit/test_tpm2_eventlog \
    test/unit/test_tpm2_eventlog_yaml \
    test/unit/test_object

TESTS += $(ALL_SYSTEM_TESTS)

if HAVE_ESYS_4_0
check_SCRIPTS += test/unit/vendor_tests.sh
TESTS += test/unit/vendor_tests.sh
endif

if HAVE_FAPI
TESTS += $(ALL_FAPI_TESTS)
endif

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
                                         -Wl,--wrap=feof, \
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
                                      -Wl,--wrap=Esys_FlushContext \
                                      -Wl,--wrap=files_get_file_size_path \
                                      -Wl,--wrap=files_load_bytes_from_path

test_unit_test_tpm2_policy_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_options_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_options_LDFLAGS  = -Wl,--wrap=Tss2_TctiLdr_Initialize \
                               -Wl,--wrap=tpm2_util_getenv
test_unit_test_options_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_cc_util_CFLAGS   = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_cc_util_LDADD    = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_eventlog_CFLAGS = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_eventlog_LDADD = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_tpm2_eventlog_yaml_CFLAGS = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_tpm2_eventlog_yaml_LDADD = $(CMOCKA_LIBS) $(LDADD)

test_unit_test_object_CFLAGS = $(AM_CFLAGS) $(CMOCKA_CFLAGS)
test_unit_test_object_LDADD = $(CMOCKA_LIBS) $(LDADD)

AM_TESTS_ENVIRONMENT =	\
	export TPM2_ABRMD=$(TPM2_ABRMD); \
	export TPM2_SIM=$(TPM2_SIM); \
	export PATH=$(abs_builddir)/tools:$(abs_builddir)/tools/misc:$(abs_top_srcdir)/test/integration:$(abs_builddir)/tools/fapi:$(PATH); \
	export TPM2_TOOLS_TEST_FIXTURES=$(abs_top_srcdir)/test/integration/fixtures; \
	export abs_builddir=$(abs_builddir); \
	export abs_srcdir=$(abs_srcdir); \
	export PYTHON=$(PYTHON); \
	export TPM2_TOOLS_TEST_FIXTURES;

if PERSISTENT
    AM_TESTS_ENVIRONMENT +=	\
        TPM2TOOLS_TEST_PERSISTENT=true;
else
    AM_TESTS_ENVIRONMENT +=	\
        TPM2TOOLS_TEST_PERSISTENT=false;
endif

SH_LOG_COMPILER = dbus-run-session bash
AM_SH_LOG_FLAGS = --
endif

TEST_EXTENSIONS = .sh

check-hook:
	rm -rf .lock_file
	rm -f  $(abs_top_srcdir)/test/integration/fixtures/event-uefiservices.bin.yaml

EXTRA_DIST_IGNORE = \
    .gitignore \
    .deps

EXTRA_DIST = \
    bootstrap \
    docs/AUTHORS.md \
    docs/CHANGELOG.md \
    docs/CONTRIBUTING.md \
    docs/INSTALL.md \
    docs/LICENSE \
    docs/MAINTAINERS.md \
    docs/README.md \
    docs/RELEASE.md \
    man \
    scripts \
    test \
    VERSION

if HAVE_MAN_PAGES
    dist_man1_MANS := \
    man/man1/tpm2_activatecredential.1 \
    man/man1/tpm2_certify.1 \
    man/man1/tpm2_certifyX509certutil.1 \
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
    man/man1/tpm2_encodeobject.1 \
    man/man1/tpm2_getcap.1 \
    man/man1/tpm2_encryptdecrypt.1 \
    man/man1/tpm2_eventlog.1 \
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
    man/man1/tpm2_policycphash.1 \
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
    man/man1/tpm2_tr_encode.1 \
    man/man1/tpm2_unseal.1 \
    man/man1/tpm2_verifysignature.1 \
    man/man1/tpm2_setcommandauditstatus.1 \
    man/man1/tpm2_getcommandauditdigest.1 \
    man/man1/tpm2_getsessionauditdigest.1 \
    man/man1/tpm2_geteccparameters.1 \
    man/man1/tpm2_ecephemeral.1 \
    man/man1/tpm2_commit.1 \
    man/man1/tpm2_ecdhkeygen.1 \
    man/man1/tpm2_ecdhzgen.1 \
    man/man1/tpm2_zgen2phase.1 \
    man/man1/tpm2_sessionconfig.1 \
    man/man1/tpm2_getpolicydigest.1 \
    man/man1/tpm2.1

if HAVE_FAPI
dist_man1_MANS += \
    man/man1/tss2_list.1 \
    man/man1/tss2_changeauth.1 \
    man/man1/tss2_delete.1 \
    man/man1/tss2_import.1 \
    man/man1/tss2_decrypt.1 \
    man/man1/tss2_encrypt.1 \
    man/man1/tss2_getinfo.1 \
    man/man1/tss2_createnv.1 \
    man/man1/tss2_nvread.1 \
    man/man1/tss2_nvextend.1 \
    man/man1/tss2_nvincrement.1 \
    man/man1/tss2_nvsetbits.1 \
    man/man1/tss2_nvwrite.1 \
    man/man1/tss2_createkey.1 \
    man/man1/tss2_createseal.1 \
    man/man1/tss2_getcertificate.1 \
    man/man1/tss2_getplatformcertificates.1 \
    man/man1/tss2_gettpmblobs.1 \
    man/man1/tss2_getappdata.1 \
    man/man1/tss2_gettpm2object.1 \
    man/man1/tss2_setappdata.1 \
    man/man1/tss2_setcertificate.1 \
    man/man1/tss2_exportkey.1 \
    man/man1/tss2_sign.1 \
    man/man1/tss2_verifysignature.1 \
    man/man1/tss2_verifyquote.1 \
    man/man1/tss2_getdescription.1 \
    man/man1/tss2_setdescription.1 \
    man/man1/tss2_pcrextend.1 \
    man/man1/tss2_quote.1 \
    man/man1/tss2_pcrread.1 \
    man/man1/tss2_provision.1 \
    man/man1/tss2_authorizepolicy.1 \
    man/man1/tss2_exportpolicy.1 \
    man/man1/tss2_unseal.1 \
    man/man1/tss2_import.1 \
    man/man1/tss2_getrandom.1 \
    man/man1/tss2_writeauthorizenv.1
endif
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
	man/common/pcrs_format.md \
	man/common/policy-limitations.md \
	man/common/pubkey.md \
	man/common/returns.md \
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
	    -e '/\[common tss2 options\]/r $(top_srcdir)/man/common/tss2-options.md' \
	    -e '/\[common tss2 options\]/d' \
	    -e '/\[common fapi references\]/r $(top_srcdir)/man/common/tss2-fapi-references.md' \
	    -e '/\[common fapi references\]/d' \
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
	    -e '/\[PCR output file format specifiers\]/r $(top_srcdir)/man/common/pcrs_format.md' \
	    -e '/\[PCR output file format specifiers\]/d' \
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
	    -e '/\[protection details\]/r $(top_srcdir)/man/common/protection-details.md' \
	    -e '/\[protection details\]/d' \
	    < $< | pandoc -s -t man > $@

CLEANFILES = $(dist_man1_MANS)

bashcompdir=@bashcompdir@
dist_bashcomp_DATA=dist/bash-completion/tpm2-tools/tpm2_completion.bash
if HAVE_FAPI
dist_bashcomp_DATA+= \
	dist/bash-completion/tpm2-tools/tss2_decrypt \
	dist/bash-completion/tpm2-tools/tss2_encrypt \
	dist/bash-completion/tpm2-tools/tss2_list \
	dist/bash-completion/tpm2-tools/tss2_changeauth \
	dist/bash-completion/tpm2-tools/tss2_delete \
	dist/bash-completion/tpm2-tools/tss2_import \
	dist/bash-completion/tpm2-tools/tss2_getinfo \
	dist/bash-completion/tpm2-tools/tss2_createkey \
    dist/bash-completion/tpm2-tools/tss2_createseal \
	dist/bash-completion/tpm2-tools/tss2_exportkey \
	dist/bash-completion/tpm2-tools/tss2_getcertificate \
    dist/bash-completion/tpm2-tools/tss2_getplatformcertificates \
    dist/bash-completion/tpm2-tools/tss2_gettpmblobs \
	dist/bash-completion/tpm2-tools/tss2_setcertificate \
    dist/bash-completion/tpm2-tools/tss2_getappdata \
    dist/bash-completion/tpm2-tools/tss2_gettpm2object \
    dist/bash-completion/tpm2-tools/tss2_setappdata \
	dist/bash-completion/tpm2-tools/tss2_sign \
	dist/bash-completion/tpm2-tools/tss2_verifysignature \
	dist/bash-completion/tpm2-tools/tss2_verifyquote \
	dist/bash-completion/tpm2-tools/tss2_createnv \
	dist/bash-completion/tpm2-tools/tss2_nvextend \
	dist/bash-completion/tpm2-tools/tss2_nvincrement \
	dist/bash-completion/tpm2-tools/tss2_nvread \
	dist/bash-completion/tpm2-tools/tss2_nvsetbits \
	dist/bash-completion/tpm2-tools/tss2_nvwrite \
	dist/bash-completion/tpm2-tools/tss2_getdescription \
	dist/bash-completion/tpm2-tools/tss2_setdescription \
	dist/bash-completion/tpm2-tools/tss2_pcrextend \
	dist/bash-completion/tpm2-tools/tss2_quote \
	dist/bash-completion/tpm2-tools/tss2_pcrread \
	dist/bash-completion/tpm2-tools/tss2_authorizepolicy \
	dist/bash-completion/tpm2-tools/tss2_exportpolicy \
	dist/bash-completion/tpm2-tools/tss2_provision \
	dist/bash-completion/tpm2-tools/tss2_getrandom \
	dist/bash-completion/tpm2-tools/tss2_unseal \
	dist/bash-completion/tpm2-tools/tss2_writeauthorizenv \
    dist/bash-completion/tpm2-tools/tss2
endif

install-data-hook:
	cd $(DESTDIR)$(bashcompdir) && \
	for tool in $(bin_PROGRAMS); do \
		[ "$${tool}" = "$${tool#tools/fapi/*}" ] && $(LN_S) -f tpm2_completion.bash $${tool##*/}; \
	done

uninstall-hook:
	cd $(DESTDIR)$(bashcompdir) && \
	for tool in $(bin_PROGRAMS); do \
		[ "$${tool}" = "$${tool#tools/fapi/*}" -a -L $${tool##*/} ] && rm -f $${tool##*/}; \
	done

dist-hook:
	for f in $(EXTRA_DIST_IGNORE); do \
		rm -rf `find $(distdir) -name $$f`; \
	done;

prepare-check:
if HAVE_EFIVAR_H
	cp  $(abs_top_srcdir)/test/integration/fixtures/event-pretty/event-*.yaml \
	    $(abs_top_srcdir)/test/integration/fixtures/
else
	cp  $(abs_top_srcdir)/test/integration/fixtures/event-raw/event-*.yaml \
	    $(abs_top_srcdir)/test/integration/fixtures/
endif

check: prepare-check

if !HAVE_PANDOC
# If pandoc is not enabled, we want to complain that you need pandoc for make dist,
# so hook the target and complain.
	@(>&2 echo "You do not have pandoc, a requirement for the distribution of manpages")
	@exit 1
endif
