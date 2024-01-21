AC_INIT([tpm2-tools],
    [m4_esyscmd_s([cat ./VERSION])])
AC_CONFIG_MACRO_DIR([m4])

AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([info])

AC_PROG_CC
AC_PROG_LN_S
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
# enable "silent-rules" option by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])
AC_CONFIG_FILES([Makefile])

# enable autoheader config.h file
AC_CONFIG_HEADERS([lib/config.h])

AC_CHECK_PROG([PANDOC],[pandoc],[yes])
AS_IF(
    [test "x${PANDOC}" = x"yes"],
    [],
    [AC_MSG_WARN([Required executable pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC],[test "x${PANDOC}" = "xyes"])
AM_CONDITIONAL(
    [HAVE_MAN_PAGES],
    [test -d "${srcdir}/man/man1" -o "x${PANDOC}" = "xyes"])

AC_ARG_ENABLE([fapi],
    [AS_HELP_STRING([--disable-fapi], [disable FAPI tools (default: auto)])],,
    [enable_fapi=check])
AS_IF([test "$enable_fapi" = yes -o "$enable_fapi" = check],
      [PKG_CHECK_MODULES([TSS2_FAPI], [tss2-fapi], [enable_fapi=yes], [
         AS_IF([test "$enable_fapi" = yes], [AC_MSG_ERROR([Required module tss2-fapi not found])])
         enable_fapi=no
         ])
       PKG_CHECK_MODULES([TSS2_FAPI_3_0], [tss2-fapi >= 3.0],
                         [AC_DEFINE([FAPI_3_0], [1], [fapi3.0.0])],
                         [true])
      ])
AM_CONDITIONAL([HAVE_FAPI], [test "$enable_fapi" = yes])

PKG_CHECK_MODULES(
    [TSS2_ESYS_4_0],
    [tss2-esys >= 4.0.0],
    [AC_DEFINE([ESYS_4_0], [1], [Esys4.0])]
    [AC_SUBST([TSS2_ESYS_CFLAGS], [$TSS2_ESYS_4_0_CFLAGS])
     AC_SUBST([TSS2_ESYS_LIBS], [$TSS2_ESYS_4_0_LIBS])
     have_esys_4_0="yes"],
    [PKG_CHECK_MODULES(
        [TSS2_ESYS_3_0],
        [tss2-esys >= 3.0.0],
        [AC_DEFINE([ESYS_3_0], [1], [Esys3.0])]
        [AC_SUBST([TSS2_ESYS_CFLAGS], [$TSS2_ESYS_3_0_CFLAGS])
         AC_SUBST([TSS2_ESYS_LIBS], [$TSS2_ESYS_3_0_LIBS])],
        [PKG_CHECK_MODULES([TSS2_ESYS_2_3], [tss2-esys >= 2.4.0],
            [AC_DEFINE([ESYS_2_3], [1], [Esys2.3])]
            [AC_SUBST([TSS2_ESYS_CFLAGS], [$TSS2_ESYS_2_3_CFLAGS])
            AC_SUBST([TSS2_ESYS_LIBS], [$TSS2_ESYS_2_3_LIBS])
        ])
    ])
])

AM_CONDITIONAL([HAVE_ESYS_4_0], [test "x${have_esys_4_0}" = "xyes"])

PKG_CHECK_MODULES([TSS2_TCTILDR], [tss2-tctildr])
PKG_CHECK_MODULES([TSS2_MU], [tss2-mu])
PKG_CHECK_MODULES([TSS2_RC], [tss2-rc])
PKG_CHECK_MODULES([TSS2_SYS], [tss2-sys])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.1.0])
LIBS_save="${LIBS}"
LIBS="${CRYPTO_LIBS} ${LIBS}"
AC_CHECK_LIB(crypto, [EVP_sm3], [
        AC_DEFINE([HAVE_EVP_SM3], [1], [Support EVP_sm3 in openssl])],
        [])
AC_CHECK_LIB(crypto, [EVP_sm4_cfb128], [
        AC_DEFINE([HAVE_EVP_SM4_CFB], [1], [Support EVP_sm4_cfb in openssl])],
        [])
LIBS="${LIBS_save}"
PKG_CHECK_MODULES([CURL], [libcurl])

# pretty print of devicepath if efivar library is present
# auto detect if not specified via the --with-efivar option.
AC_ARG_WITH([efivar],
  AS_HELP_STRING([--with-efivar], [Build with lib efivar for pretty print of device path. Default auto detect]),
  ,
  with_efivar=auto
)

# use the true program to avoid failing hard
AS_IF([test "x$with_efivar" = "xauto"],
  [PKG_CHECK_MODULES([EFIVAR], [efivar], [AC_CHECK_HEADERS([efivar/efivar.h], , [true])], [true])],
  [test "x$with_efivar" = "xyes"],
  [PKG_CHECK_MODULES([EFIVAR], [efivar], [AC_CHECK_HEADERS([efivar/efivar.h])])],
)

AC_CHECK_HEADERS([efivar/efivar.h],[efivar_h=yes ], [efivar = no ])
AM_CONDITIONAL([HAVE_EFIVAR_H], [test "$efivar_h" = yes])

# backwards compat with older pkg-config
# - pull in AC_DEFUN from pkg.m4
m4_ifndef([PKG_CHECK_VAR], [
# PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
# [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------
# Retrieves the value of the pkg-config variable for the given module.
AC_DEFUN([PKG_CHECK_VAR],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl

_PKG_CONFIG([$1], [variable="][$3]["], [$2])
AS_VAR_COPY([$1], [pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])dnl
])# PKG_CHECK_VAR
])

AC_ARG_WITH([bashcompdir],
            AS_HELP_STRING([--with-bashcompdir=DIR], [directory for bash completions]), ,
            [PKG_CHECK_VAR([with_bashcompdir], [bash-completion], [completionsdir], ,
                           [with_bashcompdir="${datarootdir}/bash-completion/completions"])])
AC_SUBST(bashcompdir, [$with_bashcompdir])

AC_ARG_WITH([tpmsim],
            AS_HELP_STRING([--with-tpmsim=BIN], [simulator used for testing]),
            [],
            [])
AC_SUBST(tpmsim, [$with_tpmsim])

AC_CANONICAL_HOST

# Check OS and set library and compile flags accordingly
case "${host_os}" in
    *nto-qnx*)
        EXTRA_CFLAGS="$EXTRA_CFLAGS -D_QNX_SOURCE"
        LIBDL_LDFLAGS=""
        ;;
    *)
        LIBDL_LDFLAGS="-ldl"
        ;;
esac
AC_SUBST([LIBDL_LDFLAGS])

AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests])],,
            [enable_unit=no])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])

AC_ARG_ENABLE([persistent],
            [AS_HELP_STRING([--disable-persistent],
                            [disable tests that require resetting the TPM])],,)
AM_CONDITIONAL([PERSISTENT], [test "x$enable_persistent" != xno])

dnl macro that checks for specific modules in python
AC_DEFUN([AC_PYTHON_MODULE],
[AC_MSG_CHECKING([for module $1 in $PYTHON])
  echo "import $1" | $PYTHON - 2>/dev/null
  if test $? -ne 0 ; then
    AC_MSG_ERROR([not found])
  else
    AC_MSG_RESULT(found)
  fi
])

# Check OS and set library and compile flags accordingly
case "${host_os}" in
    *bsd* | *BSD*)
        HOSTOS='BSD'
        ;;
    *)
        #Assume linux
        HOSTOS='Linux'
        ;;
esac

AS_IF([test "x$enable_unit" != xno], [
    PKG_CHECK_MODULES([CMOCKA],[cmocka])

    AC_CHECK_PROG([tpm2_abrmd], [tpm2-abrmd], yes, no)
    AS_IF([test $tpm2_abrmd = yes],
	  [TPM2_ABRMD=tpm2-abrmd],
          [AC_MSG_ERROR([Required executable tpm2_abrmd not found, try setting PATH])]
    )
    AC_SUBST([TPM2_ABRMD])

	AS_IF([test -z "$tpmsim"], [
        AC_CHECK_PROG([swtpm], [swtpm], yes, no)
        AC_CHECK_PROG([tpm_server], [tpm_server], yes, no)
        AS_IF([test $swtpm = yes], [TPM2_SIM=swtpm],
          [AS_IF([test $tpm_server = yes], [TPM2_SIM=tpm_server],
                 [AC_MSG_ERROR([Required executables swtpm or tpm_server not found, try setting PATH])])])
        ],
        [
        AC_CHECK_PROG([HAS_TPM2_SIM], [$tpmsim], yes, no)
        AS_IF([test "$HAS_TPM2_SIM" = yes],
            [TPM2_SIM=$tpmsim],
            [AC_MSG_ERROR([Required executable $tpmsim not found, system tests require a tpm simulator shell!])]
        )
        ]
    )
    AC_SUBST([TPM2_SIM])

    AC_CHECK_PROG([BASH_SHELL], [bash], yes, no)
    AS_IF([test $BASH_SHELL = no],
          [AC_MSG_ERROR([Required executable bash not found, system tests require a bash shell!])])

    AM_PATH_PYTHON([],
        [],
        [AC_MSG_ERROR([Required executable python not found, some system tests will fail!])]
    )

    AC_PYTHON_MODULE([yaml])

    AC_CHECK_PROG([XXD], [xxd], yes, no)
    AS_IF([test $XXD = no],
          [AC_MSG_ERROR([Required executable xxd not found, some system tests will fail!])])
    AS_IF([test "$HOSTOS" = "Linux"],
           [AC_CHECK_PROG([SS], [ss], [yes], [no])],
           [AC_CHECK_PROG([SS], [sockstat], [yes], [no])])
    AS_IF([test $SS = no],
          [AC_MSG_ERROR([Required executable ss/sockstat not found, some system tests will fail!])])

    AC_CHECK_PROG([SHASUM], [shasum], yes, no)
    AS_IF([test $SHASUM = no],
          [AC_MSG_ERROR([Required executable shasum not found, some system tests will fail!])])

    AC_CHECK_PROG([MKTEMP], [mktemp], yes, no)
    AS_IF([test $MKTEMP = no],
          [AC_MSG_ERROR([Required executable mktemp not found, some system tests will fail!])])

    AC_CHECK_PROG([EXPECT], [expect], yes, no)
    AS_IF([test $EXPECT = no],
          [AC_MSG_ERROR([Required executable expect not found, some system tests will fail!])])

    AC_CHECK_PROG([OPENSSL], [openssl], yes, no)
    AS_IF([test $OPENSSL = no],
          [AC_MSG_ERROR([Required executable openssl not found, some system tests will fail!])])

    AC_CHECK_PROG([WC], [wc], yes, no)
    AS_IF([test $WC = no],
          [AC_MSG_ERROR([Required executable wc not found, some system tests will fail!])])

    unit_test_tool_report="- tpm2_abrmd: $tpm2_abrmd
    - TPM simulator: $TPM2_SIM
    - bash: $BASH_SHELL
    - python: $PYTHON
    - xxd: $XXD
    - ss: $SS
    - shasum: $SHASUM
    - mktemp: $MKTEMP
    - expect: $EXPECT
    - openssl: $OPENSSL"
])

AC_ARG_ENABLE([dlclose],
  [AS_HELP_STRING([--disable-dlclose],
                            [Some versions of libc cause a sigsegv on exit, this disables the dlclose and works around that bug])],
  [AC_DEFINE([DISABLE_DLCLOSE], [1],
  [Some versions of libc cause a sigsegv on exit with dlclose(), this disables the dlclose()
  and works around that bug])]
 )

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening],
    [Disable compiler and linker options to frustrate memory corruption exploits])],,
  [enable_hardening="yes"])

# Good information on adding flags, and dealing with compilers can be found here:
#   https://github.com/zcash/zcash/issues/1832
#   https://github.com/kmcallister/autoharden/
AS_IF([test x"$enable_hardening" != x"no"], [

  AC_DEFUN([add_hardened_c_flag], [
    AX_CHECK_COMPILE_FLAG([$1],
      [EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  AC_DEFUN([add_hardened_ld_flag], [
    AX_CHECK_LINK_FLAG([$1],
      [EXTRA_LDFLAGS="$EXTRA_LDFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  AC_DEFUN([add_hardened_define_flag], [
    AX_CHECK_PREPROC_FLAG([$1],
      [EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],
      [AC_MSG_ERROR([Cannot enable $1, consider configuring with --disable-hardening])]
    )
  ])

  add_hardened_c_flag([-Wall])
  add_hardened_c_flag([-Wextra])
  AS_IF([test "x$ax_is_release" = "xno"], [add_hardened_c_flag([-Werror])])

  add_hardened_c_flag([-Wformat])
  add_hardened_c_flag([-Wformat-security])
  add_hardened_c_flag([-Wstack-protector])
  add_hardened_c_flag([-fstack-protector-all])
  add_hardened_c_flag([-Wstrict-overflow=5])

  add_hardened_c_flag([-O2])
  AX_ADD_FORTIFY_SOURCE

  add_hardened_c_flag([-fPIC])
  add_hardened_ld_flag([[-shared]])

  add_hardened_c_flag([-fPIE])
  add_hardened_ld_flag([[-pie]])

  add_hardened_ld_flag([[-Wl,-z,relro]])
  add_hardened_ld_flag([[-Wl,-z,now]])

], [
  AC_MSG_WARN([Compiling with --disable-hardening is dangerous!
you should consider fixing the configure script compiler flags
and submitting patches upstream!])
])

AC_DEFUN([add_c_flag], [
  AX_CHECK_COMPILE_FLAG([$1],
    [EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],
    $2
  )
])

# -D_GNU_SOURCE is required for execvpe() in options.c
add_c_flag([-D_GNU_SOURCE], [AC_MSG_ERROR([Cannot enable -D_GNU_SOURCE])])

# Enable gnu99 mode, since we use some of these features.
add_c_flag([-std=gnu99], [AC_MSG_ERROR([Cannot enable -std=gnu99])])

# Best attempt compiler options that are on newer versions of GCC that
# we can't widely enforce without killing other peoples builds.
# Works with gcc only. Needs to be disabled on BSD and clang
AS_IF([test "$HOSTOS" = "Linux"],
      [add_c_flag([-Wstringop-overflow=4])
       add_c_flag([-Wstringop-truncation])
       add_c_flag([-Wduplicated-branches])
       add_c_flag([-Wduplicated-cond])
       add_c_flag([-Wbool-compare])],[])

# Best attempt, strip unused stuff from the binary to reduce size.
# Rather than nesting these and making them ugly just use a counter.
AX_CHECK_COMPILE_FLAG([-fdata-sections], [strip="${strip}y"])
AX_CHECK_COMPILE_FLAG([-ffunction-sections], [strip="${strip}y"])
AX_CHECK_LINK_FLAG([[-Wl,--gc-sections]], [strip="${strip}y"])

AS_IF([test x"$strip" = x"yyy"], [
  EXTRA_CFLAGS="$EXTRA_CFLAGS -fdata-sections -ffunction-sections"
  EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,--gc-sections"
],
  AC_MSG_NOTICE([Not using compiler options to reduce binary size!])
)

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])
AC_SUBST([PATH])

AC_OUTPUT

AC_MSG_RESULT([
    - $PACKAGE_NAME: $VERSION
    - Man pages: ${PANDOC:-no}
    - Unit tests: $enable_unit
    $unit_test_tool_report
])
