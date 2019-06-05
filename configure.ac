AC_INIT([tpm2-tools],
    [m4_esyscmd_s([git describe --tags --always --dirty])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])
# enable "silent-rules" option by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_FILES([Makefile])
AC_CHECK_PROG([PANDOC],[pandoc],[yes])
AS_IF(
    [test "x${PANDOC}" = x"yes"],
    [],
    [AC_MSG_WARN([Required executable pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC],[test "x${PANDOC}" = "xyes"])
AM_CONDITIONAL(
    [HAVE_MAN_PAGES],
    [test -d "${srcdir}/man/man1" -o "x${PANDOC}" = "xyes"])
PKG_CHECK_MODULES([SAPI],[tss2-sys >= 2.0 tss2-sys < 3.0 tss2-mu >= 2.0 tss2-mu < 3.0])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.2g])
PKG_CHECK_MODULES([CURL],[libcurl])
AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests (default is no)])],
            [enable_unit=$enableval],
            [enable_unit=no])
AS_IF([test "x$enable_unit" != xno],
      [PKG_CHECK_MODULES([CMOCKA],
                         [cmocka],
                         [AC_DEFINE([HAVE_CMOCKA],
                                    [1])])])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])

# Good information on adding flags, and dealing with compilers can be found here:
#   https://github.com/zcash/zcash/issues/1832
#   https://github.com/kmcallister/autoharden/
AS_IF([test x"$hardening" != x"no"], [

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
  add_hardened_c_flag([-Werror])

  add_hardened_c_flag([-Wformat])
  add_hardened_c_flag([-Wformat-security])
  add_hardened_c_flag([-Wstack-protector])
  add_hardened_c_flag([-fstack-protector-all])

  add_hardened_define_flag([-U_FORTIFY_SOURCE])
  add_hardened_define_flag([-D_FORTIFY_SOURCE=2])

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

# -D_GNU_SOURCE is required for execvpe() in options.c
AX_CHECK_PREPROC_FLAG([-D_GNU_SOURCE],
  [EXTRA_CFLAGS="$EXTRA_CFLAGS -D_GNU_SOURCE"],
  [AC_MSG_ERROR([Cannot enable -D_GNU_SOURCE])]
)

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

AC_CHECK_PROG([BASH_SHELL],[bash],[yes])
AS_IF(
    [test "x${BASH_SHELL}" = x"yes"],
    [],
    [AC_MSG_WARN([Required executable bash not found, system tests require a bash shell!])])

AC_CHECK_PROG([PYTHON],[python],[yes])
AS_IF(
    [test "x${PYTHON}" = x"yes"],
    [],
    [AC_MSG_WARN([Required executable python not found, some system tests will fail!])])

dnl macro that checks for specific modules in python
AC_DEFUN([AC_PYTHON_MODULE],
[AC_MSG_CHECKING([for module $1 in python])
  echo "import $1" | python -
  if test $? -ne 0 ; then
    AC_MSG_RESULT([not found])
    AC_MSG_WARN([System tests require pyyaml, some tests will fail!])
  fi
AC_MSG_RESULT(found)
])

AC_PYTHON_MODULE([yaml])

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
