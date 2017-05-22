AC_INIT([tpm2.0-tools],
    [m4_esyscmd_s([git describe --tags --always --dirty])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
PKG_CHECK_MODULES([SAPI],[sapi])
# disable libtcti-device selectively (enabled by default)
AC_ARG_WITH(
    [tcti-device],
    [AS_HELP_STRING([--with-tcti-device],
        [Build tools with support for the device TCTI.])],
    [],
    [with_tcti_device=check])
AS_IF(
    [test "x$with_tcti_device" != "xno"],
    [PKG_CHECK_MODULES(
        [TCTI_DEV],
        [tcti-device],
        [AC_DEFINE([HAVE_TCTI_DEV],[1])
         with_tcti_device=yes],
        [if test "x$with_tcti_device" = "xyes"; then
             AC_MSG_FAILURE([--with-tcti-device option provided but libtcti-device not detected.])
         fi])])
AM_CONDITIONAL([HAVE_TCTI_DEV],[test "x$with_tcti_device" = "xyes"])
# disable libtcti-socket selectively (enabled by default)
AC_ARG_WITH(
    [tcti-socket],
    [AS_HELP_STRING([--with-tcti-socket],
        [Build tools with support for the socket TCTI.])],
    [],
    [with_tcti_socket=check])
AS_IF(
    [test "x$with_tcti_socket" != "xno"],
    [PKG_CHECK_MODULES(
        [TCTI_SOCK],
        [tcti-socket],
        [AC_DEFINE([HAVE_TCTI_SOCK],[1])
         with_tcti_socket=yes],
        [if test "x$with_tcti_socket" = "xyes"; then
             AC_MSG_FAILURE([--with-tcti-socket option provided but libtcti-socket not detected.])
         fi])])
AM_CONDITIONAL([HAVE_TCTI_SOCK],[test "x$with_tcti_socket" = "xyes"])
# selectively disable libtcti-tabrmd
AC_ARG_WITH(
    [tcti-tabrmd],
    [AS_HELP_STRING([--with-tcti-tabrmd],
        [Build tools with support for the tabrmd TCTI.])],
    [],
    [with_tcti_tabrmd=check])
AS_IF(
    [test "x$with_tcti_tabrmd" != "xno"],
    [PKG_CHECK_MODULES(
        [TCTI_TABRMD],
        [tcti-tabrmd],
        [AC_DEFINE([HAVE_TCTI_TABRMD], [1])
         with_tcti_tabrmd=yes],
        [if test "x$with_tcti_tabrmd" = "xyes"; then
             AC_MSG_FAILURE([--with-tcti-tabrmd option provided but libtcti-tabrmd not detected.])
         fi])])
AM_CONDITIONAL([HAVE_TCTI_TABRMD],[test "x$with_tcti_tabrmd" = "xyes"])
# ensure we have at least one TCTI enabled, can't do much without one
AS_IF(
    [test "x$with_tcti_device" != "xyes" -a \
          "x$with_tcti_socket" != "xyes" -a \
          "x$with_tcti_tabrmd" != "xyes"],
    [AC_MSG_ERROR(
        [no TCTIs: at least one TCTI library must be enabled],
        [1])])
PKG_CHECK_MODULES([CURL],[libcurl libcrypto])
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
AX_CHECK_COMPILE_FLAG([-fdata-sections], [strip+="y"])
AX_CHECK_COMPILE_FLAG([-ffunction-sections], [strip+="y"])
AX_CHECK_LINK_FLAG([[-Wl,--gc-sections]], [strip+="y"])

AS_IF([test x"$strip" == x"yyy"], [
  EXTRA_CFLAGS="$EXTRA_CFLAGS -fdata-sections -ffunction-sections"
  EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,--gc-sections"
],
  AC_MSG_NOTICE([Not using compiler options to reduce binary size!])
)

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
