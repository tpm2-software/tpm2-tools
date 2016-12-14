AC_INIT([tpm2.0-tools], [1.1.0])
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
# ensure we have at least one TCTI enabled, can't do much without one
AS_IF(
    [test "x$with_tcti_device" != "xyes" -a "x$with_tcti_socket" != "xyes"],
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
AC_OUTPUT
