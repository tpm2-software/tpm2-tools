AC_INIT([tpm2.0-tools], [1.0.0])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
PKG_CHECK_MODULES([SAPI],[sapi])
PKG_CHECK_MODULES([TCTI_SOCK],[tcti-socket])
PKG_CHECK_MODULES([TCTI_DEV],[tcti-device])
PKG_CHECK_MODULES([CURL],[libcurl libcrypto])
PKG_CHECK_MODULES([CMOCKA],[cmocka])
AC_OUTPUT
