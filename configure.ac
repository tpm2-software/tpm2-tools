AC_INIT([tpm2.0-tools], [1.0.0])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
AC_CHECK_HEADER([openssl/sha.h],
                [
                 AC_DEFINE([HAVE_OPENSSL_H],
                           [1],
                           [Define if sha.h exists.])
                 ],
                [AC_MSG_ERROR([Missing OPENSSL headers.])])
AC_CHECK_HEADER([curl/curl.h],
                [
                 AC_DEFINE([HAVE_CURL_H],
                           [1],
                           [Define if curl.h exists.])
                 ],
                [AC_MSG_ERROR([Missing CURL headers.])])
PKG_CHECK_MODULES([SAPI],[sapi])
PKG_CHECK_MODULES([TCTI_SOCK],[tcti-socket])
PKG_CHECK_MODULES([TCTI_DEV],[tcti-device])
AC_OUTPUT
