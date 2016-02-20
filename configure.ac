AC_INIT([tpm2.0-tools], [1.0.0])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
AC_CHECK_HEADER([tss2/tpm20.h],
                [
                 AC_DEFINE([HAVE_TPM20_H],
                           [1],
                           [Define if tpm20.h exists.])
                 ],
                [AC_MSG_ERROR([Missing TSS2 headers.])])
AC_CHECK_HEADER([tcti/tcti_socket.h],
                [
                 AC_DEFINE([HAVE_TCTI_SOCKET_H],
                           [1],
                           [Define if tcti_socket.h exists.])
                 ],
                [AC_MSG_ERROR([Missing TCTI socket header.])],
                [#include <tss2/tpm20.h>])
AC_OUTPUT
