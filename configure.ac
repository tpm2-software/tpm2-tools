AC_INIT([tpm2.0-tools], [1.0.0])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
AC_CHECK_LIB([tss2], [Tss2_Sys_GetContextSize], [],
             [AC_MSG_ERROR([Missing TSS2 library.])], [])
AC_OUTPUT
