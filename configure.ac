AC_PREREQ([2.68])
AC_INIT(rlm_attr_log.c)
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_attr_log])

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.
	FR_SMART_CHECK_LIB(c, printf)
	if test "x$ac_cv_lib_c_printf" != "xyes"; then
		fail="$fail libc"
	fi

	FR_SMART_CHECK_INCLUDE(stdio.h)
	if test "$ac_cv_header_stdio_h" != "yes"; then
		fail="$fail stdio.h"
	fi
	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
