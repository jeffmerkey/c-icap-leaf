dnl Process this file with autoconf to produce a configure script.


dnl AC_INIT(c_icap_leaf,m4_normalize(m4_include([VERSION.m4])))
AC_INIT(c_icap_leaf, 0.5.5)

AM_MAINTAINER_MODE
AM_CONFIG_HEADER(autoconf.h)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AM_PROG_CC_C_O
AC_C_BIGENDIAN

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

CFLAGS="$CFLAGS -Wall"

#check for c-icap
AC_ARG_WITH(c-icap,
[  --with-c-icap	Where to find c-icap ],
[
    cicapdir="$withval"
    if test -f $withval/bin/c-icap-config; then
       cicapflags=`$withval/bin/c-icap-config --cflags`
       cicaplibs=`$withval/bin/c-icap-config --libs`
       cicapetc=`$withval/bin/c-icap-config --configdir`
       cicapprefix=`$withval/bin/c-icap-config --prefix`
       cicapmods=`$withval/bin/c-icap-config --modulesdir`
       cicapdatadir=`$withval/bin/c-icap-config --datarootdir`
       cicaplibflags=`$withval/bin/c-icap-libicapapi-config --cflags`
       cicapliblibs=`$withval/bin/c-icap-libicapapi-config --libs`
    else
       cicapflags=`c-icap-config --cflags`
       cicaplibs=`c-icap-config --libs`
       cicapetc=`c-icap-config --configdir`
       cicapprefix=`c-icap-config --prefix`
       cicapmods=`c-icap-config --modulesdir`
       cicapdatadir=`c-icap-config --datarootdir`
       cicaplibflags=`c-icap-libicapapi-config --cflags`
       cicapliblibs=`c-icap-libicapapi-config --libs`
    fi
],
)

if test -z "$cicapdir"; then
    if c-icap-config >& /dev/null; then
        cicapflags=`c-icap-config --cflags`
        cicaplibs=`c-icap-config --libs`
        cicapetc=`c-icap-config --configdir`
        cicapprefix=`c-icap-config --prefix`
        cicapmods=`c-icap-config --modulesdir`
        cicapdatadir=`c-icap-config --datarootdir`
        cicaplibflags=`c-icap-libicapapi-config --cflags`
        cicapliblibs=`c-icap-libicapapi-config --libs`
    else
        echo "ERROR: c-icap-config not found!"
	exit -1;
    fi
fi

AM_CONDITIONAL(CICAPMODULESDIR, [test -n $cicapmods])

CFLAGS="$CFLAGS $cicapflags"
MODULES_LIBADD="$cicaplibs"
UTILITIES_LIBADD="$cicapliblibs"
UTILITIES_CFLAGS="$cicaplibflags"
CONFDIR="$cicapetc"
MODSDIR="$cicapmods"
DATADIR="$cicapdatadir"
AC_SUBST(MODULES_LIBADD)
AC_SUBST(UTILITIES_LIBADD)
AC_SUBST(UTILITIES_CFLAGS)
AC_SUBST(CONFDIR)
AC_SUBST(MODSDIR)
AC_SUBST(DATADIR)

#Check for icapapi functions
OLD_LIBS=$LIBS
LIBS="$LIBS $cicapliblibs"
AC_CHECK_LIB(icapapi, ci_brinflate_to_simple_file, [cicap_brotli='yes';AC_DEFINE(HAVE_CICAP_BROTLI, 1,Define HAVE_CICAP_BROTLI if c-icap supports brotli)], [cicap_brotli='no'])
AC_CHECK_LIB(icapapi, ci_decompress_to_simple_file, [cicap_decompress_to='yes';AC_DEFINE(HAVE_CICAP_DECOMPRESS_TO, 1,Define HAVE_CICAP_DECOMPRESS_TO if c-icap has ci_decompress_to_ family functions)], [cicap_decompress_to='no'])
AC_CHECK_LIB(icapapi, ci_decompress_error, [cicap_decompress_error='yes';AC_DEFINE(HAVE_CICAP_DECOMPRESS_ERROR, 1,Define HAVE_CICAP_DECOMPRESS_ERROR if c-icap has ci_decompress_error function)], [cicap_decompress_error='no'])
LIBS=$OLD_LIBS

# Checks for libraries

###############
# Detect Berkeley DB library
libdb="yes"
libdbpath=""
AC_ARG_WITH(bdb,
[  --with-bdb        Where to find Berkeley DB library ],
[ case "$withval" in
    yes)
         libdb="yes"
    ;;
    no )
         libdb="no"
    ;;
    * )
        libdb="yes"
        libdbpath=$withval
    ;;
  esac
],
)

if test a"$libdb" != "ano"; then
   #  Save old CFLAGS/LDFLAGS
   OLDCFLAGS=$CFLAGS
   OLDLDFLAGS=$LDFLAGS
   OLDLIBS=$LIBS

   if test "a$libdbpath" != "a"; then
      CFLAGS="-I$libdbpath/include $CFLAGS"
      LDFLAGS="-L$libdbpath/lib $LDFLAGS"
   fi
   # We are going to see if we can found a Berkeley DB located under a
   # libdbpath/include/db4x directory and use lbdbpath/lib/libdb-4.x library.
   for DBVER in "" 6 6.3 6.2 6.1 6.0 5 5.4 5.3 5.2 5.1 5.0 4 4.9 4.8 4.7 4.6 4.5 4.4 4.3 4.2; do
        if test -z $DBVER; then
           usedblib="-ldb"
           incdbdir=""
        else
           usedblib="-ldb-$DBVER"
           incdbdir=db`echo $DBVER|sed 's/\.//'`"/"
        fi
        if test -z "$libdbpath"; then
           print_libdbpath="..."
        else
            print_libdbpath="under $libdbpath..."
        fi
        echo -n "checking for BerleleyDB v$DBVER $print_libdbpath"
        LIBS="$usedblib $OLD_LIBS"
        AC_LINK_IFELSE(
               [AC_LANG_SOURCE(
                 [
                     #include <${incdbdir}db.h>
                     int main(){
                        int major,minor,patch;
                        if (!db_version(&major,&minor,&patch))
                             return -1;
                        return 0;
                     }
                  ])
               ],
               [echo yes;libdb="yes";],
               [echo "no";libdb="no";]
        )

        if test a"$libdb" = "ayes"; then
           BDB_ADD_LDADD=""
           BDB_ADD_FLAG=""
           if test "a$libdbpath" != "a"; then
                BDB_ADD_LDADD="-L$libdbpath/lib "
                BDB_ADD_FLAG="-I$libdbpath/include"
           fi
           BDB_ADD_LDADD="$BDB_ADD_LDADD$usedblib"
           AC_SUBST(BDB_ADD_LDADD)
           AC_SUBST(BDB_ADD_FLAG)
           AC_DEFINE(HAVE_BDB, 1, [Define HAVE_BDB if berkeley DB is installed])
           AC_DEFINE_UNQUOTED(BDB_HEADER_PATH(incfile), [<${incdbdir}incfile>], [Set DB_HEADER_PATH macro to compute berkeley DB header subpath])
           break;
        fi
   done

   CFLAGS=$OLDCFLAGS
   LDFLAGS=$OLDLDFLAGS
   LIBS=$OLDLIBS
fi

if test a"$libdb" = "ayes"; then
    AC_DEFINE(HAVE_BDB, 1, [Define HAVE_BDB if berkeley DB is installed])
fi

AC_MSG_CHECKING([if fds can send through unix sockets])
AC_TRY_COMPILE(
       [
      #include <stdlib.h>
      #include <sys/socket.h>
      #include <sys/un.h>
       ],
      [
      int main(int argc, char **argv) {
             struct msghdr mh;
             struct cmsghdr cmh;
             mh.msg_control = NULL;
             mh.msg_controllen = 0;
             cmh.cmsg_level = SOL_SOCKET;
             cmh.cmsg_type = SCM_RIGHTS;
      }
      ],
AC_DEFINE(HAVE_FD_PASSING,1,[Define HAVE_FD_PASSING if sending fd through unix socket supported])
AC_MSG_RESULT(yes),
AC_MSG_RESULT(no),
)

# Check for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(ctype.h)

AC_CHECK_FUNCS(strcasestr,
AC_DEFINE(HAVE_STRCASESTR,1,[Define HAVE_STRCASESTR if strcasestr exists])
)

# Now determine which modules will going to build .....

AM_CONDITIONAL(USEBDB,   [test a"$libdb" != ano])

AC_OUTPUT([Makefile services/Makefile services/leaf/Makefile services/leafinfo/Makefile modules/Makefile])

