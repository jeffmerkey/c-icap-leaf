CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@

cicapmodule_LTLIBRARIES=srv_leafinfo.la

AM_CPPFLAGS=-I$(top_srcdir)/ -I$(top_srcdir)/include/ 

srv_leafinfo_la_LIBADD = @MODULES_LIBADD@
srv_leafinfo_la_CFLAGS=  -I/usr/include/mysql/ -I../../include/  
srv_leafinfo_la_LDFLAGS= -module -avoid-version  
srv_leafinfo_la_SOURCES = leafinfo.c


