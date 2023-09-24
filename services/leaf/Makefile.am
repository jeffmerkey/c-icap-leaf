CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@

cicapmodule_LTLIBRARIES=srv_leaf.la

AM_CPPFLAGS=-I$(top_srcdir)/ -I$(top_srcdir)/include/ 

srv_leaf_la_LIBADD = @MODULES_LIBADD@
srv_leaf_la_CFLAGS=  -I/usr/include/mysql/ -I../../include/  
srv_leaf_la_LDFLAGS= -module -avoid-version -L/usr/lib64/mysql/ -lmysqlclient -lpthread
srv_leaf_la_SOURCES = srv_main.c srv_leaf.c srv_strstr.c


