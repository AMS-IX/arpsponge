#!make
#
# $Id$
#
#  (c) Copyright 2005 Steven Bakker, AMS-IX B.V.
#
#  See the LICENSE file that came with this package.
#
include ../config.mk

TOPDIR		=	..

INITDIR		=	$(DESTDIR)/etc/init.d
INSTALLDIRS	=	$(DESTDIR)/etc/init.d \
				$(DESTDIR)/etc/rc0.d \
				$(DESTDIR)/etc/rc1.d \
				$(DESTDIR)/etc/rc2.d \
				$(DESTDIR)/etc/rc3.d \
				$(DESTDIR)/etc/rc4.d \
				$(DESTDIR)/etc/rc5.d \
				$(DESTDIR)/etc/rc6.d

INSTALLINKS	=	\
				$(DESTDIR)/etc/rc0.d/K80arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc1.d/K80arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc2.d/S30arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc3.d/S30arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc4.d/S30arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc5.d/S30arpswiffer:../init.d/arpswiffer \
				$(DESTDIR)/etc/rc6.d/K80arpswiffer:../init.d/arpswiffer

TARGETS		=	\
			arpswiffer

INSTALLFILES	=	\
			$(INITDIR)/arpswiffer

include ../rules.mk

# E.O.F. Makefile
