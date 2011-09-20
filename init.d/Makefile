#!make
#
# $Id$
#
#  (c) Copyright 2005-2011 AMS-IX B.V.
#
#  This is free software. It can be distributed under
#  your choice of the GPL or Artistic License 2.0.
#
#  See the Copying file that came with this package.
#
include ../config.mk

TOPDIR		=	..

INITDIR		=	$(DESTDIR)/etc/init.d

XINSTALLDIRS	=	$(DESTDIR)/etc/init.d \
				$(DESTDIR)/etc/rc0.d \
				$(DESTDIR)/etc/rc1.d \
				$(DESTDIR)/etc/rc2.d \
				$(DESTDIR)/etc/rc3.d \
				$(DESTDIR)/etc/rc4.d \
				$(DESTDIR)/etc/rc5.d \
				$(DESTDIR)/etc/rc6.d

XINSTALLINKS	=	\
				$(DESTDIR)/etc/rc0.d/K80$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc1.d/K80$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc2.d/S30$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc3.d/S30$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc4.d/S30$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc5.d/S30$(NAME):../init.d/$(NAME) \
				$(DESTDIR)/etc/rc6.d/K80$(NAME):../init.d/$(NAME)

TARGETS		=	\
			$(NAME)

INSTALLFILES	=	\
			$(INITDIR)/$(NAME)

include ../rules.mk

# E.O.F. Makefile
