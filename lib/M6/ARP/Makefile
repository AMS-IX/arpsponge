# $Id$
#
#  (c) Copyright 2005-2011 AMS-IX B.V.
#
#  This is free software. It can be distributed under
#  your choice of the GPL or Artistic License 2.0.
#
#  See the Copying file that came with this package.
#
TOPDIR		=	../../..

include $(TOPDIR)/config.mk


INSTALLDIR	=	$(INSTLIB)/M6/ARP

INSTALLFILES		=	\
		$(INSTALLDIR)/Base.pm \
		$(INSTALLDIR)/Const.pm \
		$(INSTALLDIR)/Control.pm \
		$(INSTALLDIR)/Event.pm \
		$(INSTALLDIR)/Log.pm \
		$(INSTALLDIR)/NetPacket.pm \
		$(INSTALLDIR)/Queue.pm \
		$(INSTALLDIR)/Sponge.pm \
		$(INSTALLDIR)/Table.pm \
		$(INSTALLDIR)/Util.pm

include $(TOPDIR)/rules.mk

all			:	Control-all

install		:	Control-install

clean		:	Control-clean

veryclean	:	Control-veryclean

# E.O.F. Makefile
