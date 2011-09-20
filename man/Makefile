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

SECTION		=	8

TARGETS		=	\
			$(NAME).pod \
			$(NAME).$(SECTION) \
			asctl.pod \
			aslogtail.pod \
			asctl.$(SECTION) \
			aslogtail.$(SECTION)

INSTALLFILES	=	\
			$(MANDIR)/man$(SECTION)/$(NAME).$(SECTION) \
			$(MANDIR)/man$(SECTION)/asctl.$(SECTION) \
			$(MANDIR)/man$(SECTION)/aslogtail.$(SECTION)

include ../rules.mk

$(NAME).pod: ../sbin/$(NAME)
	$(RM) -f $@
	ln -s $? $@

asctl.pod: ../sbin/asctl
	$(RM) -f $@
	ln -s $? $@

aslogtail.pod: ../sbin/aslogtail
	$(RM) -f $@
	ln -s $? $@

#	cd $(TOPDIR); $(MAKE) $@

# E.O.F. Makefile
