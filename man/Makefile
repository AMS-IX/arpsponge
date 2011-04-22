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
	$(RM) -f $(NAME).pod
	ln -s ../sbin/$(NAME) $(NAME).pod

%.pod: ../sbin/%
	$(RM) -f $@
	ln -s $? $@

# E.O.F. Makefile
