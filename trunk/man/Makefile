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
			$(NAME).$(SECTION)

INSTALLFILES	=	\
			$(MANDIR)/man$(SECTION)/$(NAME).$(SECTION)

include ../rules.mk

$(NAME).pod: ../sbin/$(NAME)
	$(RM) -f $(NAME).pod
	ln -s ../sbin/$(NAME) $(NAME).pod

# E.O.F. Makefile
