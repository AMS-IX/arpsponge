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
			arpswiffer.pod \
			arpswiffer.$(SECTION)

INSTALLFILES	=	\
			$(MANDIR)/man$(SECTION)/arpswiffer.$(SECTION)

include ../rules.mk

arpswiffer.pod: ../sbin/arpswiffer
	$(RM) -f arpswiffer.pod
	ln -s ../sbin/arpswiffer arpswiffer.pod

# E.O.F. Makefile
