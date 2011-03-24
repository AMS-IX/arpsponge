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

INSTALLDIRS	=	$(BINDIR)

TARGETS		=	\
			arpsponge \
			asctl

INSTALLFILES	=	\
			$(BINDIR)/arpsponge \
			$(BINDIR)/asctl

include ../rules.mk

bla: arpsponge.pl Makefile
	@ echo expanding
	@ $(perlit) arpsponge.pl > bla

# E.O.F. Makefile
