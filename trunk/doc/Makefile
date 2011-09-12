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

TARGETS		= 

# debian/rules specifies make instlal SKIPDOCS=1 to
# prevent us from installing docs. The debian/docs
# file will take care of that.
ifndef SKIPDOCS

INSTALLDIRS = $(DOCDIR)

INSTALLFILES	= \
			$(DOCDIR)/arpsponge_architecture.txt \
			$(DOCDIR)/command_mapping.txt

endif

include ../rules.mk

# E.O.F. Makefile
