#!make
#
#  Copyright 2005-2016 AMS-IX B.V.
#
#  This is free software. It can be distributed under
#  your choice of the GPL or Artistic License 2.0.
#
#  See the Copying file that came with this package.
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
