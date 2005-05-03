#!make
# $Id$
#
# Copyright (c) 1999-2002 Steven Bakker
# All rights reserved
#
# Notes:
#	All you'll probably ever need to edit is in `config.mk'
#
# ============================================================================

TOPDIR	=	.

include $(TOPDIR)/config.mk
include $(TOPDIR)/rules.mk

default		:	all

all			:	sbin-all init.d-all man-all lib-all

install		:	sbin-install init.d-install man-install lib-install

clean		:	sbin-clean init.d-clean man-clean lib-clean

veryclean	:	sbin-veryclean init.d-veryclean man-veryclean lib-veryclean
