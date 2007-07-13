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

TARGETS = defaults.sample

default		:	all

all			:	$(TARGETS) sbin-all init.d-all man-all lib-all

install		:	all sbin-install init.d-install man-install lib-install

clean		:	sbin-clean init.d-clean man-clean lib-clean

veryclean	:	sbin-veryclean init.d-veryclean man-veryclean lib-veryclean

#NODIST

dist:
	@echo "creating distribution:"
	@echo "creating temporary area.."; \
	    DIR=`pwd`; \
	    PID=$$$$; \
	    $(RM) -r /tmp/$(PACKAGE).$$PID; \
	    mkdir -p /tmp/$(PACKAGE).$$PID/$(PACKAGE); \
	    \
	    echo "copying sources.."; \
	    tar cf /tmp/$(PACKAGE).$$PID/$(PACKAGE)/dist.tar .; \
	    cd /tmp/$(PACKAGE).$$PID/$(PACKAGE); \
	    tar xf dist.tar; \
	    $(RM) dist.tar; \
	    \
	    echo "cleaning it up"; \
	    make clean >/dev/null 2>&1; \
	    chmod -R u+w,go-w .; \
	    $(RM) -r ./junk; \
	    $(RM) installed.log; \
	    $(RM) tools/mkdist; \
	    find . \( -name '*.src' -o -name '*.tar' \) -exec $(RM) '{}' ';' ;\
	    find . \( -name '*.gz' -o -name '*.Z' \) -exec $(RM) '{}' ';' ;\
	    find . -depth -type d -name CVS -exec $(RM) -r '{}' ';' ;\
	    find . -depth -type d -name .svn -exec $(RM) -r '{}' ';' ;\
	    $(RM) -r ./old ;\
	    $$DIR/tools/mkdist Makefile > Makefile.dist; \
			mv Makefile.dist Makefile; \
	    $$DIR/tools/mkdist config.mk > config.mk.dist; \
			rm config.mk; \
	    \
	    echo "tarring and zipping it up"; \
	    cd ..; \
	    tar cf - ./$(PACKAGE) | \
		gzip -9 > $$DIR/$(PACKAGE).tar.gz; \
	    \
	    echo "cleaning up temporaries"; \
	    cd $$DIR; \
	    $(RM) -r /tmp/$(PACKAGE).$$PID; \
	    echo "phew! done!"

#END-NODIST
