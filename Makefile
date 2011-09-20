#!make
# $Id$
#
#  (c) Copyright 2005-2011 AMS-IX B.V.
#
#  This is free software. It can be distributed under
#  your choice of the GPL or Artistic License 2.0.
#
#  See the Copying file that came with this package.
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

all			:	$(TARGETS) sbin-all init.d-all man-all \
				lib-all doc-all

install		:	all sbin-install init.d-install man-install \
				lib-install doc-install

clean		:	sbin-clean init.d-clean man-clean \
				lib-clean doc-clean

veryclean	:	sbin-veryclean init.d-veryclean man-veryclean \
				lib-veryclean doc-veryclean

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
		$(RM) -r $(PACKAGE); \
	    $(RM) -r junk; \
	    $(RM) -r tools/mkdist; \
		$(RM) -r debian/files; \
		$(RM) -r debian/$(NAME); \
	    $(RM) -r old ; \
	    find . \( -name '*.gz' \
				  -o -name '*.Z' \
				  -o -name '*.tar' \
				  -o -name '*.orig' \
				  -o -name '*-stamp' \
				  -o -name '*.changes' \
				  -o -name '*.log' \
				  -o -name '*.deb' \
				  -o -name 'errors' \
				\) -exec $(RM) '{}' ';' ;\
	    find . -depth \( -name CVS \
				  -o -name RCS \
				  -o -name .svn \
				\) -exec $(RM) -r '{}' ';' ;\
	    $$DIR/tools/mkdist Makefile > Makefile.dist; \
			mv Makefile.dist Makefile; \
	    $$DIR/tools/mkdist config.mk > config.mk.dist; \
			cp config.mk.dist config.mk; \
		for script in arpsponge asctl; do \
			$(perlit) sbin/$$script.pl > sbin/$$script; \
			pod2text sbin/$$script > $$script.txt; \
		done; \
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
