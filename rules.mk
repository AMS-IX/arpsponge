#
#!make
# $Id$
#
# Copyright (c) 2002 Steven Bakker
# All rights reserved

default : all

RM            =  /bin/rm -f
MV            =  /bin/mv

RELEASE       =  3.10-beta13
NAME          =  arpsponge
PACKAGE       =  $(NAME)-$(RELEASE)
TOOLDIR       =  $(TOPDIR)/tools

INSTALL_LOG   =  $(TOPDIR)/installed.log
INSTALLPROG   =  $(TOOLDIR)/bsdinst -c -l $(INSTALL_LOG)
INSTALL       =  $(INSTALLPROG) -o $(OWNER) -g $(GROUP) -m $(MODE)
BININSTALL    =  $(INSTALLPROG) -o $(OWNER) -g $(GROUP) -m $(BINMODE)

MKDIR         =  $(TOOLDIR)/mkinstalldirs
RMDIR         =  $(TOOLDIR)/rminstalldirs

#
# Substitute configuration variables in files.
#
perlit= $(PERL) -p -e \
		   "s!\@LIBDIR@!$(LIBDIR)!g;		\
		    s!\@BINDIR@!$(BINDIR)!g;		\
		    s!\@DFL_PATH@!$(DFL_PATH)!g;	\
		    \
		    s!\@NAME@!$(NAME)!g;		\
		    s!\@UNAME@!\U$(NAME)\E!g;		\
		    s!\@Uname@!\u$(NAME)!g;		\
		    \
		    s!\@OWNER@!$(OWNER)!g;		\
		    s!\@GROUP@!$(GROUP)!g;		\
		    \
		    s!\@SECTION@!\U$(SECTION)\E!g;	\
		    s!\@USECTION@!\U$(SECTION)\E!g;	\
		    s!\@FILESECTION@!$(FILESECTION)!g;	\
		    s!\@UFILESECTION@!\U$(FILESECTION)\E!g;	\
		    \
		    s!\@RELEASE@!$(RELEASE)!g;		\
		    s!\@SHELL@!$(SHELL)!g;		\
		    s!\@PERL@!$(PERL)!g;		\
		    \
		    s!\@SPONGE_VAR@!$(SPONGE_VAR)!g;	\
		    s!\@SPONGE_OPTIONS@!$(SPONGE_OPTIONS)!g;	\
		    s!\@DFL_SOCK_PERMS@!$(DFL_SOCK_PERMS)!g;	\
			\
		    s!\@IFCONFIG@!$(IFCONFIG)!g;	\
		    s!\@DFL_RATE@!$(DFL_RATE)!g;	\
		    s!\@DFL_INIT@!$(DFL_INIT)!g;	\
		    s!\@DFL_ARP_AGE@!$(DFL_ARP_AGE)!g;	\
		    s!\@DFL_QUEUEDEPTH@!$(DFL_QUEUEDEPTH)!g;	\
		    s!\@DFL_FLOOD_PROTECTION@!$(DFL_FLOOD_PROTECTION)!g;	\
		    s!\@DFL_PENDING@!$(DFL_PENDING)!g;	\
		    s!\@DFL_PROBERATE@!$(DFL_PROBERATE)!g;	\
		    s!\@DFL_LEARN@!$(DFL_LEARN)!g;	\
		    s!\@DFL_LOGLEVEL@!$(DFL_LOGLEVEL)!g;	\
		    "

.SUFFIXES:	.al .pm .pmrsc .pl \
		.src	\
		.sample	\
		.sh	\
		.txt .ps \
		.$(SECTION) .pod .man .txt

% : %.sh Makefile
	@echo building $@ from $<
	@$(perlit) $< > $@
	@chmod 755 $@
	
%.sample : %.sample.src Makefile
	@echo building $@ from $<
	@$(perlit) $< > $@
	@chmod 644 $@

% : %.src Makefile
	@echo building $@ from $<
	@$(perlit) $< > $@
	@chmod 644 $@

% : %.pl Makefile
	@ echo building $@ from $<
	@ $(perlit) $< > $@
	@ chmod 755 $@
	@ $(PERL) -wc $@ || $(RM) $@

%.$(SECTION) : %.pod
	@echo building $@ from $<
	@PERLLIB=$$PERLLIB:$(TOPDIR)/lib; export PERLLIB; \
		pod2man \
				--release="$(NAME)-$(RELEASE)" \
				--date="`date`" \
				--center="AMS-IX Management Utilities" \
				--section=$(SECTION) \
				--name="`echo $* | sed -e 's/\.\./::/g'`" \
			$< > $@

%.html : %.pod
	@echo building $@ from $<
	@PERLLIB=$$PERLLIB:$(TOPDIR)/lib; export PERLLIB; \
		$(TOOLDIR)/pod2html \
				--name="`echo $* | sed -e 's/\.\./::/g'`" \
			$< > $@

%.txt : %.$(SECTION)
	@echo building $@ from $<
	@$(perlit) $< | gnroff -mgan > $@

%.ps : %.$(SECTION)
	@echo building $@ from $<
	@$(perlit) $< | groff -Tps -mgan > $@

$(INITDIR)/% : %
	@echo installing executable $< in $(INITDIR)
	$(MKDIR) $(INITDIR) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	$(BININSTALL) $< $@
	$(PERL) -pi -e 's|^(#!/.*) -I../lib|$$1|' $@

$(BINDIR)/% : %
	@echo installing executable $< in $(BINDIR)
	$(MKDIR) $(BINDIR) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	$(BININSTALL) $< $@
	$(PERL) -pi -e 's|^(#!/.*) -I../lib|$$1|' $@

$(MANDIR)/man$(SECTION)/% : %
	@echo installing $< in $(MANDIR)/man$(SECTION)
	@$(MKDIR) $(MANDIR)/man$(SECTION) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	@$(INSTALL) $< $@

$(DOCDIR)/% : %
	@if [ ! -n "$(SKIPDOCS)" ]; then \
		echo installing $< in $(DOCDIR); \
		$(MKDIR) $(DOCDIR) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG); \
		$(INSTALL) $< $@; \
	fi

$(INSTDIR1)/% : %
	@echo installing $< in $(INSTDIR1)
	@$(MKDIR) $(INSTDIR1) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	@$(INSTALL) $< $@

$(INSTDIR2)/% : %
	@echo installing $< in $(INSTDIR2)
	@$(MKDIR) $(INSTDIR2) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	@$(INSTALL) $< $@

$(INSTDIR3)/% : %
	@echo installing $< in $(INSTDIR3)
	@$(MKDIR) $(INSTDIR3) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	@$(INSTALL) $< $@

$(INSTALLDIR)/% : %
	@echo installing $< in $(INSTALLDIR)
	@$(MKDIR) $(INSTALLDIR) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)
	@$(INSTALL) $< $@

%.sample : %
	@echo building $@ from $<
	@$(perlit) $< > $@
	@chmod 644 $@

auto/$(AUTO)/%/autosplit.ix : $(AUTO)/%.pm
	@echo autosplit $<;
	@PERLLIB=$$PERLLIB:$(TOPDIR)/lib; export PERLLIB; \
	    $(TOOLDIR)/autosplit ./auto $<

auto/$(AUTO1)/%/autosplit.ix : $(AUTO1)/%.pm
	@echo autosplit $<;
	@PERLLIB=$$PERLLIB:$(TOPDIR)/lib; export PERLLIB; \
	    $(TOOLDIR)/autosplit ./auto $<

%-all		:	; cd $* ; $(MAKE) all
%-install	:	; cd $* ; $(MAKE) install
%-uninstall	:	; cd $* ; $(MAKE) uninstall
%-autosplit	:	; cd $* ; $(MAKE) autosplit
%-clean		:	; cd $* ; $(MAKE) clean

all		:	$(TARGETS)

install		:	all installdirs $(INSTALLFILES) install-links post-install

installdirs	:
			@echo "Checking/creating installation directories..."
			@echo $(INSTALLDIRS)
			@$(MKDIR) $(INSTALLDIRS) 2>&1 | sed -e 's/^mkdir //' >> $(INSTALL_LOG)

post-install	:	
			@$(RM) $(INSTALL_LOG).tmp; \
			sort -ru $(INSTALL_LOG) > $(INSTALL_LOG).tmp; \
			$(MV) $(INSTALL_LOG).tmp $(INSTALL_LOG)

uninstall	:
	echo "Removing installed files:" ; \
	files=$(INSTALLFILES); \
	if [ -f $(INSTALL_LOG) ]; then \
		files="$$files `cat $(INSTALL_LOG)`"; \
	fi; \
	echo '** Warning: will remove the following files:'; \
	echo $$files | $(PERL) -n -e \
		'print map { qq{    $$_\n} } split(" ", $$_);'; \
	if [ `echo "\c" | wc -c` -gt 0 ]; then \
	    echo -n "Are you sure [yn] y"; \
	else \
	    echo "Are you sure [ny] n\c"; \
	fi; \
	read ans; \
	case "$$ans" in \
	    y*|Y*) echo "Removing ..."; \
		    $(RM) $$files >/dev/null 2>&1; \
		    $(RMDIR) $$files >/dev/null 2>&1; \
		    $(RM) $(INSTALL_LOG); \
		    echo "Done"; \
		    true;; \
	    *) false;; \
	esac

x-uninstall	:	; $(RM) $(INSTALLFILES)

clean		:	; @echo cleaning up
			@$(RM) $(TARGETS) core 2>/dev/null \
				$(NAME)_*.deb; \
			true

install-links:
	@for link in ._no $(INSTALLLINKS) $(INSTALLINKS); do \
		[ $$link = ._no ] && continue; \
		linkname=`echo $$link | cut -f1 -d:`; \
		fname=`echo $$link | cut -f2 -d:`; \
		if [ ! -f $$linkname ] || [ -h $$linkname ]; then \
			target=`/bin/ls -l $$linkname 2>/dev/null | sed -e 's|^.*-> ||'`; \
			if [ X$$target != X$$fname ]; then \
				$(RM) $$linkname; \
				ln -s $$fname $$linkname; \
				echo $$linkname; \
			fi; \
		fi; \
	done

veryclean	:	clean
			@if [ -d ./SCCS ]; then sccs clean; fi

_debtemp	:= /tmp/deb.$(NAME).$(shell echo $$RANDOM)

dpkg:
	mkdir -p $(_debtemp)
	cp -rp . $(_debtemp)/$(NAME)-$(RELEASE)
	cd $(_debtemp)/$(NAME)-$(RELEASE); \
	    (fakeroot /usr/bin/make -f debian/rules binary || true)
	ls $(_debtemp)/$(NAME)_*.deb >/dev/null 2>&1; \
		[ $$? = 0 ] && mv $(_debtemp)/$(NAME)_*.deb .
	$(RM) -rf $(_debtemp)

	#$(RM) -rf debian *.deb
	    #dh_make --single; \
#
#  %: define.h %.c
#	$@: target (wonkie)
#	$^: dependencies (define.h wonkie.c)
#	$<: primary source file (define.h)
#	$?: out of date dependency (wonkie.c)
#	$*: portion that matched the "%" (wonkie)
