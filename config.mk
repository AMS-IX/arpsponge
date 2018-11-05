#!make
# ============================================================================
#
#  CONFIG.MK:	Installation preferences
#
#   Copyright 2005-2016 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc
#   perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#   See the "Copying" file that came with this package.
#
# ============================================================================
#

# ----------------------------------------------------------------------------
#			MANDATORY CONFIG SECTION
# ----------------------------------------------------------------------------

# Where's perl on your system?
PERL                 = /usr/bin/perl

IFCONFIG             = /sbin/ifconfig
DFL_RATE             = 50
DFL_QUEUEDEPTH       = 1000
DFL_ARP_AGE          = 600
DFL_PENDING          = 5
DFL_PROBERATE        = 100
DFL_FLOOD_PROTECTION = 3.0
DFL_INIT             = ALIVE
DFL_LEARN            = 5
DFL_LOGLEVEL         = info

DFL_SOCK_PERMS       = root:noc:0660
SPONGE_VAR           = /var/run/$(NAME)

# ----------------------------
# --- Installation details ---
# ----------------------------

OWNER                = root
GROUP                = root
MODE                 = 644
BINMODE              = 755

# ----------------------------------------------------------------------------
#				END MANDATORY SECTION
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
#					OPTIONAL SECTION
# ----------------------------------------------------------------------------

# ------------------------------------------------------
# --- Locations for scripts, libraries, manual pages ---
# ------------------------------------------------------

# Prefix for most directories
DIRPREFIX            = $(DESTDIR)/usr/local

BINPREFIX            = $(DIRPREFIX)
DOCPREFIX            = $(DIRPREFIX)/share

# Where to install perl scripts, jobs, library files and manual pages.
BINDIR               = $(BINPREFIX)/sbin

# FreeBSD
LIBROOT              = $(DIRPREFIX)/lib/perl5/site_perl
# Fedora/RedHat
LIBROOT              = $(DIRPREFIX)/lib/perl5
# Debian
LIBROOT              = $(DIRPREFIX)/lib/site_perl

INSTLIB              = $(LIBROOT)
MANDIR               = $(DIRPREFIX)/man
DOCDIR               = $(DOCPREFIX)/doc/$(NAME)-$(RELEASE)

# What section for the manual pages?
SECTION              = 8
FILESECTION          = 4

# ----------------------------------------------------------------------------
#				END OPTIONAL SECTION
# ----------------------------------------------------------------------------

# Don't change this.  This is for people with a brain damaged csh(1).
# Well, you may change it, as long as it points to a Bourne-like shell.
SHELL                = /bin/sh

LIBDIR               = $(LIBROOT)
TOOLDIR              = $(TOPDIR)/tools
AUTODIR              = .
CURRDIR              = .
