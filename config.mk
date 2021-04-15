#!make
# ============================================================================
#
#  CONFIG.MK: Installation preferences
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
#   MANDATORY CONFIG SECTION
# ----------------------------------------------------------------------------

#### OS Specific - pick one, comment out the others.
#DISTRO := freebsd
#DISTRO := fedora
#DISTRO := redhat
#DISTRO := ubuntu
#DISTRO := debian

ifeq (${DISTRO},)
  $(info --------------------------)
  $(info Detecting DISTRO and OS...)
  OS := $(shell uname -s | tr [:upper:] [:lower:])
  DISTRO := ?
  ifeq (${OS}, linux)
    DISTRO := $(shell grep -E "^ID=" /etc/os-release | cut -f2 -d=)
  else
    _is_bsd := $(shell echo ${OS} | grep -E bsd)
    ifneq (${_is_bsd},)
      DISTRO := ${OS}
      DISTRO_FLAVOR := ${OS}
      OS := bsd
    endif
  endif
  $(info > OS     = ${OS})
  $(info > DISTRO = ${DISTRO})
  $(info --------------------------)
endif

# Defaults apply for Linux
PERL                    = /usr/bin/perl
LIBROOT                 = $(DIRPREFIX)/lib/perl5
IFCONFIG                = /sbin/ifconfig
OWNER                   = root
GROUP                   = root
DFL_SOCK_GROUP          = adm
RUNDIR                  = /run
ETC_DEFAULT             = /etc/default

ifeq (${DISTRO},freebsd)
  OS                      = bsd
  DISTRO_FLAVOR           = freebsd
else ifneq (, $(filter ${DISTRO},fedora redhat))
  OS                      = linux
  DISTRO_FLAVOR           = redhat
else ifneq (,$(filter ${DISTRO},debian ubuntu))
  OS                      = linux
  DISTRO_FLAVOR           = debian
else
  $(error unknown DISTRO "${DISTRO}")
endif

ifeq (${OS},bsd)
  PERL                    = /usr/local/bin/perl
  LIBROOT                 = $(DIRPREFIX)/lib/perl5/site_perl
  GROUP                   = wheel
  DFL_SOCK_GROUP          = wheel
  RUNDIR                  = /var/run
  ifeq (${DISTRO},openbsd)
    # OpenBSD has no /etc/default or /etc/defaults :-(
    ETC_DEFAULT           = /etc
  else
    ETC_DEFAULT           = /etc/defaults
  endif
else ifeq (${OS},linux)
  ifeq (${DISTRO_FLAVOR},debian)
    LIBROOT               = $(DIRPREFIX)/lib/site_perl
  endif
endif

# ---------------------------------------------------------------------------
# OVERRIDES
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SPONGE DEFAULTS
# ---------------------------------------------------------------------------

DFL_RATE             = 50
DFL_QUEUEDEPTH       = 1000
DFL_ARP_AGE          = 600
DFL_PENDING          = 5
DFL_PROBERATE        = 100
DFL_FLOOD_PROTECTION = 3.0
DFL_INIT             = ALIVE
DFL_LEARN            = 5
DFL_LOGLEVEL         = info

DFL_SOCK_PERMS       = root:$(DFL_SOCK_GROUP):0660
SPONGE_VAR           = /var/run/$(NAME)

# ----------------------------
# --- Installation details ---
# ----------------------------

MODE                 = 644
BINMODE              = 755

# ----------------------------------------------------------------------------
#               OPTIONAL SECTION
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

INSTLIB              = $(LIBROOT)
MANDIR               = $(DIRPREFIX)/man
DOCDIR               = $(DOCPREFIX)/doc/$(NAME)-$(RELEASE)

# What section for the manual pages?
SECTION              = 8
FILESECTION          = 4

# ----------------------------------------------------------------------------
#               END OPTIONAL SECTION
# ----------------------------------------------------------------------------

# Don't change this.  This is for people with a brain damaged csh(1).
# Well, you may change it, as long as it points to a Bourne-like shell.
SHELL                = /bin/sh

LIBDIR               = $(LIBROOT)
TOOLDIR              = $(TOPDIR)/tools
AUTODIR              = .
CURRDIR              = .
