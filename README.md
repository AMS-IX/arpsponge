# About ARPSPONGE (a.k.a. "Bob")

The `arpsponge` is a tool that sweeps up stray ARP queries from a LAN. It listens on an ethernet interface and if the ARP rate for a particular IP address goes over the threshold, it starts faking responses.

This is especially useful on large peering LANs where a router crash can result in large ARP (broadcast) storms.

The arpsponge package provides a daemon, a CLI control utility, and an init script (see the arpsponge and asctl man pages).

This is released as free software, see the "Copying" file that came with this source).

## Requirements

  * GNU make
  * Perl (>= 5.10)
  * Perl modules:
    * Carp
    * Data::Dumper
    * File::Path
    * Getopt::Long
    * IO::File
    * IO::Select
    * IO::Socket
    * IO::String
    * NetAddr::IP
    * Net::ARP
    * Net::IPv4Addr
    * NetPacket (::ARP, ::Ethernet, ::IP)
    * Net::Pcap
    * Pod::Usage
    * POSIX
    * Readonly
    * Sys::Syslog
    * Term::ReadKey
    * Term::ReadLine
    * Time::HiRes

Depending on your O/S distribution and version of Perl, some or all of these may already be included in a base install of Perl.

## Installation

### DEBIAN

  1. Optionally edit config.mk (see below)
  2. Run `make dpkg`
  3. `dpkg --install *.deb`

### OTHER SYSTEMS

  1. Look at the start of `config.mk` and set correct values for:

    * (MUST be set correctly)

      * PERL         (/usr/bin/perl)
      * IFCONFIG     (/sbin/ifconfig)
      * SPONGE_VAR   (/var/run/arpsponge)

    * (MAY be changed)

      * IDIRPREFIX
      * BINPREFIX
      * DOCPREFIX
      * BINDIR
      * LIBROOT
      * INSTLIB
      * MANDIR
      * DOCDIR
      * SECTION
      * FILESECTION

  2. run `make`

  3. run `make install`

## Documentation

See the `arpsponge` man page, or `perldoc arpsponge`.
