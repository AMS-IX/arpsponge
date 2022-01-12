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
    * Config
    * Data::Dumper
    * Exporter
    * File::Path
    * FindBin
    * Getopt::Long
    * IO::File
    * IO::Select
    * IO::Socket
    * IO::Socket::UNIX
    * IO::String
    * IPC::Run
    * JSON::PP
    * NetAddr::IP
    * Net::ARP
    * Net::Pcap
    * Pod::Text::Termcap
    * Pod::Usage
    * POSIX
    * Readonly
    * Scalar::Util
    * Sys::Syslog
    * Term::ReadKey
    * Term::ReadLine
    * Term::ReadLine::Gnu
    * Time::HiRes
    * YAML::PP

Depending on your O/S distribution and version of Perl, some or all of these may already be included in a base install of Perl.

## Installation

### DEBIAN

  1. Edit config.mk if necessary (see below)
  2. Run `make dpkg`
  3. `dpkg --install *.deb`

### OTHER SYSTEMS

  1. The `config.mk` should be able to detect your OS/distro automatically. If not, you may need to edit `config.mk` and set an explicit  value.
  2. Make sure the following variables are set correctly, either by the `DISTRO` selection or by overriding them.
    * `PERL`
    * `IFCONFIG`
    * `SPONGE_VAR`
    * `RUNDIR`
    * `ETC_DEFAULT`
  3. If you want, you can override any of the variables below:
    * `DIRPREFIX`
    * `BINPREFIX`
    * `DOCPREFIX`
    * `BINDIR`
    * `LIBROOT`
    * `INSTLIB`
    * `MANDIR`
    * `DOCDIR`
    * `SECTION`
    * `FILESECTION`
  5. run `make` (or `gmake` on BSD).

  6. run `make install` (`gmake install` on BSD).

## Documentation

See the `arpsponge` man page, or `perldoc arpsponge`.

# FreeBSD Notes

Installing dependencies:

```
pkg install gmake \
    perl5 \
    p5-Net-Pcap p5-Readonly p5-NetAddr-IP p5-IO-String \
    p5-Net-Arp p5-Term-ReadKey p5-Term-ReadLine-Gnu p5-IPC-Run \
    p5-YAML-PP p5-JSON-PP
```
