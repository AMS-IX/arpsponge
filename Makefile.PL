#!/usr/bin/perl
#
# Copyright (c) AMS-IX B.V. - All rights reserved.
#
# See the "Copying" file that came with this package
# to see the licensing terms.
#
# Boilerplate Makefile.PL
#
# Fill in and modify where necessary.
#

use 5.014;
use warnings;
use ExtUtils::MakeMaker;

## List of scripts in "bin" directory.
## Only list the distributable stuff.
my @scripts = qw(
    arpsponge
    arpsponge_defaults
    asctl
    aslogtail
);

WriteMakefile(
    NAME          => 'M6::ArpSponge',
    VERSION_FROM  => 'lib/M6/ArpSponge.pm',
    ABSTRACT_FROM => 'lib/M6/ArpSponge.pm',
    AUTHOR        => [
        q{Steven Bakker <Steven.Bakker@ams-ix.net>},
    ],

    MIN_PERL_VERSION  => '5.014',
    PREREQ_FATAL      => 1,
    PREREQ_PM         => {
        'Carp'                        => '1.3301',
        'Config'                      => '5.020002',
        'Data::Dumper'                => '2.151_01',
        'Exporter'                    => '5.71',
        'File::Path'                  => '2.09',
        'FindBin'                     => '1.51',
        'Getopt::Long'                => '2.42',
        'IO::File'                    => '1.16',
        'IO::Select'                  => '1.22',
        'IO::Socket'                  => '1.38',
        'IO::Socket::UNIX'            => '1.26',
        'IO::String'                  => '1.08',
        'IPC::Run'                    => '0.92',
        'JSON::PP'                    => '2.27300',
        'List::Util'                  => '1.41',
        'Moo'                         => '1.006001',
        'Net::ARP'                    => 'v1.0.8',
        'Net::Pcap'                   => '0.17',
        'NetAddr::IP'                 => '4.075',
        'POSIX'                       => '1.38_03',
        'Pod::Text::Termcap'          => '2.08',
        'Pod::Usage'                  => '1.63',
        'Scalar::Util'                => '1.41',
        'Sys::Syslog'                 => '0.33',
        'Term::CLI'                   => '0.057001',
        'Term::CLI::Argument'         => '0.057001',
        'Term::CLI::Argument::String' => '0.057001',
        'Term::CLI::L10N'             => '0.057001',
        'Term::CLI::Util'             => '0.057001',
        'Term::ReadKey'               => '2.32',
        'Term::ReadLine'              => '1.14',
        'Time::HiRes'                 => '1.9726',
        'YAML::PP'                    => '0.026',
        'base'                        => '2.22',
        'constant'                    => '1.31',
        'feature'                     => '1.36_01',
        'namespace::clean'            => '0.25',
        'parent'                      => '0.228',
        'strict'                      => '1.08',
        'version'                     => '0.9909',
        'warnings'                    => '1.23',
    },

    BUILD_REQUIRES      => {
        'Test::Compile' => 'v1.2.0',
        'Test::More'    => '1.001008',
        'strict'        => '1.08',
        'warnings'      => '1.23',
    },

    INSTALLSCRIPT     => '$(PREFIX)/sbin',
    INSTALLSITESCRIPT => '$(PREFIX)/sbin',
    EXE_FILES         => [ map { "sbin/$_" } @scripts ],
    PMLIBDIRS         => [ 'lib' ],

    dist              => { COMPRESS => 'gzip -9f', SUFFIX => 'gz' },
);
