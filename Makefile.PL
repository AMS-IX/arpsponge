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
## Only if necessary...
my @scripts = qw(
);

WriteMakefile(
    NAME          => 'M6::ArpSponge',
    VERSION_FROM  => 'lib/M6/ArpSponge.pm',
    ABSTRACT_FROM => 'lib/M6/ArpSponge.pm',
    AUTHOR       => [
        q{Steven Bakker <Steven.Bakker@ams-ix.net>},
    ],

    # Uncomment if necessary...
    #EXE_FILES    => [map { "bin/$_" } @scripts],
    #MAN1PODS	  => { map { ("bin/$_" => "blib/man1/$_.1p") } @scripts },
    PREREQ_FATAL => 0, # Change to 1 if you really need our prereqs.
    
    'MIN_PERL_VERSION'  => '5.014',

    'PREREQ_PM'         => {
        'Carp'                                          => '1.54',
        'Config'                                        => '5.038002',
        'Data::Dumper'                                  => '2.188',
        'Exporter'                                      => '5.77',
        'File::Path'                                    => '2.18',
        'FindBin'                                       => '1.53',
        'Getopt::Long'                                  => '2.54',
        'IO::File'                                      => '1.52',
        'IO::Select'                                    => '1.52',
        'IO::Socket'                                    => '1.52',
        'IO::Socket::UNIX'                              => '1.52',
        'IO::String'                                    => '1.08',
        'IPC::Run'                                      => '20220807.0',
        'JSON::PP'                                      => '4.16',
        'List::Util'                                    => '1.63',
        'Moo'                                           => '2.005005',
        'Net::ARP'                                      => 'v1.0.12',
        'Net::Pcap'                                     => '0.21',
        'NetAddr::IP'                                   => '4.079',
        'POSIX'                                         => '2.13',
        'Pod::Text::Termcap'                            => '5.01',
        'Pod::Usage'                                    => '2.03',
        'Readonly'                                      => '2.05',
        'Scalar::Util'                                  => '1.63',
        'Sys::Syslog'                                   => '0.36',
        'Term::CLI'                                     => '0.059000',
        'Term::CLI::Argument'                           => '0.059000',
        'Term::CLI::L10N'                               => '0.059000',
        'Term::CLI::Util'                               => '0.059000',
        'Term::ReadKey'                                 => '2.38',
        'Term::ReadLine'                                => '1.17',
        'Time::HiRes'                                   => '1.9775',
        'YAML::PP'                                      => '0.036',
        'base'                                          => '2.27',
        'constant'                                      => '1.33',
        'feature'                                       => '1.82',
        'namespace::clean'                              => '0.27',
        'parent'                                        => '0.241',
        'strict'                                        => '1.12',
        'version'                                       => '0.9930',
        'warnings'                                      => '1.65',
    },

    BUILD_REQUIRES      => {
        'Test::Compile' => 'v3.3.1',
        'Test::More'    => '1.302195',
        'strict'        => '1.12',
        'warnings'      => '1.65',
    },

    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz' },
);
