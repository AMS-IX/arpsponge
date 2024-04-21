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
    ABSTRACT_FROM => 'sbin/arpsponge.pl',
    AUTHOR       => [
        q{First Last <First.Last@ams-ix.net>},
    ],

    # Uncomment if necessary...
    #EXE_FILES    => [map { "bin/$_" } @scripts],
    #MAN1PODS	  => { map { ("bin/$_" => "blib/man1/$_.1p") } @scripts },
    PREREQ_FATAL => 0, # Change to 1 if you really need our prereqs.
    
    PREREQ_PM    => {
        # Include output from "perldepend --cpan bin/* lib/**/*.pm"
    },
    BUILD_REQUIRES      => {
        # Include output from "perldepend --cpan t/*"
    },

    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz' },
);
