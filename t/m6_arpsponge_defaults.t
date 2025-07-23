#===============================================================================
#
#  Description:  Unit tests for M6::ARPSponge::Defaults
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#
#   Copyright (c) 2025 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

use 5.014;
use warnings;

use Test2::V0;

use M6::ArpSponge::Defaults;

my %all = M6::ArpSponge::Defaults->all();

my $got = $all{MAX_ARP_AGE};
cmp_ok $got, '>', 0, "\$all{MAX_ARP_AGE} returns a positive integer";

my $expected = $got;
for my $k (('max arp age', 'MaxArpAge', 'max_arpAge')) {
    $got = M6::ArpSponge::Defaults->get($k);
    is $got, $expected, "->get('$k') == \$all{MAX_ARP_AGE} == $expected";
}

$got = M6::ArpSponge::Defaults->MAX_ARP_AGE;
is $got, $expected, "->MAX_ARP_AGE == \$all{MAX_ARP_AGE} == $expected";

like(
    dies { $got = M6::ArpSponge::Defaults->DOES_NOT_EXIST },
    qr{Undefined subroutine},
    "->DOES_NOT_EXIST throws an appropriate exception"
);

done_testing();
