#===============================================================================
#       Module:  70-m6_arpsponge_state.t
#
#  Description:  Unit tests for M6::ARPSponge::State
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
use POSIX qw( strftime );

use M6::ArpSponge::State qw(:all);
use Data::Dumper;

my %name_map = (
    'DEAD'       => DEAD,
    'ALIVE'      => ALIVE,
    'STATIC'     => STATIC,
    'NONE'       => NONE,
    'PENDING(0)' => PENDING(0),
);

is is_valid_state('PENDING'), PENDING(0),
    "is_valid_state('PENDING') => PENDING(0)";

for my $name (sort { $a cmp $b } keys %name_map) {
    my $err = undef;
    my $got = is_valid_state($name, -err => \$err);
    my $expected = $name_map{$name};
    is $got, $expected, "is_valid_state('$name') => $expected";
    is $err, undef, "is_valid_state() leaves \$err undefined on success";
}

for my $bad_str (qw( ILLEGAL PENDING(-1) )) {
    my $err;
    my $state = is_valid_state($bad_str, -err => \$err);
    is $state, undef, "is_valid_state('$bad_str') => undef";
    like $err, qr{not a valid state},
        "is_valid_state('$bad_str') sets error message correctly";
}

my %state_map = reverse %name_map;
for my $val (sort { ($a||0) <=> ($b||0) } keys %state_map) {
    my $got = state_to_string($val);
    my $expected = $state_map{$val};
    is $got, $expected, "state_to_string($val) => '$expected'";
}

is state_to_string(undef), 'NONE',   "state_to_str(undef) => 'NONE'";
is state_to_string(-10),  'ILLEGAL', "state_to_str(-10) => 'ILLEGAL'";

done_testing();
