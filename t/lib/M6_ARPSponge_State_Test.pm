#===============================================================================
#       Module:  M6_ARPSponge_State_Test.pm
#
#  Description:  Test class for M6::ARPSponge::State
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#
#   Copyright (c) 2015 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6_ARPSponge_State_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;

use M6::ARPSponge::State qw(:states);

sub startup : Test(startup => 1) {
    my $self = shift;
    use_ok( 'M6::ARPSponge::State', ':states' );
    $self->{'state'} = STATE_ALIVE;
}

sub test_states : Test(3) {
    my $self = shift;

    my $static  = STATE_STATIC;
    my $dead    = STATE_DEAD;
    my $alive   = STATE_ALIVE;
    my $pending = STATE_PENDING(0);

    ok($static < $dead, "STATE_STATIC < STATE_DEAD");
    ok($dead < $alive, "STATE_DEAD < STATE_ALIVE");
    ok($alive < $pending, "STATE_ALIVE < STATE_PENDING");
}

sub test_methods : Test(1) {
    my $state = shift->{'state'};
    my @methods = qw(
        increment
        decrement
        clone
        to_string
        to_num
        new
        new_from_string
        new_from_int
    );
    can_ok( $state, @methods);
}


sub test_new_from_int : Test(4) {
    my $self = shift;
    my $static  = M6::ARPSponge::State->new_from_int(-3);
    my $dead    = M6::ARPSponge::State->new_from_int(-2);
    my $alive   = M6::ARPSponge::State->new_from_int(-1);
    my $pending = M6::ARPSponge::State->new_from_int(0);

    ok($static  == STATE_STATIC,     "new_from_int(-3) == STATE_STATIC");
    ok($dead    == STATE_DEAD,       "new_from_int(-2) == STATE_DEAD");
    ok($alive   == STATE_ALIVE,      "new_from_int(-1) == STATE_ALIVE");
    ok($pending == STATE_PENDING(0), "new_from_int(0) == STATE_PENDING(0)");
}


sub test_new_from_string : Test(4) {
    my $self = shift;
    my $static  = M6::ARPSponge::State->new_from_string('STATIC');
    my $dead    = M6::ARPSponge::State->new_from_string('DEAD');
    my $alive   = M6::ARPSponge::State->new_from_string('ALIVE');
    my $pending = M6::ARPSponge::State->new_from_string('PENDING');

    ok($static  == STATE_STATIC,     "new_from_string('STATIC') == STATE_STATIC");
    ok($dead    == STATE_DEAD,       "new_from_string('DEAD') == STATE_DEAD");
    ok($alive   == STATE_ALIVE,      "new_from_string('ALIVE') == STATE_ALIVE");
    ok($pending == STATE_PENDING(0), "new_from_string('PENDING') == STATE_PENDING");
}

sub test_string_value : Test(4) {
    my $self = shift;
    ok(STATE_STATIC     eq 'STATIC',     "STATE_STATIC eq 'STATIC'");
    ok(STATE_DEAD       eq 'DEAD',       "STATE_DEAD eq 'DEAD'");
    ok(STATE_ALIVE      eq 'ALIVE',      "STATE_ALIVE eq 'ALIVE'");
    ok(STATE_PENDING(0) eq 'PENDING(0)', "STATE_PENDING(0) eq 'PENDING(0)'");
}

sub test_int_value : Test(4) {
    my $self = shift;
    ok(STATE_STATIC     == -3, "STATE_STATIC == -3");
    ok(STATE_DEAD       == -2, "STATE_DEAD == -2");
    ok(STATE_ALIVE      == -1, "STATE_ALIVE == -1");
    ok(STATE_PENDING(0) ==  0, "STATE_PENDING(0) == 0");
}

1;
