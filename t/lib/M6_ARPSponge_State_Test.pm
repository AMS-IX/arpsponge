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


sub test_all: Test(5) {
    my $self = shift;
    my @all = M6::ARPSponge::State->ALL;
    cmp_ok(int(@all), '==', 4,  '@ALL == 4');
    cmp_ok($all[0], '==', STATE_STATIC,      'ALL[0] == STATE_STATIC');
    cmp_ok($all[1], '==', STATE_DEAD,        'ALL[1] == STATE_DEAD');
    cmp_ok($all[2], '==', STATE_ALIVE,       'ALL[2] == STATE_ALIVE');
    cmp_ok($all[3], '==', STATE_PENDING(0),  'ALL[3] == STATE_PENDING(0)');
}

sub test_clone : Test(2) {
    my $self = shift;

    my $state = STATE_DEAD; # No cloning yet.
    $state++; # Force clone.
    cmp_ok($state, '>', STATE_DEAD, 'STATE_DEAD+1 > STATE_DEAD');

    $state = STATE_ALIVE;
    $state--;
    cmp_ok($state, '<', STATE_ALIVE, 'STATE_ALIVE-1 > STATE_ALIVE');
}

sub test_new : Test(8) {
    my $self = shift;

    my $from_int    = M6::ARPSponge::State->new(-3);
    ok($from_int, 'new(-3)');

    my $from_string = M6::ARPSponge::State->new('STATIC');
    ok($from_string, 'new("STATIC")');

    ok($from_string == $from_int, 'new("STATIC") == new(-3)');

    my $from_state  = M6::ARPSponge::State->new($from_int);
    ok($from_state == $from_int, 'new($from_int) == $from_int');

    my $from_undef  = M6::ARPSponge::State->new(undef);
    ok($from_undef eq STATE_NONE, 'new(undef) eq STATE_NONE');

    my $bad1 = M6::ARPSponge::State->new(-4);
    ok(!defined($bad1), 'new(-4) => undef');

    my $bad2 = M6::ARPSponge::State->new('INVALID', -err => \(my $err));
    ok(!defined($bad2), 'new("INVALID") => undef');
    like($err, qr/^".*?" is not a valid state$/, 'new("INVALID") => error');
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


sub test_new_from_string : Test(6) {
    my $self = shift;
    my $none     = M6::ARPSponge::State->new_from_string('NONE');
    my $static   = M6::ARPSponge::State->new_from_string('STATIC');
    my $dead     = M6::ARPSponge::State->new_from_string('DEAD');
    my $alive    = M6::ARPSponge::State->new_from_string('ALIVE');
    my $pending  = M6::ARPSponge::State->new_from_string('PENDING');
    my $pending2 = M6::ARPSponge::State->new_from_string('PENDING(2)');

    ok($none     eq STATE_NONE,       "new_from_string('NONE') eq STATE_NONE");
    ok($static   == STATE_STATIC,     "new_from_string('STATIC') == STATE_STATIC");
    ok($dead     == STATE_DEAD,       "new_from_string('DEAD') == STATE_DEAD");
    ok($alive    == STATE_ALIVE,      "new_from_string('ALIVE') == STATE_ALIVE");
    ok($pending  == STATE_PENDING(0), "new_from_string('PENDING') == STATE_PENDING");
    ok($pending2 == STATE_PENDING(2), "new_from_string('PENDING(2)') == STATE_PENDING(2)");
}

sub test_string_value : Test(6) {
    my $self = shift;
    ok(STATE_NONE       eq 'NONE',       "STATE_NONE   eq 'NONE'");
    ok(STATE_STATIC     eq 'STATIC',     "STATE_STATIC eq 'STATIC'");
    ok(STATE_DEAD       eq 'DEAD',       "STATE_DEAD eq 'DEAD'");
    ok(STATE_ALIVE      eq 'ALIVE',      "STATE_ALIVE eq 'ALIVE'");
    ok(STATE_PENDING(0) eq 'PENDING(0)', "STATE_PENDING(0) eq 'PENDING(0)'");

    my $state = STATE_STATIC;
    $state--;
    ok($state eq 'ILLEGAL', "STATE_STATIC-1 eq 'ILLEGAL'");
}

sub test_int_value : Test(4) {
    my $self = shift;
    ok(STATE_STATIC     == -3, "STATE_STATIC == -3");
    ok(STATE_DEAD       == -2, "STATE_DEAD == -2");
    ok(STATE_ALIVE      == -1, "STATE_ALIVE == -1");
    ok(STATE_PENDING(0) ==  0, "STATE_PENDING(0) == 0");
}

1;
