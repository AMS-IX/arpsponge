#===============================================================================
#  Description:  Unit tests for M6::ARPSponge::Event
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

use M6::ArpSponge::Event qw(:all);

imported_ok(qw(
        EVENT_NAMES
        EVENT_IO
        EVENT_ALIEN
        EVENT_SPOOF
        EVENT_STATIC
        EVENT_SPONGE
        EVENT_CTL
        EVENT_STATE
        EVENT_ALL
        EVENT_NONE
        event_log
        event_mask
        event_mask_to_str
        is_event_mask
        parse_event_mask
    ),
    (map { "event_$_" }
        qw( emerg alert crit err warning notice info debug )),
);


my @PARSE_TESTS = (
    {
        arg          => undef,
        expected     => event_mask(),
    },
    {
        arg          => 'none',
        expected     => EVENT_NONE,
    },
    {
        arg          => 'all',
        expected     => EVENT_ALL,
    },
    {
        arg          => '!none',
        expected     => EVENT_ALL,
    },
    {
        arg          => 'io,alien',
        expected     => EVENT_IO | EVENT_ALIEN,
    },
    {
        arg          => 'all,!ctl',
        expected     => EVENT_ALL & ~EVENT_CTL,
    },
    {
        arg          => 'whoopsie',
        expected     => undef,
        expected_err => qr{not a valid event name}i,
    },
);

my @EVENT_NAMES = EVENT_NAMES;

cmp_ok int(@EVENT_NAMES), '>', 0, "EVENT_NAMES() returns at least one name";

push @PARSE_TESTS, {
    arg => join(',', sort grep { !/^(?:all|none)$/ } @EVENT_NAMES),
    expected => EVENT_ALL,
};

for my $test (@PARSE_TESTS) {
    my ($arg, $expected, $expected_err)
        = @{$test}{qw( arg expected expected_err )};

    my $arg_str = defined $arg ? qq{'$arg'} : 'undef';
    my $exp_str = defined $expected ? sprintf("0x%02x", $expected) : 'undef';

    my $err = undef;
    my $got = parse_event_mask($arg, -err => \$err);

    is $got, $expected, "parse_event_mask($arg_str) returns $exp_str";
    if (defined $expected_err) {
        like $err, $expected_err,
            "parse_event_mask($arg_str) sets appropriate error message";
    }
    else {
        is $err, undef, "parse_event_mask($arg_str) returns no error";
    }
}

my ($arg, $got, $expected, $err, $curr);
my (@got, @expected);

$expected = event_mask();
$arg = EVENT_STATIC;
$got = event_mask(EVENT_STATIC);
is $got, $expected,
    sprintf("event_mask(0x%02x) returns old mask (0x%02x)", $arg, $expected);

$got = event_mask();
$expected = $arg;
is $got, $expected,
    sprintf("event_mask(0x%02x) sets mask to 0x%02x", $arg, $expected);

$curr = event_mask();
$arg = '+ctl,+alien';
$expected = $got | EVENT_CTL | EVENT_ALIEN;
$got = parse_event_mask($arg, -err => \$err);
is $got, $expected,
    sprintf("parse_event_mask('%s') (curr=0x%02x) returns 0x%02x",
        $arg, $curr, $expected);

event_mask($got);

$curr = event_mask();
$arg = '!static';
$expected = $curr & ~EVENT_STATIC;
$got = parse_event_mask($arg, -err => \$err);
is $got, $expected,
    sprintf("parse_event_mask('%s') (curr=0x%02x) returns 0x%02x",
        $arg, $curr, $expected);

event_mask($got);

$curr = event_mask();
$arg = '+static,!alien';
$expected = ($curr | EVENT_STATIC) & ~EVENT_ALIEN;
$got = parse_event_mask($arg, -err => \$err);
is $got, $expected,
    sprintf("parse_event_mask('%s') (curr=0x%02x) returns 0x%02x",
        $arg, $curr, $expected);

event_mask(EVENT_NONE);

$curr = event_mask();
$arg = '!none';
$expected = EVENT_ALL;
$got = parse_event_mask($arg, -err => \$err);
is $got, $expected,
    sprintf("parse_event_mask('%s') (curr=0x%02x) returns 0x%02x",
        $arg, $curr, $expected);

event_mask(EVENT_NONE);
$curr = event_mask();
$arg = '+ctl,+alien';
$expected = EVENT_CTL | EVENT_ALIEN;
$got = parse_event_mask($arg, -err => \$err);
is $got, $expected,
    sprintf("parse_event_mask('%s') (curr=0x%02x) returns 0x%02x",
        $arg, $curr, $expected);

my @STR_TESTS = (
    { arg => undef,
        expected => ['none'] },
    { arg => EVENT_NONE,
        expected => ['none'] },
    { arg => EVENT_SPOOF|EVENT_CTL,
        expected => ['ctl', 'spoof'] },
    { arg => EVENT_ALL,
        expected => [ grep { !/^(?:all|none)$/ } @EVENT_NAMES ] },
);

for my $test (@STR_TESTS) {
    my ($arg, $expected) = @{$test}{qw( arg expected )};

    my $arg_str = defined $arg ? sprintf("0x%02x", $arg) : 'undef';
    $expected //= [];
    my @expected = sort @{$expected};
    my $exp_str = "(".join(', ', map { qq{'$_'} } @expected).")";

    my @got = sort (event_mask_to_str($arg));

    is \@got, \@expected, "event_mask_to_str($arg_str) returns $exp_str";
}

event_mask(EVENT_IO|EVENT_CTL);
$curr = event_mask();

$arg = EVENT_IO;
ok is_event_mask($arg),
    sprintf("is_event_mask(0x%02x) (curr=0x%02x) returns true", $curr, $arg);

$arg = EVENT_CTL;
ok is_event_mask($arg),
    sprintf("is_event_mask(0x%02x) (curr=0x%02x) returns true", $curr, $arg);

$arg = EVENT_ALIEN;
ok !is_event_mask($arg),
    sprintf("is_event_mask(0x%02x) (curr=0x%02x) returns false", $curr, $arg);

done_testing();
