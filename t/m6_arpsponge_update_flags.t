#===============================================================================
#  Description:  Unit tests for M6::ARPSponge::UpdateFlags
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

use M6::ArpSponge::UpdateFlags qw(:all);

imported_ok(qw(
    ARP_UPDATE_FLAG_NAMES
    ARP_UPDATE_REPLY
    ARP_UPDATE_REQUEST
    ARP_UPDATE_GRATUITOUS
    ARP_UPDATE_NONE
    ARP_UPDATE_ALL
    parse_update_flags
    update_flags_to_str
));

my @PARSE_TESTS = (
    {
        arg          => undef,
        expected     => ARP_UPDATE_NONE,
    },
    {
        arg          => 'none',
        expected     => ARP_UPDATE_NONE,
    },
    {
        arg          => 'all',
        expected     => ARP_UPDATE_ALL,
    },
    {
        arg          => '!none',
        expected     => ARP_UPDATE_ALL,
    },
    {
        arg          => 'all,!request',
        expected     => ARP_UPDATE_ALL & ~ARP_UPDATE_REQUEST,
    },
    {
        arg          => 'all,!request',
        expected     => ARP_UPDATE_ALL & ~ARP_UPDATE_REQUEST,
    },
    {
        arg      => 'reply,request',
        expected => ARP_UPDATE_REPLY|ARP_UPDATE_REQUEST,
    },
    {
        arg          => 'whoopsie',
        expected     => undef,
        expected_err => qr{not a valid ARP update flag}i,
    },
);

my @names = ARP_UPDATE_FLAG_NAMES;

cmp_ok int(@names), '>', 0, "ARP_UPDATE_FLAG_NAMES() returns at least one name";

push @PARSE_TESTS, {
    arg => join(',', sort grep { !/^(?:all|none)$/ } @names),
    expected => ARP_UPDATE_ALL,
};

for my $test (@PARSE_TESTS) {
    my ($arg, $expected, $expected_err)
        = @{$test}{qw( arg expected expected_err )};

    my $arg_str = defined $arg ? qq{'$arg'} : 'undef';
    my $exp_str = defined $expected ? sprintf("0x%02x", $expected) : 'undef';

    my $err = undef;
    my $got = parse_update_flags($arg, -err => \$err);

    is $got, $expected, "parse_update_flags($arg_str) returns $exp_str";
    if (defined $expected_err) {
        like $err, $expected_err,
            "parse_update_flags($arg_str) sets appropriate error message";
    }
    else {
        is $err, undef, "parse_update_flags(undef) returns no error";
    }
}

my @STR_TESTS = (
    { arg => undef,            expected => ['none'] },
    { arg => ARP_UPDATE_NONE,  expected => ['none'] },
    { arg => ARP_UPDATE_NONE,  expected => ['none'] },
    { arg => ARP_UPDATE_REPLY, expected => ['reply'] },
    { arg => ARP_UPDATE_ALL,   expected => ['request', 'reply', 'gratuitous'] },
);

for my $test (@STR_TESTS) {
    my ($arg, $expected) = @{$test}{qw( arg expected )};

    my $arg_str = defined $arg ? sprintf("0x%02x", $arg) : 'undef';
    $expected //= [];
    my @expected = sort @{$expected};
    my $exp_str = "(".join(', ', map { qq{'$_'} } @expected).")";

    my @got = sort (update_flags_to_str($arg));

    is \@got, \@expected, "update_flags_to_str($arg_str) returns $exp_str";
}

done_testing();
