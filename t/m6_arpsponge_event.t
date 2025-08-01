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

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Mock::Sys::Syslog;

my $mock_syslog;

BEGIN {
    $mock_syslog = Test::Mock::Sys::Syslog->new();
}

use M6::ArpSponge::Event qw(:all);
use Sys::Syslog qw(:standard :macros);
use M6::ArpSponge::Log qw(:func);

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
        event_mask_to_string
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

subtest 'parse_event_mask' => sub {
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
};

subtest 'event_mask' => sub {
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
};

subtest 'event_mask_to_string' => sub {
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

        my @got = sort (event_mask_to_string($arg));

        is \@got, \@expected,
            "event_mask_to_string($arg_str) returns $exp_str";
    }
};

subtest 'event_logging' => sub {
    init_log();

    event_mask(EVENT_IO|EVENT_CTL);

    log_level(LOG_DEBUG);

    my @event_log = (
        [ 'emerg'  , \&event_emerg   ],
        [ 'alert'  , \&event_alert   ],
        [ 'crit'   , \&event_crit    ],
        [ 'err'    , \&event_err     ],
        [ 'warning', \&event_warning ],
        [ 'notice' , \&event_notice  ],
        [ 'info'   , \&event_info    ],
        [ 'debug'  , \&event_debug   ],
    );

    for my $elt (@event_log) {
        my ($prio_name, $func) = @{$elt};
        my $prio = is_valid_log_level($prio_name);
        my $msg = "an IO event at level \U$prio_name\E";

        $mock_syslog->clear_log_buffer();
        $func->(EVENT_IO, $msg);
        
        my $buf = $mock_syslog->log_buffer();
        is int(@{$buf}),  1, "logged a \U$prio_name\E message";

        my ($got_prio, $got_msg) = @{$buf->[-1]};
        is $got_prio, uc $prio_name,
            "event_${prio_name}(EVENT_IO, ...) => \U$prio_name\E level event";
        like $got_msg, qr{\Q$msg\E},
            "event_${prio_name}(EVENT_IO, ...) logs $msg";
    }

    $mock_syslog->clear_log_buffer();
    event_err(EVENT_ALIEN, 'an ALIEN event at level ERR');
    my $buf = $mock_syslog->log_buffer();
    is @{$buf}, 0,
        "event_emerg(EVENT_ALIEN, ...) is not logged due to event mask";
};

done_testing();
