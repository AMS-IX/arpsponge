#===============================================================================
#       Module:  M6_ARPSponge_Util_Test.pm
#
#  Description:  Test class for M6::ARPSponge::Util
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

use 5.014;
use warnings;

use Test2::V0;
use POSIX qw( strftime );

use M6::ArpSponge::Util qw(:all);

my %IP = (
    STR => '193.194.136.132',
    INT => 3250751620,
    HEX => 'c1c28884',
    NET => '193.194.136.128',
    LEN => 25,
);

my %MAC = (
    STR1 => 'a1:b2:03:04:e5:f6',
    STR2 => 'a1b2.304.e5f6',
    HEX  => 'a1b20304e5f6',
);

TEST_INT2IP : {
    my $arg = $IP{INT};
    my $expected = $IP{STR};
    is int2ip($arg), $expected, "int2ip($arg) returns '$expected'";
}

TEST_IP2INT : {
    my $arg = $IP{STR};
    my $expected = $IP{INT};
    is ip2int($arg), $expected, "ip2int('$arg') returns $expected";
}

TEST_HEX2IP : {
    my $arg = $IP{'HEX'};
    my $expected  = $IP{'STR'};
    is hex2ip($arg), $expected, "hex2ip('$arg') returns '$expected'";
}

TEST_IP2HEX : {
    my $arg = $IP{'STR'};
    my $expected = $IP{'HEX'};
    is ip2hex($arg), $expected, "ip2hex('$arg') returns '$expected'";
}

TEST_HEX2MAC : {
    my $arg = $MAC{'HEX'};
    my $expected  = $MAC{'STR1'};
    is hex2mac($arg), $expected, "hex2mac('$arg') returns '$expected'";
}

TEST_MAC2HEX : {
    my $arg1 = $MAC{'STR1'};
    my $arg2 = $MAC{'STR2'};
    my $expected = $MAC{'HEX'};
    is mac2hex($arg1), $expected, "mac2hex('$arg1') returns '$expected'";
    is mac2hex($arg2), $expected, "mac2hex('$arg2') returns '$expected'";
    ok !defined(mac2hex()), "mac2hex() returns undef";
    ok !defined(mac2hex(undef)), "mac2hex(undef) returns undef";
    for my $bad_mac (qw( 11.22.33.44.55 11.22.33.44.55.66.77 ga:rb:ag:ed:um:p0 )) {
        my $got = mac2hex($bad_mac);
        is $got, undef, "mac2hex('$bad_mac') returns undef";
    }
}

TEST_MAC2MAC : {
    my $arg = $MAC{'STR2'};
    my $expected = $MAC{'STR1'};
    is mac2mac($arg), $expected, "mac2mac('$arg') returns '$expected'";
}

TEST_HEX_ADDR_IN_NET : {
    my $net         = '10.168.100.0';
    my $ip_yes      = '10.168.100.10';
    my $ip_no       = '192.170.120.3';
    my $hex_net     = ip2hex($net);
    my $hex_ip_yes  = ip2hex($ip_yes);
    my $hex_ip_no   = ip2hex($ip_no);

    ok hex_addr_in_net($hex_ip_yes, $hex_net, 24), "$hex_ip_yes in $hex_net/24";
    ok hex_addr_in_net($hex_ip_yes, $hex_net, 26), "$hex_ip_yes in $hex_net/26";
    ok !hex_addr_in_net($hex_ip_no, $hex_net, 24), "$hex_ip_no not in $hex_net/24";

    ok hex_addr_in_net($hex_ip_yes, $hex_net, 3), "$hex_ip_yes in $hex_net/3";
    ok !hex_addr_in_net($hex_ip_no, $hex_net, 3), "$hex_ip_no not in $hex_net/3";
}

TEST_IS_VALID_INT : {
    my $err;
    my $arg;
    my $num;

    $arg = '12345';
    $num = is_valid_int($arg, -err => \$err);
    ok defined($num), "is_valid_int('$arg') => defined";
    cmp_ok $num, '==', $arg, "is_valid_int('$arg') = $arg";

    $arg = '';
    $num = is_valid_int($arg, -err => \$err);
    ok !defined($num), "is_valid_int('$arg') => undef";
    like $err, qr/not a valid (integer|number)/,
        "is_valid_int('$arg') returns valid error message";

    $num = is_valid_int(undef, -err => \$err);
    ok(!defined($num), 'is_valid_int(undef) => undef');

    $num = is_valid_int();
    ok(!defined($num), 'is_valid_int() => undef');

    $err = undef;
    $arg = '12345-boo';
    $num = is_valid_int($arg, -err => \$err);
    ok !defined($num), "is_valid_int('$arg') => undef";
    like $err, qr/not a valid (integer|number)/,
        "is_valid_int('$arg') returns valid error message";

    #########################################################################

    my $min = 1;
    my $max = 12345;

    $err = undef;
    $arg = '12345';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok defined($num),
        "is_valid_int('$arg') => valid with $min-$max (inclusive) bounds"
        or diag("error: $err");

    $err = undef;
    $arg = '0';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_int('$arg') => invalid with $min-$max (inclusive) bounds";
    like $err, qr/too small$/,
        "is_valid_int('$arg') => 'too small' error";

    $err = undef;
    $arg = '12346';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_int('$arg') => invalid with $min-$max (inclusive) bounds";

    like $err, qr/too large$/,
        "is_valid_int('$arg') => 'too large' error";

    #########################################################################

    $err = undef;
    $arg = '12345';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 0);
    ok defined($num),
        "is_valid_int('$arg') => valid without -inclusive";

    $err = undef;
    $arg = '12344';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 0,
                -min => $min,
                -max => $max);
    ok defined($num),
        "is_valid_int('$arg') => valid with $min-$max (exclusive) bounds";

    $err = undef;
    $arg = '1';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 0,
                -min => 1);
    ok !defined($num),
        "is_valid_int('$arg') => invalid with $min-$max (exclusive) bounds";
    like $err, qr/too small$/,
        "is_valid_int('$arg') => 'too small' error";

    $err = undef;
    $arg = '12346';
    $num = is_valid_int($arg,
                -err => \$err,
                -inclusive => 0,
                -max => 12345);
    ok !defined($num),
        "is_valid_int('$arg') => invalid with $min-$max (exclusive) bounds";
    like $err, qr/too large$/,
        "is_valid_int('$arg') => 'too large' error";
}

TEST_IS_VALID_FLOAT : {
    my $err;
    my $num;
    my $arg;

    #########################################################################

    for my $arg (qw( 123.45 .45 123.45e-5 )) {
        $num = is_valid_float($arg, -err => \$err);
        ok defined($num), "is_valid_float($arg) => defined";
        cmp_ok $num, '==', $arg, "is_valid_float($arg) = $arg";
    }

    $arg = '';
    $num = is_valid_float($arg, -err => \$err);
    ok !defined($num), "is_valid_float('$arg') => undef";
    like $err, qr/not a valid number/,
        "is_valid_float('$arg') returns valid error message";

    $num = is_valid_float(undef, -err => \$err);
    ok !defined($num), "is_valid_float(undef) => undef" ;
    like $err, qr/not a valid number/,
        "is_valid_float(undef) returns valid error message";

    $num = is_valid_float();
    ok !defined($num), "is_valid_float() => undef";
    like $err, qr/not a valid number/,
        "is_valid_float() returns valid error message";

    $arg = '123.45-boo';
    $err = undef;
    $num = is_valid_float($arg, -err => \$err);
    ok !defined($num), "is_valid_float('$arg') => undef";
    like $err, qr/not a valid number/,
        "is_valid_float('$arg') returns valid error message";

    #########################################################################

    $err = undef;
    my $min = 1;
    my $max = 123.45;
    $arg = '123.45';
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok defined($num),
        "is_valid_float('$arg') => valid with $min-$max (inclusive) bounds"
            or diag("error: $err");

    $err = undef;
    $arg = '0';
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_float('$arg') => invalid with $min-$max (inclusive) bounds";
    like $err, qr/too small$/,
        "is_valid_float('$arg') returns valid error message";

    $err = undef;
    $arg = '123.46';
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 1,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_float('$arg') => invalid with $min-$max (inclusive) bounds";
    like $err, qr/too large$/,
        "is_valid_float('$arg') returns valid error message";

    #########################################################################

    $arg = '123.45';
    $err = undef;
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 0);
    ok defined($num),
        "is_valid_float('$arg') => valid without -inclusive";

    $arg = '123.44';
    $err = undef;
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 0,
                -min => $min,
                -max => $max);
    ok defined($num),
        "is_valid_float('$arg') => valid with $min-$max (exclusive) bounds";


    $arg = '1';
    $err = undef;
    $num = is_valid_float($arg,
                -err => \$err,
                -inclusive => 0,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_float('$arg') => invalid with $min-$max (exclusive) bounds";
    like $err, qr/too small$/,
        "is_valid_float('$arg') => 'too small' error";

    $err = undef;
    $arg = '123.46';
    $num = is_valid_float($arg,
                -err => \$err,
                -min => $min,
                -max => $max);
    ok !defined($num),
        "is_valid_float('$arg') => invalid with $min-$max (exclusive) bounds";
    like $err, qr/too large$/,
        "is_valid_float('$arg') => 'too large' error";
}

TEST_FORMAT_TIME : {
    my $self = shift;

    my $timeval = 1300891278;
    my $expected = strftime("%Y-%m-%d@%H:%M:%S%z", localtime($timeval));
    my $got = format_time($timeval);
    is($got, $expected, 'format_time with defaults');

    $expected = strftime("%Y-%m-%d*%H:%M:%S%z", localtime($timeval));
    $got = format_time($timeval, '*');
    is($got, $expected, 'format_time with explicit separator');

    $expected = 'never';
    $got = format_time();
    is($got, $expected, qq{format_time() = '$expected'});

    $got = format_time(undef);
    is($got, $expected, qq{format_time(undef) = '$expected'});

    $got = format_time(-1);
    is($got, $expected, qq{format_time(-1) = '$expected'});
}

TEST_RELATIVE_TIME : {
    my $diff = 5 + 49*60 + 4*3600 + 1*3600*24;
    my $time;
    my $expected;
    my $got;

    $time = time-$diff;
    $expected = '1 day, 04:49:05 ago';
    $got = relative_time($time);
    is $got, $expected, qq{relative_time($time) = '$expected'};

    $time = time+$diff;
    $expected = '1 day, 04:49:05 from now';
    $got = relative_time($time);
    is($got, $expected, qq{relative_time($time) = '$expected'});

    $diff = 5 + 49*60 + 4*3600;

    $time = time-$diff;
    $expected = '04:49:05 ago';
    $got = relative_time($time);
    is($got, $expected, qq{relative_time($time) = '$expected'});

    $time = time+$diff;
    $expected = '04:49:05 from now';
    $got = relative_time($time);
    is($got, $expected, qq{relative_time($time) = '$expected'});

    $diff = 5 + 49*60 + 4*3600 + 2*3600*24;

    $time = time-$diff;
    $expected = '2 days, 04:49:05 ago';
    $got = relative_time($time);
    is($got, $expected, qq{relative_time($time) = '$expected'});

    $time = time+$diff;
    $expected = '2 days, 04:49:05';
    $got = relative_time($time, 0);
    is($got, $expected, qq{relative_time($time, 0) = '$expected'});

    $expected = 'never';
    $got = relative_time(undef, 0);
    is($got, $expected, qq{relative_time(undef, 0) = '$expected'});

    $expected = 'never';
    $got = relative_time(0);
    is($got, $expected, qq{relative_time(0) = '$expected'});

    $expected = 'never';
    $got = relative_time();
    is($got, $expected, qq{relative_time() = '$expected'});
}

TEST_IS_VALID_IP : {
    my $valid_ip    = '192.168.100.2';
    my $invalid_ip  = '192.168.100.300';
    my $invalid_ip2 = 'nope';
    my $valid_net   = '192.168.100.0/25';
    my $valid_net_outside = '192.168.100.128/25';
    my $invalid_net = '192.168.300.0/25';

    my $got = is_valid_ip($valid_ip);
    is $got, $valid_ip, "is_valid_ip('$valid_ip') => '$valid_ip'";

    $got = is_valid_ip($invalid_ip);
    ok !defined($got), "is_valid_ip('$invalid_ip') => undef";

    $got = is_valid_ip($invalid_ip2);
    ok !defined($got), "is_valid_ip('$invalid_ip2') => undef";

    $got = is_valid_ip('');
    ok !defined($got), "is_valid_ip('') => undef";

    $got = is_valid_ip(undef);
    ok !defined($got), "is_valid_ip(undef) => undef";

    $got = is_valid_ip();
    ok !defined($got), "is_valid_ip() => undef";

    $got = is_valid_ip($valid_ip, -network => $valid_net);
    is $got, $valid_ip,
        "is_valid_ip('$valid_ip', -network => '$valid_net') => $valid_ip";

    my $warning = warning {
        $got = is_valid_ip($valid_ip, -network => $invalid_net)
    };

    like($warning,
        qr/\*\* INTERNAL.*-network argument .* is not valid/,
        "is_valid_ip('$valid_ip', -network => '$invalid_net') gives a warning"
    );

    $got = is_valid_ip($valid_ip, -network => $valid_net_outside);
    ok !defined($got),
        "is_valid_ip: '$valid_ip' is outside '$valid_net_outside'";
}

TEST_IS_VALID_BOOL : {
    my @true_bools  = qw( 1 20 true TRuE yes YES YeS on ON oN );
    my @false_bools = qw( 0 -1 false fAlSe no nO off OFF oFf );
    my @invalid_bools = (undef, '', 'bad');
    my $expected;

    $expected = 1;
    for my $arg (@true_bools) {
        my $err = undef;
        my $got = is_valid_bool($arg, -err => \$err);
        is $got, 1, "is_valid_bool('$arg') returns 1";
    }
    $expected = 0;
    for my $arg (@false_bools) {
        my $err = undef;
        my $got = is_valid_bool($arg, -err => \$err);
        is $got, 0, "is_valid_bool('$arg') returns 0";
    }

    for my $arg (@invalid_bools) {
        my $err = undef;
        my $got = is_valid_bool($arg, -err => \$err);
        my $argstr = defined $arg ? qq{'$arg'} : 'undef';
        is $got, undef, "is_valid_bool($argstr) returns undef";
    }
}

done_testing();
