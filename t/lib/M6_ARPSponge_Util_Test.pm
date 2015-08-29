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

package M6_ARPSponge_Util_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;
use Test::Warnings qw( :all );
use POSIX qw( strftime );

use M6::ARPSponge::Util qw(:all);

sub startup : Test(startup => 1) {
    my $self = shift;
    use_ok( 'M6::ARPSponge::Util', ':all' );

    $self->{'IP'}->{'STR'}   = '193.194.136.132';
    $self->{'IP'}->{'INT'}   = 3250751620;
    $self->{'IP'}->{'HEX'}   = 'c1c28884';
    $self->{'IP'}->{'NET'}   = '193.194.136.128';
    $self->{'IP'}->{'LEN'}   = 25;

    $self->{'MAC'}->{'STR1'} = 'a1:b2:03:04:e5:f6';
    $self->{'MAC'}->{'STR2'} = 'a1b2.304.e5f6';
    $self->{'MAC'}->{'HEX'}  = 'a1b20304e5f6';
}

sub test_int2ip : Test(1) {
    my $self = shift;
    my $arg = $self->{'IP'}->{'INT'};
    my $expected  = $self->{'IP'}->{'STR'};
    is(int2ip($arg), $expected, "int2ip($arg)");
}

sub test_ip2int : Test(1) {
    my $self = shift;
    my $arg = $self->{'IP'}->{'STR'};
    my $expected = $self->{'IP'}->{'INT'};
    is(ip2int($arg), $expected, "ip2int($arg)");
}

sub test_hex2ip : Test(1) {
    my $self = shift;
    my $arg = $self->{'IP'}->{'HEX'};
    my $expected  = $self->{'IP'}->{'STR'};
    is(hex2ip($arg), $expected, "hex2ip($arg)");
}

sub test_ip2hex : Test(1) {
    my $self = shift;
    my $arg = $self->{'IP'}->{'STR'};
    my $expected = $self->{'IP'}->{'HEX'};
    is(ip2hex($arg), $expected, "ip2hex($arg)");
}

sub test_hex2mac : Test(1) {
    my $self = shift;
    my $arg = $self->{'MAC'}->{'HEX'};
    my $expected  = $self->{'MAC'}->{'STR1'};
    is(hex2mac($arg), $expected, "hex2mac($arg)");
}

sub test_mac2hex : Test(5) {
    my $self = shift;
    my $arg1 = $self->{'MAC'}->{'STR1'};
    my $arg2 = $self->{'MAC'}->{'STR2'};
    my $expected = $self->{'MAC'}->{'HEX'};
    is(mac2hex($arg1), $expected, "mac2hex($arg1)");
    is(mac2hex($arg2), $expected, "mac2hex($arg2)");
    ok(!defined(mac2hex()), "mac2hex() => undef");
    ok(!defined(mac2hex(undef)), "mac2hex(undef) => undef");
    ok(!defined(mac2hex('aa.aa.bb.bb.cc')), "mac2hex('aa.aa.bb.bb.cc') => undef");
}

sub test_mac2mac : Test(1) {
    my $self = shift;
    my $arg = $self->{'MAC'}->{'STR2'};
    my $expected = $self->{'MAC'}->{'STR1'};
    is(mac2mac($arg), $expected, "mac2mac($arg)");
}

sub test_hex_addr_in_net : Test(5) {
    my $self = shift;
    my $net    = '10.168.100.0';
    my $ip_yes = '10.168.100.10';
    my $ip_no  = '192.170.120.3';
    my $hex_net    = ip2hex($net);
    my $hex_ip_yes = ip2hex($ip_yes);
    my $hex_ip_no  = ip2hex($ip_no);

    ok(hex_addr_in_net($hex_ip_yes, $hex_net, 24), "$hex_ip_yes in $hex_net/24");
    ok(hex_addr_in_net($hex_ip_yes, $hex_net, 26), "$hex_ip_yes in $hex_net/26");
    ok(!hex_addr_in_net($hex_ip_no, $hex_net, 24), "$hex_ip_no not in $hex_net/24");

    ok(hex_addr_in_net($hex_ip_yes, $hex_net, 3), "$hex_ip_yes in $hex_net/3");
    ok(!hex_addr_in_net($hex_ip_no, $hex_net, 3), "$hex_ip_no not in $hex_net/3");
}

sub test_is_valid_int : Test(19) {
    my $self = shift;

    my $err;
    my $num;

    $num = is_valid_int('12345', -err => \$err);
    ok(defined($num), 'is_valid_int("12345") => defined');
    cmp_ok($num, '==', 12345, 'is_valid_int("12345") = 12345');

    $num = is_valid_int('', -err => \$err);
    ok(!defined($num), 'is_valid_int("") => undef');
    like($err, qr/not a valid number/, 'err value');

    $num = is_valid_int(undef, -err => \$err);
    ok(!defined($num), 'is_valid_int(undef) => undef');

    $num = is_valid_int();
    ok(!defined($num), 'is_valid_int() => undef');

    $err = undef;
    $num = is_valid_int('12345-boo', -err => \$err);
    ok(!defined($num), 'is_valid_int("12345-boo") => undef');
    like($err, qr/not a valid number/, 'err value');

    #########################################################################

    $err = undef;
    $num = is_valid_int('12345', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 12345);
    ok(defined($num), 'valid with inclusive');

    $err = undef;
    $num = is_valid_int('0', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 12345);
    ok(!defined($num), 'too small with inclusive');
    like($err, qr/too small$/, 'err value');

    $err = undef;
    $num = is_valid_int('12346', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 12345);
    ok(!defined($num), 'too large with inclusive');
    like($err, qr/too large$/, 'err value');

    #########################################################################

    $err = undef;
    $num = is_valid_int('12345', 
                -err => \$err,
                -inclusive => 0);
    ok(defined($num), 'valid without inclusive');

    $err = undef;
    $num = is_valid_int('12344', 
                -err => \$err,
                -inclusive => 0,
                -min => 1,
                -max => 12345);
    ok(defined($num), 'valid with boundaries, without inclusive');

    $err = undef;
    $num = is_valid_int('1', 
                -err => \$err,
                -inclusive => 0,
                -min => 1);
    ok(!defined($num), 'too small without inclusive');
    like($err, qr/too small$/, 'err value');

    $err = undef;
    $num = is_valid_int('12346',
                -err => \$err,
                -inclusive => 0,
                -max => 12345);
    ok(!defined($num), 'too large without inclusive');
    like($err, qr/too large$/, 'err value');
}


sub test_is_valid_float : Test(23) {
    my $self = shift;

    my $err;
    my $num;

    #########################################################################

    $num = is_valid_float('123.45', -err => \$err);
    ok(defined($num), 'is_valid_float("123.45") => defined');
    cmp_ok($num, '==', 123.45, 'is_valid_float("123.45") = 123.45');

    $num = is_valid_float('.45', -err => \$err);
    ok(defined($num), 'is_valid_float(".45") => defined');
    cmp_ok($num, '==', .45, 'is_valid_float(".45") = .45');

    $num = is_valid_float('123.45e-5', -err => \$err);
    ok(defined($num), 'is_valid_float("123.45e-5") => defined');
    cmp_ok($num, '==', 123.45e-5, 'is_valid_float("123.45e-5") = 123.45e-5');

    $num = is_valid_float('', -err => \$err);
    ok(!defined($num), 'is_valid_float("") => undef');
    like($err, qr/not a valid number/, 'err value');

    $num = is_valid_float(undef, -err => \$err);
    ok(!defined($num), 'is_valid_float(undef) => undef');

    $num = is_valid_float();
    ok(!defined($num), 'is_valid_float() => undef');

    $err = undef;
    $num = is_valid_float('123.45-boo', -err => \$err);
    ok(!defined($num), 'is_valid_float("123.45-boo") => undef');
    like($err, qr/not a valid number/, 'err value');

    #########################################################################

    $err = undef;
    $num = is_valid_float('123.45', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 123.45);
    ok(defined($num), 'valid with inclusive');

    $err = undef;
    $num = is_valid_float('0', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 123.45);
    ok(!defined($num), 'too small with inclusive');
    like($err, qr/too small$/, 'err value');

    $err = undef;
    $num = is_valid_float('123.46', 
                -err => \$err,
                -inclusive => 1,
                -min => 1,
                -max => 123.45);
    ok(!defined($num), 'too large with inclusive');
    like($err, qr/too large$/, 'err value');

    #########################################################################

    $err = undef;
    $num = is_valid_float('123.45', 
                -err => \$err,
                -inclusive => 0);
    ok(defined($num), 'valid without inclusive');

    $err = undef;
    $num = is_valid_float('123.44', 
                -err => \$err,
                -inclusive => 0,
                -min => 1,
                -max => 123.45);
    ok(defined($num), 'valid with boundaries, without inclusive');

    $err = undef;
    $num = is_valid_float('1', 
                -err => \$err,
                -inclusive => 0,
                -min => 1);
    ok(!defined($num), 'too small without inclusive');
    like($err, qr/too small$/, 'err value');

    $err = undef;
    $num = is_valid_float('123.46',
                -err => \$err,
                -inclusive => 0,
                -max => 123.45);
    ok(!defined($num), 'too large without inclusive');
    like($err, qr/too large$/, 'err value');
}

sub test_format_time : Test(5) {
    my $self = shift;

    my $timeval = 1300891278;
    my $expected = strftime("%Y-%m-%d@%H:%M:%S", localtime($timeval));
    my $got = format_time($timeval);
    is($got, $expected, 'format_time with defaults');

    $expected = strftime("%Y-%m-%d*%H:%M:%S", localtime($timeval));
    $got = format_time($timeval, '*');
    is($got, $expected, 'format_time with explicit separator');

    $expected = 'never';
    $got = format_time();
    is($got, $expected, qq{format_time() = '$expected'});

    $got = format_time(undef);
    is($got, $expected, qq{format_time() = '$expected'});

    $got = format_time(-1);
    is($got, $expected, qq{format_time(-1) = '$expected'});
}

sub test_relative_time : Test(9) {
    my $diff = 5 + 49*60 + 4*3600 + 1*3600*24;

    my $expected = '1 day, 04:49:05 ago';
    my $got = relative_time(time-$diff);
    is($got, $expected, qq{relative_time() #1});

    $expected = '1 day, 04:49:05 from now';
    $got = relative_time(time+$diff);
    is($got, $expected, qq{relative_time() #2});

    $diff = 5 + 49*60 + 4*3600;

    $expected = '04:49:05 ago';
    $got = relative_time(time-$diff);
    is($got, $expected, qq{relative_time() #3});

    $expected = '04:49:05 from now';
    $got = relative_time(time+$diff);
    is($got, $expected, qq{relative_time() #4});
    
    $diff = 5 + 49*60 + 4*3600 + 2*3600*24;

    $expected = '2 days, 04:49:05 ago';
    $got = relative_time(time-$diff);
    is($got, $expected, qq{relative_time() #5});

    $expected = '2 days, 04:49:05';
    $got = relative_time(time+$diff, 0);
    is($got, $expected, qq{relative_time() #6});

    $expected = 'never';
    $got = relative_time(undef, 0);
    is($got, $expected, qq{relative_time() #7});

    $expected = 'never';
    $got = relative_time(0);
    is($got, $expected, qq{relative_time() #8});

    $expected = 'never';
    $got = relative_time();
    is($got, $expected, qq{relative_time() #9});
}

sub test_is_valid_ip : Test(no_plan) {
    my $ip_str1 = '192.168.100.2';
    my $ip_str2 = '192.168.100.300';

    my $got = is_valid_ip($ip_str1);
    is($got, $ip_str1, 'is_valid_ip #1');

    $got = is_valid_ip($ip_str2);
    ok(!defined($got), 'is_valid_ip #2');

    $got = is_valid_ip('');
    ok(!defined($got), 'is_valid_ip #3');

    $got = is_valid_ip(undef);
    ok(!defined($got), 'is_valid_ip #4');

    $got = is_valid_ip();
    ok(!defined($got), 'is_valid_ip #5');

    $got = is_valid_ip($ip_str1, -network => '192.168.100.0/25');
    is($got, $ip_str1, 'is_valid_ip #6');

    my $warning = warning { $got = is_valid_ip($ip_str1, -network => '192.168.300.0/25') };

    like($warning,
        qr/\*\* INTERNAL.*-network argument .* is not valid/,
        'is_valid_ip #7'
    );

    $got = is_valid_ip($ip_str1, -network => '192.168.200.0/24');
    ok(!defined($got), 'is_valid_ip #8');
}


1;
