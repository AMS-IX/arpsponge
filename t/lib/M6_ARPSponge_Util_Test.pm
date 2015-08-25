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

sub test_mac2hex : Test(2) {
    my $self = shift;
    my $arg1 = $self->{'MAC'}->{'STR1'};
    my $arg2 = $self->{'MAC'}->{'STR2'};
    my $expected = $self->{'MAC'}->{'HEX'};
    is(mac2hex($arg1), $expected, "mac2hex($arg1)");
    is(mac2hex($arg2), $expected, "mac2hex($arg2)");
}

sub test_mac2mac : Test(1) {
    my $self = shift;
    my $arg = $self->{'MAC'}->{'STR2'};
    my $expected = $self->{'MAC'}->{'STR1'};
    is(mac2mac($arg), $expected, "mac2mac($arg)");
}

sub test_hex_addr_in_net : Test(1) {
    my $self = shift;
    my $ip = $self->{'IP'}->{'STR'};
    my $net = $self->{'IP'}->{'NET'};
    my $len = $self->{'IP'}->{'LEN'};
    my $hex_ip  = ip2hex($ip);
    my $hex_net = ip2hex($net);
    ok(hex_addr_in_net($hex_ip, $hex_net, $len), "$hex_ip in $hex_net/$len");
}


1;
