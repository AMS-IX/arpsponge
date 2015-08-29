#===============================================================================
#       Module:  M6_ARPSponge_NetPacket_Test.pm
#
#  Description:  Test class for M6::ARPSponge::NetPacket
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

package M6_ARPSponge_NetPacket_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;

use M6::ARPSponge::Util qw(:all);
use M6::ARPSponge::NetPacket qw(:all);

sub startup : Test(startup) {
    my $self = shift;

    $self->{'IP1_STR'}   = '192.168.136.1';
    $self->{'IP1_HEX'}   = ip2hex($self->{'IP1_STR'});

    $self->{'IP2_STR'}   = '192.168.136.2';
    $self->{'IP2_HEX'}   = ip2hex($self->{'IP2_STR'});

    $self->{'MAC1_STR'}  = 'a1:b2:03:04:e5:f6';
    $self->{'MAC1_HEX'}  = mac2hex($self->{'MAC1_STR'});

    $self->{'MAC2_STR'}  = 'a1:b2:03:04:e5:f7';
    $self->{'MAC2_HEX'}  = mac2hex($self->{'MAC2_STR'});
}

sub test_arp : Test(no_plan) {
    my $self = shift;
    my $arp_hash_1 = {
        htype => ARP_HTYPE_ETHERNET,
        proto => ARP_PROTO_IPv4,
        hlen  => ARP_HLEN_ETHERNET,
        plen  => ARP_PLEN_IPv4,
        opcode => ARP_OPCODE_REQUEST,
        spa    => $self->{'IP1_HEX'},
        sha    => $self->{'MAC1_HEX'},
        tpa    => $self->{'IP2_HEX'},
        tha    => ETH_ADDR_BROADCAST,
        data   => undef,
    };
    my $data_1 = encode_arp($arp_hash_1);
    ok(defined($data_1), "encode_arp without defaults");

    my $arp_hash_2 = {
        opcode => ARP_OPCODE_REQUEST,
        spa    => $self->{'IP1_HEX'},
        sha    => $self->{'MAC1_HEX'},
        tpa    => $self->{'IP2_HEX'},
        tha    => ETH_ADDR_BROADCAST,
    };
    my $data_2 = encode_arp($arp_hash_2);
    ok(defined($data_2), "encode_arp with defaults");

    is($data_1, $data_2, "encode_arp with and without defaults");

    my $decode = decode_arp($data_1);
    is_deeply($decode, $arp_hash_1, 'decode_arp(encode_arp) idempotency');

    $decode = decode_arp();
    is_deeply($decode, {}, 'decode_arp() returns empty hash');

    $decode = decode_arp(undef);
    is_deeply($decode, {}, 'decode_arp(undef) returns empty hash');
}

1;
