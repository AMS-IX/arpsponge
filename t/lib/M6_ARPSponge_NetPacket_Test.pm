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

  # Encode request without defaults.
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

  # Encode request with defaults.
    my $arp_hash_2 = {
        opcode => ARP_OPCODE_REQUEST,
        spa    => $self->{'IP1_HEX'},
        sha    => $self->{'MAC1_HEX'},
        tpa    => $self->{'IP2_HEX'},
        tha    => ETH_ADDR_BROADCAST,
    };
    my $data_2 = encode_arp($arp_hash_2);
    ok(defined($data_2), "encode_arp with defaults");

  # Check if encoding with and without defaults is equivalent.
    is($data_1, $data_2, "encode_arp with and without defaults");

  # Decode and see if result is same as original input.
    my $decode = decode_arp($data_1);
    is_deeply($decode, $arp_hash_1, 'decode_arp(encode_arp) idempotency');

  # Decode with empty input (should return empty hash).
    $decode = decode_arp();
    is_deeply($decode, {}, 'decode_arp() returns empty hash');

    $decode = decode_arp(undef);
    is_deeply($decode, {}, 'decode_arp(undef) returns empty hash');
}

sub parse_frame_data {
    my $self = shift;
    my $frame_str = shift;

  # Parse it to a binary string.
    my $frame_data;
    for my $line ($frame_str =~ /^[\da-f]{4}\h\h((?:[\da-f]{2}\h)+)\h/gm) {
        $line =~ s/\s//g;
        $frame_data .= pack('H*', $line);
    }
    return $frame_data;
}


sub test_ethernet : Test(no_plan) {
    my $self = shift;

  # Captured frame data from tshark (-P -x).
    my $frame_str = q{
 65 31.031137000 SunrichT_23:cd:6d -> Broadcast    ARP 42 Who has 91.200.19.1?  Tell 91.200.19.209

0000  ff ff ff ff ff ff 00 0a cd 23 cd 6d 08 06 00 01   .........#.m....
0010  08 00 06 04 00 01 00 0a cd 23 cd 6d 5b c8 13 d1   .........#.m[...
0020  ff ff ff ff ff ff 5b c8 13 01                     ......[...
};

    my $frame_data = $self->parse_frame_data($frame_str);

    my $arp_hash = {
        htype  => ARP_HTYPE_ETHERNET,
        proto  => ARP_PROTO_IPv4,
        hlen   => ARP_HLEN_ETHERNET,
        plen   => ARP_PLEN_IPv4,
        opcode => ARP_OPCODE_REQUEST,
        sha    => mac2hex('00:0a:cd:23:cd:6d'),
        spa    => ip2hex('91.200.19.209'),
        tha    => ETH_ADDR_BROADCAST,
        tpa    => ip2hex('91.200.19.1'),
        data   => undef,
    };

    my $eth_hash = {
        src_mac  => $arp_hash->{'sha'},
        dest_mac => $arp_hash->{'tha'},
        type     => ETH_TYPE_ARP,
        data     => encode_arp($arp_hash),
    };

    my $eth_data = encode_ethernet($eth_hash);

    is($eth_data, $frame_data, 'encode_ethernet(ARP)');

    my $got_eth_hash = decode_ethernet($frame_data);
    is_deeply($got_eth_hash, $eth_hash, 'decode_ethernet(ARP)');

    $got_eth_hash = decode_ethernet(undef);
    is_deeply($got_eth_hash, {}, 'decode_ethernet(undef)');

    $got_eth_hash = decode_ethernet();
    is_deeply($got_eth_hash, {}, 'decode_ethernet()');
}


sub test_ipv4 : Test(no_plan) {
    my $self = shift;

  # Captured frame data from tshark (-P -x).
    my $frame_str = q{
  6 38.438265000 91.200.19.209 -> 91.200.16.50 TCP 74 [TCP Out-Of-Order] 54442→80 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=41428229 TSecr=0 WS=128

0000  00 1b 17 00 1a 31 00 0a cd 23 cd 6d 08 00 45 10   .....1...#.m..E.
0010  00 3c b1 c7 40 00 40 06 ad 51 5b c8 13 d1 5b c8   .<..@.@..Q[...[.
0020  10 32 d4 aa 00 50 ad 1e 94 c2 00 00 00 00 a0 02   .2...P..........
0030  72 10 db c1 00 00 02 04 05 b4 04 02 08 0a 02 78   r..............x
0040  25 05 00 00 00 00 01 03 03 07                     %.........
};

    my $frame_data = $self->parse_frame_data($frame_str);

    my $eth_hash = decode_ethernet($frame_data);
    my $ipv4_data = $eth_hash->{'data'};

    my $ip_hash = {
        ver     => 4,
        hlen    => 5,
        tos     => 0x10,
        len     => 60,
        id      => 0xb1c7,
        flags   => 0x02,
        foffset => 0,
        ttl     => 64,
        proto   => 6,
        cksum   => 0xad51,
        src_ip  => ip2hex('91.200.19.209'),
        dest_ip => ip2hex('91.200.16.50'),
        options => '',
        data    => substr($ipv4_data, 20),
    };

    my $got_ip_hash = decode_ipv4($ipv4_data);
    is_deeply($got_ip_hash, $ip_hash, 'decode_ipv4(SYN)');

    $got_ip_hash = decode_ipv4(undef);
    is_deeply($got_ip_hash, {}, 'decode_ipv4(undef)');

    $got_ip_hash = decode_ipv4();
    is_deeply($got_ip_hash, {}, 'decode_ipv4()');

  # Test whether we can really call the decode_ip alias.
    $got_ip_hash = decode_ipv4($ipv4_data);
    is_deeply($got_ip_hash, $ip_hash, 'decode_ip(SYN)');

  # Invalidate header length, just for kicks.
    substr($ipv4_data, 0, 1) = pack('H2', '44');
    $got_ip_hash = decode_ipv4($ipv4_data);
    is($got_ip_hash->{'ver'},  4, 'decode_ipv4 with bad hlen (ver)');
    is($got_ip_hash->{'hlen'}, 4, 'decode_ipv4 with bad hlen (hlen)');
    is($got_ip_hash->{'options'}, '', 'decode_ipv4 with bad hlen (options)');
}

1;
