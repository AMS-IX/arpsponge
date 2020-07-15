##############################################################################
#
# ARP Sponge network packet routines.
#
#   Copyright 2011-2016 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc
#   perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#   See the "Copying" file that came with this package.
#
# Most of the basic decoding was ripped from the original NetPacket::
# modules.
#
# S.Bakker.
#
###############################################################################
package M6::ARP::NetPacket;

use strict;
use Readonly;

BEGIN {
    use Exporter;

    our $VERSION = 1.04;
    our @ISA = qw( Exporter );

    my @functions = qw(
            decode_ethernet decode_ip decode_ipv4 decode_arp
            encode_ethernet encode_arp
        );

    my @variables = qw(
            $ETH_TYPE_IP
            $ETH_TYPE_IPv4
            $ETH_TYPE_ARP
            $ETH_TYPE_IPv6
            $ETH_ADDR_BROADCAST  $ETH_ADDR_NONE
            $IPv4_ADDR_BROADCAST $IPv4_ADDR_NONE
            $ARP_OPCODE_REQUEST  $ARP_OPCODE_REPLY
            $ARP_HTYPE_ETHERNET  $ARP_HLEN_ETHERNET
            $ARP_PROTO_IPv4      $ARP_PLEN_IPv4
            $ARP_PROTO_IP
        );

    our @EXPORT_OK = ( @functions, @variables );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
            'all'    => [ @EXPORT_OK ],
            'func'   => [ @functions ],
            'vars'   => [ @variables ],
        );
}

# The only things we're interested in right now...
Readonly our $ETH_TYPE_IP    => 0x0800;
Readonly our $ETH_TYPE_IPv4  => 0x0800;
Readonly our $ETH_TYPE_ARP   => 0x0806;
Readonly our $ETH_TYPE_IPv6  => 0x86dd;

Readonly our $ARP_OPCODE_REQUEST  => 1;
Readonly our $ARP_OPCODE_REPLY    => 2;
Readonly our $ARP_HTYPE_ETHERNET  => 1;
Readonly our $ARP_PROTO_IP        => $ETH_TYPE_IPv4;
Readonly our $ARP_PROTO_IPv4      => $ETH_TYPE_IPv4;
Readonly our $ARP_HLEN_ETHERNET   => 6;
Readonly our $ARP_PLEN_IPv4       => 4;

Readonly our $ETH_ADDR_BROADCAST  => 'ff' x $ARP_HLEN_ETHERNET;
Readonly our $IPv4_ADDR_BROADCAST => 'ff' x $ARP_PLEN_IPv4;
Readonly our $ETH_ADDR_NONE       => '00' x $ARP_HLEN_ETHERNET;
Readonly our $IPv4_ADDR_NONE      => '00' x $ARP_PLEN_IPv4;

=pod

=head1 NAME

M6::ARP::NetPacket - (partially) decode ethernet, IP and ARP packets

=head1 SYNOPSIS

 use M6::ARP::NetPacket qw( :all );
 use M6::ARP::Util qw( :all );

 $packet = ...;

 $eth_data = decode_ethernet($packet);

 if ( $eth_data->{type} == $ETH_TYPE_IPv4 ) {
    $ip_data = decode_ipv4( $eth_data->{'data'} );

    printf( "%s -> %s, %d bytes (including IP header)\n",
            hex2ip( $ip_data->{'src_ip'} ),
            hex2ip( $ip_data->{'dest_ip'} ),
            $ip_data->{'len'} );
 }

 if ( $eth_data->{type} == $ETH_TYPE_ARP ) {
    $arp_data = decode_arp( $eth_data->{'data'} );

    if ($arp_data->{opcode} == $ARP_OPCODE_REQUEST) {
        printf( "ARP WHO-HAS %s TELL %s\@%s\n",
                hex2ip( $arp_data->{'tpa'} ),
                hex2ip( $arp_data->{'spa'} ),
                hex2mac( $arp_data->{'sha'} ) );
    }
    else {
        printf( "ARP %s IS-AT %s\n",
                hex2ip( $arp_data->{'spa'} ),
                hex2ip( $arp_data->{'sha'} ) );
    }
 }

=head1 DESCRIPTION

This module defines a number of routines to decode raw pcap packet data
on Ethernet, IP and ARP level.

The semantics are similar to those of the L<NetPacket>(3) family, except that:

=over

=item 1.

All IP and MAC addresses are decoded as hex strings (as opposed to what e.g.
L<NetPacket::IP>(3) does).

=item 2.

We decode only a minimal subset of a packet, just enough for the
L<arpsponge>(1)'s purposes.

=back

=head1 VARIABLES

The variables below can be imported individually, by using the C<:vars> or C<:all> tags:

  use M6::ARP::NetPacket qw( :vars );
  use M6::ARP::NetPacket qw( :all );

Note that these variables are all read-only.

=over

=item X<$ETH_TYPE_IP>I<$ETH_TYPE_IP>, X<$ETH_TYPE_IPv4>I<$ETH_TYPE_IPv4>

Ethernet C<type> for IPv4 frames.

=item X<$ETH_TYPE_IPv6>I<$ETH_TYPE_IPv6>

Ethernet C<type> for IPv6 frames.

=item X<$ETH_TYPE_ARP>I<$ETH_TYPE_ARP>

Ethernet C<type> for ARP frames.

=item X<$ETH_ADDR_BROADCAST>I<$ETH_ADDR_BROADCAST>

Hex string representing the ethernet broadcast address ('ff' x 6).

=item X<$IPv4_ADDR_BROADCAST>I<$IPv4_ADDR_BROADCAST>

Hex string representing the IPv4 broadcast address ('ff' x 4).

=item X<$ETH_ADDR_NONE>I<$ETH_ADDR_NONE>

Hex string representing the "zero" ethernet address ('00' x 6).

=item X<$IPv4_ADDR_NONE>I<$IPv4_ADDR_NONE>

Hex string representing the IPv4 "zero" address ('00' x 4).

=item X<$ARP_OPCODE_REQUEST>I<$ARP_OPCODE_REQUEST>

ARP C<opcode> for ARP requests.

=item X<$ARP_OPCODE_REPLY>I<$ARP_OPCODE_REPLY>

ARP C<opcode> for ARP replies.

=item X<$ARP_HTYPE_ETHERNET>I<$ARP_HTYPE_ETHERNET>

ARP C<htype> for Ethernet hardware addresses.

=item X<$ARP_PROTO_IP>I<$ARP_PROTO_IP>, X<$ARP_PROTO_IPv4>I<$ARP_PROTO_IPv4>

ARP C<proto> for IPv4 requests/replies.

=item X<$ARP_HLEN_ETHERNET>I<$ARP_HLEN_ETHERNET>

Ethernet protocol address length in bytes (6).

=item X<$ARP_PLEN_IPv4>I<$ARP_PLEN_IPv4>

IP protocol address length in bytes (4).

=back

=head1 FUNCTIONS

The functions below can be imported individually, by using the C<:func> or C<:all> tags:

  use M6::ARP::NetPacket qw( :all );
  use M6::ARP::NetPacket qw( :func );

All functions return a hash ref (not an object!) with a minimal set of fields
set. They do not set C<_parent> or C<_frame>.

=over

=item X<decode_ethernet>B<decode_ethernet> ( I<DATA> )

(TCP/IP Illustrated, Volume 1, Section 2.2, p21-23.)

Decode I<DATA> as a raw Ethernet frame. Returns a hash with the following
fields:

=over 12

=item C<src_mac>

Source MAC address as a 12 digit, lowercase hex string.

=item C<dest_mac>

Destination MAC address as a 12 digit, lowercase hex string.

=item C<type>

Integer denoting the Ethernet type field.

=item C<data>

Payload data of the Ethernet frame.

=back

=cut

sub decode_ethernet {
    my ($pkt) = @_;
    return {} if !defined $pkt;

    my %self = ();
    # Much faster than the "Nn" + sprintf() trick.
    @self{'dest_mac','src_mac','type','data'} = unpack('H12H12na*', $pkt);
    return \%self;
}

###############################################################################

=item X<encode_ethernet>B<encode_ethernet> ( I<HASHREF> )

(TCP/IP Illustrated, Volume 1, Section 2.2, p21-23.)

Encode I<HASHREF> as a raw Ethernet frame. Returns a scalar with
the raw data. I<HASHREF> should point to a hash with the following fields:

=over 12

=item C<src_mac>

Source MAC address as a 12 digit, lowercase hex string.

=item C<dest_mac>

Destination MAC address as a 12 digit, lowercase hex string.

=item C<type>

Integer denoting the Ethernet type field.

=item C<data>

Payload data of the Ethernet frame.

=back

=cut

sub encode_ethernet {
    my ($self) = @_;

    return pack( 'H12H12na*', @{$self}{qw( dest_mac src_mac type data )} );
}

###############################################################################

=item X<decode_ip>B<decode_ip> ( I<DATA> )

Synonymous with L<decode_ipv4()|/decode_ipv4>.

=cut

sub decode_ip { &decode_ipv4 }

=item X<decode_ipv4>B<decode_ipv4> ( I<DATA> )

(TCP/IP Illustrated, Volume 1, Section 3.2, p34-37.)

Decode I<DATA> as a raw IPv4 packet. Returns a hash with the following
fields:

=over 12

=item C<ver>

IP version (4, duh).

=item C<hlen>

Header length.

=item C<tos>

Type of Service.

=item C<len>

IP packet length.

=item C<id>

IP datagram identification.

=item C<foffset>

Fragment offset.

=item C<ttl>

Time To Live.

=item C<proto>

IP protocol field.

=item C<cksum>

IP checksum.

=item C<src_ip>

Source IP address as an 8 digit, lowercase hex string.

=item C<dest_ip>

Destination IP address as an 8 digit, lowercase hex string.

=item C<options>

IP options field.

=item C<data>

Payload data of the IP datagram.

=back

=cut

sub decode_ipv4 {
    my ($pkt) = @_;

    return {} if ! defined $pkt;

    my %self;

    # Unpack IP addresses directly as "H8".
    (
        my $tmp,
        @self{qw(tos len id foffset ttl proto cksum src_ip dest_ip options)}
    ) = unpack('CCnnnCCnH8H8a*', $pkt);

    # Extract bit fields
    $self{ver} = ($tmp & 0xf0) >> 4;
    $self{hlen} = $tmp & 0x0f;

    $self{flags} = $self{foffset} >> 13;
    $self{foffset} = ($self{foffset} & 0x1fff) << 3;

    # Decode variable length header options and remaining data in field

    # Option length is number of 32 bit words
    my $olen = $self{hlen}*4 - 20;
       $olen = 0 if $olen < 0;  # Check for bad hlen

    @self{qw(options data)}
        = unpack("a${olen}a*", $self{options});

    return \%self;
}

###############################################################################

=item X<decode_arp>B<decode_arp> ( I<DATA> )

(TCP/IP Illustrated, Volume 1, Section 4.4, p56-57.)

Decode I<DATA> as a raw ARP packet. Returns a hash with the following
fields:

=over 12

=item C<htype>

Hardware type field. This routine is only designed for
I<$ARP_HTYPE_ETHERNET>.

=item C<proto>

Type of protocol address. This routine is only designed for
I<$ARP_PROTO_IPv4>.

=item C<hlen>, C<plen>

Hardware address length and protocol address length (in octets). For IPv4
on Ethernet these should be I<$ARP_HLEN_ETHERNET> and I<$ARP_PLEN_IPv4>,
respectively.

=item C<opcode>

Operation type: one of I<$ARP_OPCODE_REQUEST> or I<$ARP_OPCODE_REPLY>.

=item C<sha>

Source hardware (MAC) address
as a 12 digit, lowercase hex string.

=item C<spa>

Source protocol (IP) address
as an 8 digit, lowercase hex string.

=item C<tha>

Target hardware (MAC) address
as a 12 digit, lowercase hex string.

=item C<tpa>

Target protocol (IP) address
as an 8 digit, lowercase hex string.

=item C<data>

Payload data (always C<undef>)

=back

In theory the ARP packet could be for an AppleTalk address over Token Ring, but
in practice (and our use case), we only see IP over Ethernet.

Still, it pays to check the C<proto> and C<htype> fields, just to make sure you
don't get nonsense.

=cut

sub decode_arp {
    my ($pkt) = @_;
    return {} if !defined $pkt;

    my %self;

    # @self{qw( htype proto hlen plen opcode sha spa tha tpa )}
    #   = unpack('nnCCnH12H8H12H8', $pkt);

    # 99 out of 100 times hlen is 6 and plen is 4 (IP over ethernet),
    # but just in case:
    (
        @self{qw( htype proto hlen plen opcode )},
        my $payload
    ) = unpack('nnCCna*', $pkt);

    # Take the long way home.
    my $spec = 'H'.($self{hlen}*2).'H'.($self{plen}*2);
    @self{qw( sha spa tha tpa )} = unpack($spec.$spec, $payload);

    $self{data} = undef;
    return \%self;
}

###############################################################################

=item X<encode_arp>B<encode_arp> ( I<HASHREF> )

(TCP/IP Illustrated, Volume 1, Section 4.4, p56-57.)

Encode I<HASHREF> as a raw ARP packet. Returns a scalar with
the raw data. I<HASHREF> should point to a hash with the following fields:

=over 12

=item C<htype>

(optional, default value I<$ARP_HTYPE_ETHERNET>)

Hardware type field. Only I<$ARP_HTYPE_ETHERNET> is currently supported.

=item C<proto>

(optional, default value I<$ARP_PROTO_IPv4>)

Type of protocol address. Only I<$ARP_PROTO_IPv4> is currently supported.

=item C<hlen>, C<plen>

(optional, default values I<$ARP_HLEN_ETHERNET> and I<$ARP_PLEN_IPv4>)

Hardware address length and protocol address length (in octets). For IPv4
on Ethernet these should be I<$ARP_HLEN_ETHERNET> and I<$ARP_PLEN_IPv4>,
respectively.

=item C<opcode>

Operation type: one of I<$ARP_OPCODE_REQUEST> or I<$ARP_OPCODE_REPLY>.

=item C<sha>

Source hardware (MAC) address
as a 12 digit, lowercase hex string.

=item C<spa>

Source protocol (IP) address
as an 8 digit, lowercase hex string.

=item C<tha>

Target hardware (MAC) address
as a 12 digit, lowercase hex string.

=item C<tpa>

Target protocol (IP) address
as an 8 digit, lowercase hex string.

=back

In theory the ARP packet could be for an AppleTalk address over Token Ring, but
in practice (and our use case), we only see IP over Ethernet.

=cut

sub encode_arp {
    my ($self) = @_;

    $self->{htype} //= $ARP_HTYPE_ETHERNET;
    $self->{proto} //= $ARP_PROTO_IPv4;

    $self->{hlen}  //= $ARP_HLEN_ETHERNET;
    $self->{plen}  //= $ARP_PLEN_IPv4;

    my $spec = 'H'.($self->{hlen}*2).'H'.($self->{plen}*2);
    return pack("nnCCn$spec$spec",
        @{$self}{qw( htype proto hlen plen opcode sha spa tha tpa )}
    );
}

###############################################################################

1;

__END__

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<M6::ARP::Sponge(3)|M6::ARP::Sponge>,
L<M6::ARP::Util(3)|M6::ARP::Util>,
L<NetPacket(3)|NetPacket>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
