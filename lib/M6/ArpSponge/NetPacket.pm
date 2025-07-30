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
package M6::ArpSponge::NetPacket;

use 5.014;
use warnings;

use M6::ArpSponge;

our $VERSION = $M6::ArpSponge::VERSION;

use Exporter 'import';

BEGIN {
    my @functions = qw(
        decode_ethernet decode_ipv4 decode_arp
        encode_ethernet encode_arp
    );

    my @constants = qw(
        ETH_TYPE_IP
        ETH_TYPE_IPV4
        ETH_TYPE_ARP
        ETH_TYPE_IPV6
        ETH_ADDR_BROADCAST  ETH_ADDR_NONE
        IPV4_ADDR_BROADCAST IPV4_ADDR_NONE
        ARP_OPCODE_REQUEST  ARP_OPCODE_REPLY
        ARP_HTYPE_ETHERNET  ARP_HLEN_ETHERNET
        ARP_PROTO_IPV4      ARP_PLEN_IPV4
        ARP_PROTO_IP
    );

    our @EXPORT_OK = ( @functions, @constants );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
        'all'    => [ @EXPORT_OK ],
        'func'   => [ @functions ],
        'const'  => [ @constants ],
    );
}

# The only things we're interested in right now...
use constant ETH_TYPE_IP    => 0x0800;
use constant ETH_TYPE_IPV4  => 0x0800;
use constant ETH_TYPE_ARP   => 0x0806;
use constant ETH_TYPE_IPV6  => 0x86dd;

use constant ARP_OPCODE_REQUEST  => 1;
use constant ARP_OPCODE_REPLY    => 2;
use constant ARP_HTYPE_ETHERNET  => 1;
use constant ARP_PROTO_IP        => ETH_TYPE_IPV4;
use constant ARP_PROTO_IPV4      => ETH_TYPE_IPV4;
use constant ARP_HLEN_ETHERNET   => 6;
use constant ARP_PLEN_IPV4       => 4;

use constant ETH_ADDR_BROADCAST  => 'ff' x ARP_HLEN_ETHERNET;
use constant IPV4_ADDR_BROADCAST => 'ff' x ARP_PLEN_IPV4;
use constant ETH_ADDR_NONE       => '00' x ARP_HLEN_ETHERNET;
use constant IPV4_ADDR_NONE      => '00' x ARP_PLEN_IPV4;


sub decode_ethernet {
    my ($pkt) = @_;
    return {} if !defined $pkt;

    my %self = ();
    # Much faster than the "Nn" + sprintf() trick.
    @self{'dest_mac','src_mac','type','data'} = unpack('H12H12na*', $pkt);
    return \%self;
}


sub encode_ethernet {
    my ($self) = @_;

    return pack( 'H12H12na*', @{$self}{qw( dest_mac src_mac type data )} );
}


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

sub encode_arp {
    my ($self) = @_;

    $self->{htype} //= ARP_HTYPE_ETHERNET;
    $self->{proto} //= ARP_PROTO_IPV4;

    $self->{hlen}  //= ARP_HLEN_ETHERNET;
    $self->{plen}  //= ARP_PLEN_IPV4;

    my $spec = 'H'.($self->{hlen}*2).'H'.($self->{plen}*2);
    return pack("nnCCn$spec$spec",
        @{$self}{qw( htype proto hlen plen opcode sha spa tha tpa )}
    );
}

1;

__END__

=head1 NAME

M6::ArpSponge::NetPacket - (partially) decode ethernet, IP and ARP packets

=head1 SYNOPSIS

 use M6::ArpSponge::NetPacket qw( :all );
 use M6::ArpSponge::Util qw( :all );

 $packet = ...;

 $eth_data = decode_ethernet($packet);

 if ( $eth_data->{type} == ETH_TYPE_IPV4 ) {
    $ip_data = decode_ipv4( $eth_data->{'data'} );

    printf( "%s -> %s, %d bytes (including IP header)\n",
            hex2ip( $ip_data->{'src_ip'} ),
            hex2ip( $ip_data->{'dest_ip'} ),
            $ip_data->{'len'} );
 }

 if ( $eth_data->{type} == ETH_TYPE_ARP ) {
    $arp_data = decode_arp( $eth_data->{'data'} );

    if ($arp_data->{opcode} == ARP_OPCODE_REQUEST) {
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

The semantics are similar to those of the L<B<NetPacket>(3)|NetPacket>
family, except that:

=over

=item 1.

All IP and MAC addresses are decoded as hex strings (as opposed to what e.g.
L<B<NetPacket::IP>(3)|NetPacket::IP> does).

=item 2.

We decode only a minimal subset of a packet, just enough for the
L<B<arpsponge>(1)|arpsponge>'s purposes.

=back

=head1 CONSTANTS

The constants below can be imported individually, by using the C<:const> or C<:all> tags:

  use M6::ArpSponge::NetPacket qw( :const );
  use M6::ArpSponge::NetPacket qw( :all );

=over

=item B<ETH_TYPE_IP>, B<ETH_TYPE_IPV4>
X<ETH_TYPE_IP>X<ETH_TYPE_IPV4>

Ethernet C<type> for IPv4 frames.

=item B<ETH_TYPE_IPV6>
X<ETH_TYPE_IPV6>

Ethernet C<type> for IPv6 frames.

=item B<ETH_TYPE_ARP>
X<ETH_TYPE_ARP>

Ethernet C<type> for ARP frames.

=item B<ETH_ADDR_BROADCAST>
X<ETH_ADDR_BROADCAST>

Hex string representing the Ethernet broadcast address (C<'ff' x 6>).

=item B<IPV4_ADDR_BROADCAST>
X<IPV4_ADDR_BROADCAST>

Hex string representing the IPv4 broadcast address (C<'ff' x 4>).

=item B<ETH_ADDR_NONE>
X<ETH_ADDR_NONE>

Hex string representing the "zero" ethernet address (C<'00' x 6>).

=item B<IPV4_ADDR_NONE>
X<IPV4_ADDR_NONE>

Hex string representing the IPV4 "zero" address (C<'00' x 4>).

=item B<ARP_OPCODE_REQUEST>
X<ARP_OPCODE_REQUEST>

ARP C<opcode> for ARP requests.

=item B<ARP_OPCODE_REPLY>
X<ARP_OPCODE_REPLY>

ARP C<opcode> for ARP replies.

=item B<ARP_HTYPE_ETHERNET>
X<ARP_HTYPE_ETHERNET>

ARP C<htype> for Ethernet hardware addresses.

=item B<ARP_PROTO_IP>, B<ARP_PROTO_IPV4>
X<ARP_PROTO_IP>X<ARP_PROTO_IPV4>

ARP C<proto> for IPv4 requests/replies.

=item B<ARP_HLEN_ETHERNET>
X<ARP_HLEN_ETHERNET>

Ethernet protocol address length in bytes (6).

=item B<ARP_PLEN_IPV4>
X<ARP_PLEN_IPV4>

IP protocol address length in bytes (4).

=back

=head1 FUNCTIONS

The functions below can be imported individually, by using the C<:func> or C<:all> tags:

  use M6::ArpSponge::NetPacket qw( :all );
  use M6::ArpSponge::NetPacket qw( :func );

All functions return a hash ref (not an object!) with a minimal set of fields
set.
(Note that, unlike the L<B<NetPacket>(3)>|NetPacket> modlues,
they I<do not> set C<_parent> or C<_frame>.)

=head2 decode_ethernet

  HASHREF = decode_ethernet( DATA );

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

=head2 encode_ethernet

  DATA = encode_ethernet( HASHREF );

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

=head2 decode_ipv4

  HASHREF = decode_ipv4( DATA );

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

=head2 decode_arp

  HASHREF = decode_arp( DATA );

(TCP/IP Illustrated, Volume 1, Section 4.4, p56-57.)

Decode I<DATA> as a raw ARP packet. Returns a hash with the following
fields:

=over 12

=item C<htype>

Hardware type field. This routine is only designed for
B<ARP_HTYPE_ETHERNET>.

=item C<proto>

Type of protocol address. This routine is only designed for
B<ARP_PROTO_IPV4>.

=item C<hlen>, C<plen>

Hardware address length and protocol address length (in octets). For IPv4
on Ethernet these should be B<ARP_HLEN_ETHERNET> and B<ARP_PLEN_IPV4>,
respectively.

=item C<opcode>

Operation type: one of B<ARP_OPCODE_REQUEST> or B<ARP_OPCODE_REPLY>.

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

In theory the ARP packet could be for an AppleTalk address over Token
Ring, but in practice (and our use case), we only see IP over Ethernet.

Still, it pays to check the C<proto> and C<htype> fields, just to make
sure you don't get nonsense.

=head2 encode_arp

  DATA = encode_arp( HASHREF )

(TCP/IP Illustrated, Volume 1, Section 4.4, p56-57.)

Encode I<HASHREF> as a raw ARP packet. Returns a scalar with
the raw data. I<HASHREF> should point to a hash with the following fields:

=over 12

=item C<htype>

(optional, default value B<ARP_HTYPE_ETHERNET>)

Hardware type field. Only B<ARP_HTYPE_ETHERNET> is currently supported.

=item C<proto>

(optional, default value B<ARP_PROTO_IPV4>)

Type of protocol address. Only B<ARP_PROTO_IPV4> is currently supported.

=item C<hlen>, C<plen>

(optional, default values B<ARP_HLEN_ETHERNET> and B<ARP_PLEN_IPV4>, resp.)

Hardware address length and protocol address length (in octets). For IPv4
on Ethernet these should be B<ARP_HLEN_ETHERNET> and B<ARP_PLEN_IPV4>,
respectively.

=item C<opcode>

Operation type: one of B<ARP_OPCODE_REQUEST> or B<ARP_OPCODE_REPLY>.

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

In theory the ARP packet could be for an AppleTalk address over Token
Ring, but in practice (and our use case), we only see IP over Ethernet.

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<B<M6::ArpSponge::Sponge>(3)|M6::ArpSponge::Sponge.3>,
L<B<M6::ArpSponge::Util>(3)|M6::ArpSponge::Util.3>,
L<B<NetPacket>(3)|NetPacket.3>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
