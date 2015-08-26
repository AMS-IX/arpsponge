###############################################################################
#
# M6::ARPSponge::ARPTable
#
#   Copyright (c) 2015 AMS-IX B.V.; All rights reserved.
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
# S.Bakker, 2015;
#
# IMPORTANT:
#
#   * IP and MAC addresses are stored as HEX strings, use
#     M6::ARP::Util::hex2{ip,mac} to convert to human-readable
#     form.
#
###############################################################################
package M6::ARPSponge::ARPTable;

use Modern::Perl;
use Moo;
use Types::Standard -types;

use M6::ARPSponge::NetPacket qw( :eth_addr );

our $VERSION    = 1.00;

# Public r/o attributes.
has 'table'  => (
    is      => 'rw',
    isa     => HashRef,
    writer  => '_set_table',
    default => sub {{}},
);


sub lookup {
    my ($self, $ip) = @_;
    return $self->table->{$ip} ? @{$self->table->{$ip}} : ();
}

sub update {
    my ($self, $ip, $mac, $time) = @_;

    if (defined $mac && $mac ne ETH_ADDR_NONE) {
        $self->table->{$ip} = [ $mac, $time // time ];
    }
    else {
        delete $self->table->{$ip};
    }
    return $self;
}

sub delete {
    my ($self, $ip) = @_;
    delete $self->table->{$ip};
    return $self;
}

sub clear {
    my $self = shift;
    %{$self->table} = ();
    return $self;
}


1;

__END__


=head1 NAME

M6::ARPSponge::ARPTable - Perl object class for ARP information.

=head1 SYNOPSIS

 use M6::ARPSponge::ARPTable;
 use M6::ARPSponge::Util qw(
    ip2hex hex2ip mac2hex hex2mac
    format_time
 );

 my $table = M6::ARPSponge::ARPTable->new();

 my $ip  = '10.0.0.1';
 my $mac = '52:54:00:85:3c:0a';

 # Add or update ARP entry
 $table->update( ip2hex($ip), mac2hex($mac) );

 # Perform lookup of an ARP entry
 my ($hex_mac, $mtime) = $table->lookup( ip2hex($ip) );

 if (defined $hex_mac) {
    say $ip, ' -> ', hex2mac($hex_mac),
        ' (', format_time($mtime), ')';
 }

 # Delete an ARP entry.
 $table->delete( ip2hex($ip) );

 # Clear the whole ARP table.
 $table->clear();

 # Access the internal ARP HASH table.
 my $hash = $table->table;

 for my $hex_ip (sort { $a cmp $b } keys %$hash) {
    my ($hex_mac, $mtime) = @{$hash->{$hex_ip}};

    say hex2ip($hex_ip),
        ' -> ', hex2mac($hex_mac),
        ' (', format_time($mtime), ')';
 }

=head1 DESCRIPTION

The M6::ARPSponge::ARPTable class keeps track of IP-to-MAC mappings,
along with a timestamp.

IP addresses and MAC addresses are interpreted and stored as
hex-strings, timestamps are interpreted as seconds since epoch.

=head1 CONSTRUCTOR

=over

=item B<new>
X<new>

Create a new, empty C<M6::ARPSponge::ARPTable> object and return a
reference to it.

=back

=head1 METHODS

=over

=item B<clear>
X<clear>

Clear all entries from the table. Returns the object reference.

=item B<delete> ( I<HEXIP> )
X<delete>

Delete any entry for I<HEXIP>. Returns the object reference.

=item B<lookup> ( I<HEXIP> )
X<lookup>

Look up the ARP entry for I<HEXIP> and either return a list of two
elements, (I<HEXMAC>, I<TSTAMP>), or an empty list.

=item B<table>
X<table>

Return a reference to the internal HASH table that is used to
store the ARP entries. The structure of the table is:

    {
        HEXIP1 => [ HEXMAC1, TSTAMP1 ],
        HEXIP2 => [ HEXMAC2, TSTAMP2 ],
        ...
    }

Note that this returns a reference to the internal table, so any
operations through the object API will affect the hash. For example:

    my $ref = $arp_table->table;
    $arp_table->clear();

    # %$ref is now empty!

This HASHREF should be treated as a read-only value, for example to
iterate over all entries efficiently.

=item B<update> ( I<HEXIP>, I<HEXMAC> [, I<TSTAMP>] )
X<update>

Add or update the ARP entry for I<HEXIP>, mapping it to I<HEXMAC>.
If I<TSTAMP> is given, its value is used for the entry's timestamp;
otherwise, the current time is used.

If I<HEXMAC> matches the C<000000000000> string (i.e. the MAC address
is C<00:00:00:00:00:00>), any existing entry for I<HEXIP> is deleted,
effectively implementing L</delete>().

Returns the object reference, so calls can be chained:

  $table->update($hex_ip1, $hex_mac1)->update($hex_ip2, $hex_mac2);

=back

=head1 AUTHOR

Steven Bakker (steven.bakker AT ams-ix.net).

=head1 COPYRIGHT

Copyright 2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
