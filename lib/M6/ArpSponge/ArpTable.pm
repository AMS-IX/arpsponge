##############################################################################
#
# ARP Table
#
#   Copyright 2005-2016 AMS-IX B.V.; All rights reserved.
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
# S.Bakker, 2005
#
###############################################################################
package M6::ArpSponge::ArpTable;

use 5.014;
use warnings;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Moo;
use Time::HiRes qw( time );

use namespace::clean;

has _arp  => ( is => 'rw', init_arg => undef, default => sub { {} } );
has _rarp => ( is => 'rw', init_arg => undef, default => sub { {} } );

sub clear_ip {
    my ($self, $ip) = @_;

    my $entry = delete $self->_arp->{$ip}
        or return;

    my $mac = $entry->[0];
    my $rarp = $self->_rarp;
    if (keys %{$rarp->{$mac}} == 1) {
        delete $rarp->{$mac};
    }
    else {
        delete $rarp->{$mac}->{$ip};
    }
}

sub clear_mac {
    my ($self, $mac) = @_;

    my $ip_hash = delete $self->_rarp->{$mac}
        or return;

    for my $ip (keys %{$ip_hash}) {
        delete $self->_arp->{$ip};
    }
}


sub lookup_ip {
    my ($self, $ip) = @_;
    if (my $e = $self->_arp->{$ip}) {
        return wantarray ? @{$e} : $e->[0];
    }
    return;
}


sub lookup_mac {
    my ($self, $mac) = @_;

    return keys %{ $self->_rarp->{$mac} // {} };
}


sub purge {
    my ($self, $timestamp) = @_;

    if (!defined $timestamp) {
        my $purged = scalar(keys %{$self->_arp});
        $_[0]->_arp({});
        $_[0]->_rarp({});
        return $purged;
    }
    
    my $purged = 0;
    my $mac_hash = $self->_rarp;
    my $ip_hash = $self->_arp;
    while (my ($mac, $mac_ip_hash) = each %{$mac_hash}) {
        while (my ($ip, $ip_ts) = each %{$mac_ip_hash}) {
            if ($ip_ts < $timestamp) {
                delete $ip_hash->{$ip};
                delete $mac_ip_hash->{$ip};
                $purged++;
            }
        }
        my $k = int(keys %{$mac_ip_hash});
        if (keys %{$mac_ip_hash} == 0) {
            delete $mac_hash->{$mac};
        }
    }
    return $purged;
}


sub ip_list  { keys %{$_[0]->_arp} }
sub mac_list { keys %{$_[0]->_rarp} }

sub add {
    my ($self, $ip, $mac, $timestamp) = @_;
    $timestamp //= time;
    $self->clear_ip($ip);
    return if !defined $mac;
    $self->_arp->{$ip} = [ $mac, $timestamp ];
    $self->_rarp->{$mac}->{$ip} = $timestamp;
    return $timestamp;
}

1;

=pod

=head1 NAME

M6::ArpSponge::ArpTable - keep a table of ARP entries

=head1 SYNOPSIS

 use M6::ArpSponge::ArpTable;

 $table = M6::ArpSponge::ArpTable->new();

 $table->add($some_ip, $some_mac);
 $table->add($some_ip, $some_mac, time);

 $mac = $table->lookup_ip($some_ip);
 ($mac, $tstamp) = $table->lookup_ip($some_ip);

 @ip_list = $table->lookup_mac($mac);

 $table->clear_ip($some_ip);
 $table->clear_mac($some_mac);

 @ip_list = $table->ip_list;
 @mac_list = $table->mac_list;

 $purge_count = $table->purge();
 $purge_count = $table->purge(time - $max_age);

=head1 DESCRIPTION

This object class can be used by network monitoring processes to keep
track of IP to MAC mappings.

=head1 CONSTRUCTOR

=head2 new

    $OBJ = M6::ArpSponge::Table->new();

Create a new object instance and return a reference to it.

=head1 METHODS

=head2 add

    $TIMESTAMP = $OBJ->add( $IP, $MAC );
    $TIMESTAMP = $OBJ->add( $IP, $MAC, $TIMESTAMP );

Add a mapping for I<$IP> to I<$MAC>. If I<$TIMESTAMP> is given, use
it for the entry's timestamp, otherwise use the current time.
Return the timestamp.

=head2 clear_ip

    $OBJ->clear_ip( $IP );

Clear the table for I<$IP>.

=head2 clear_mac

    $OBJ->clear_mac( $MAC );

Clear the table for MAC address I<$MAC>.

=head2 ip_list

    @IP_LIST = $OBJ->ip_list();

Return an unsorted list of all IP addresses that are present in the
ARP table.

=head2 lookup_ip

    $MAC = $OBJ->lookup_ip( $IP );
    ($MAC, $MTIME) = OBJ->lookup_ip( $IP );

Return the MAC address for I<$IP>
(or MAC address and last modification time in list context).
Returns C<undef> (or an empty list) if there is no entry for I<$IP>.

=head2 lookup_mac

    @IP_LIST = $OBJ->lookup_mac( $MAC );

Return an unsorted (possibly empty) list of IP addresses that are mapped
to I<MAC>.

=head2 mac_list

    @MAC_LIST = $OBJ->mac_list();

Return an unsorted list of MAC addresses that are present in the
ARP table.

=head2 purge

    $IP_COUNT = $OBJ->purge();
    $IP_COUNT = $OBJ->purge( $TIMESTAMP );

Delete all entries from the table. If I<$TIMESTAMP> is given,
only delete entries that are older than I<$TIMESTAMP>
(that is, entries for which the timestamp falls before I<$TIMESTAMP>).

Return the number of IP entries removed.

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<B<perl>(1)|perl.1>,
L<B<M6::ArpSponge::Sponge>(3)|M6::ArpSponge::Sponge.3>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2005-2025, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
