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
package M6::ArpSponge::Table;

use strict;

use Time::HiRes qw( time );

BEGIN {
    our $VERSION = 1.03;
}

=pod

=head1 NAME

M6::ArpSponge::Table - keep a table of ARP entries

=head1 SYNOPSIS

 use M6::ArpSponge::Table;

 $table = new M6::ArpSponge::Table;

 $table->clear($some_ip);
 $table->add($some_ip, $some_mac);

 $mac = $table->arp($some_ip);
 $stamp = $table->mtime($some_ip);
 @iplist = $table->rarp($mac);

 @iplist = $table->ip_list;
 @maclist = $table->mac_list;

=head1 DESCRIPTION

This object class can be used by network monitoring processes to keep
track of IP to MAC mappings.

=head1 CONSTRUCTOR

=over

=item X<new>B<new>

Create a new object instance and return a reference to it.

=cut

sub new {
    my ($type, $max_depth) = @_;

    $type = ref $type if ref $type;
    bless { arp => {}, rarp => {} }, $type;
}

=back

=head1 METHODS

=over

=item X<clear>B<clear> ( I<IP> )

Clear the ARP table for I<IP>.

=cut

sub clear {
    my ($self, $ip) = @_;

    if (my $mac = $self->arp($ip)) {
        delete $self->{rarp}->{$mac}->{$ip};
    }
    delete $self->{arp}->{$ip};
}

=item X<arp>B<arp> ( I<IP> )

Return the MAC address for I<IP>. Returns C<undef> if there is no
entry for I<IP>.

=cut

sub arp { $_[0]->{'arp'}->{$_[1]} }

=item X<rarp>B<rarp> ( I<MAC> )

Return an unsorted list of IP addresses that are mapped to I<MAC>.

=cut

sub rarp { keys %{$_[0]->{'rarp'}->{$_[1]}} }

=item X<ip_list>B<ip_list>

Return an unsorted list of IP addresses that are present in the ARP table.

=cut

sub ip_list { keys %{$_[0]->{'arp'}} }

=item X<mac_list>B<mac_list>

Return an unsorted list of MAC addresses that are present in the ARP table.

=cut

sub mac_list { sort { ip_sort($a, $b) } keys %{$_[0]->{'rarp'}} }

=item X<add>B<add> ( I<IP>, I<MAC> [, I<TIMESTAMP>] )

Add I<IP> to I<MAC> mapping to the table. If I<TIMESTAMP> is given, use
it for the entry's timestamp, otherwise use the current time.
Returns the timestamp.

=cut

sub add {
    my ($self, $ip, $mac, $timestamp) = @_;
    $timestamp //= time;
    $self->clear($ip);
    $self->{'arp'}->{$ip} = $mac;
    $self->{'rarp'}->{$mac}->{$ip} = $timestamp;
    return $timestamp;
}

1;

__END__

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<perl(1)|perl>, L<M6::ArpSponge::Sponge(3)|M6::ArpSponge::Sponge>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2005-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
