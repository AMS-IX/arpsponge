##############################################################################
#
# ARP Query Timestamp Queue 
#
#   Copyright (c) 2005-2011 AMS-IX B.V.; All rights reserved.
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
# A.Vijn,   2003-2004;
# S.Bakker, 2004-onwards;
#
###############################################################################
package M6::ARPSponge::Queue;

use Modern::Perl;
use Moo;
use Types::Standard -types;

our $VERSION = '1.00';

our $DFL_DEPTH = 1000;

has 'max_depth' => (
    is      => 'ro',
    isa     => Int,
    default => sub { $DFL_DEPTH },
);
    
has '_table' => (
    is      => 'rw',
    isa     => HashRef,
    default => sub {{}},
);

BEGIN {
    *get = \&get_timestamp;
}


sub clear_all {
    my $self = shift;
    %{$self->_table} = ();
}


sub clear {
    delete $_[0]->_table->{$_[1]};
}


sub depth {
	my $q = $_[0]->_table->{$_[1]};
    return $q ? int(@$q) : 0;
}

# Slightly tricky calculation. Dumb calculation would be:
#
#   n / (Tn - T1)
#
# Where "n" is the number of entries, "T1" is the timestamp
# of the first entry and "Tn" is the n-th timestamp.
#
# However, this skews the calculation somewhat (the shorter the queue the
# worse the skew... hey that rhymes!).
#
# Consider the case where we send a packet once every second:
#
#   Packet 1 at time 0
#   Packet 2 at time 1
#
# In the queue we now have two entries with timestamps 0 and 1. Using the
# above formula, we get a rate of _two_ packets per second... That's clearly
# wrong. Even worse, the rate slowly aproaches 1 the further we go:
#
#   Packet   3 at time  2 => rate = 1.5
#   Packet   4 at time  3 => rate = 1.3333
#   Packet   5 at time  4 => rate = 1.2
#   ...
#   Packet 100 at time 99 => rate = 1.0101
#
# The correct way to handle this is to not count the first entry as part
# of the "n". After all, the rate of packets is calculated by looking at
# the gaps between them, and there is no gap _before_ the first packet.
#
# Hence, the corrected formula is:
#
# 	(n-1) / (Tn - T1)
#
# Which gives the correct rate of "1" for the above examples.
#
# [Statistics: comment/code > 4]
#
sub rate {
	my $q = $_[0]->_table->{$_[1]};
	return undef if !defined($q) or @$q < 2;
	my $first = $q->[0]->[1];
	my $last  = $q->[$#$q]->[1];
	my $time  = ($first < $last) ? $last-$first : 1;
	return ( (int(@$q)-1) / $time ) * 60;
}


sub is_full {
    $_[0]->depth($_[1]) >= $_[0]->max_depth;
}


sub add {
	my ($self, $ip, $src_ip, $val) = @_;

    my $q = $self->_table->{$ip};
    if ($q) {
        if (int(@$q) >= $self->max_depth) {
            shift @$q;
        }
        push @$q, [ $src_ip, $val ];
        return int(@$q);
    }
    else {
        $self->_table->{$ip} = [ $src_ip, $val ];
        return 1;
    }
}


sub get_entry {
	my ($self, $ip, $index) = @_;

    my $q = $self->_table->{$ip} or return undef;

	$index = 0 if !defined($index);
	if ($index < 0) {
		$index = int(@$q) + $index;
		$index = 0 if $index < 0;
	}
	return $q->[$index];
}


sub get_timestamp {
	my ($self, $ip, $index) = @_;

    if (my $entry = $self->get_entry($ip, $index)) {
        return $entry->[1];
    }
    return undef;
}


sub get_queue {
    return $_[0]->_table->{$_[1]};
}


sub reduce {
	my ($self, $ip, $max_rate) = @_;

    my $q = $self->_table->{$ip};

    if (!$q || @$q == 0) {
        return 0;
    }

    if ($max_rate <= 0) {
        return int(@$q);
    }

    my $min_delta = 1/$max_rate;

    my @sorted  = sort { $$a[0] cmp $$b[0] || $$a[1] <=> $$b[1] } @$q;
    my @reduced = ();
    my $prev_entry = undef;
    for my $entry (@sorted) {
        if ($prev_entry) {
            if ($entry->[0] ne $prev_entry->[0] or
                $entry->[1] - $prev_entry->[1] >= $min_delta)
            {
                push @reduced, $prev_entry;
            }
        }
        $prev_entry = $entry;
    }
    push @reduced, $prev_entry;
    @$q = sort { $$a[1] <=> $$b[1] } @reduced;
    return int(@reduced);
}

1;

__END__

=head1 NAME

M6::ARPSponge::Queue - ARP query queue.

=head1 SYNOPSIS

 use M6::ARPSponge::Queue;

 $q = M6::ARPSponge::Queue->($max_depth);

 $q->clear($dst_ip);
 $q->add($dst_ip, $src_ip, $timestamp);

 $q->clear_all();

 while ( ! $q->is_full($dst_ip) ) {
	...
 }

 $q_depth_1 = $q->depth($dst_ip);
 $q->reduce($dst_ip, 0.750);
 $q_depth_2 = $q->depth($dst_ip);
 $q_first   = $q->get_timestamp($dst_ip, 0);
 $q_last    = $q->get_timestamp($dst_ip, -1);

 $q_per_min = $q->rate($dst_ip);

 $listref = $q->get_queue($dst_ip);
 print "timestamps: ", join(", ", map { $_->[1] } @{$listref}), "\n";

=head1 DESCRIPTION

This object class is used by the L<M6::ARPSponge>(3p)
module to store [I<source>, I<timestamp>] tuples for ARP queries. 

The object holds a collection of circular buffers that are accessed by 
unique keys (IP address strings in the typical usage scenario). Pairs
of source IP and timestamp data added to a queue until its size reaches
the maximum depth, at which point newly added values cause the oldest
values to be shifted off the queue.

=head1 IP ADDRESS REPRESENTATION

Although the L<arpsponge>(8) stores IP addresses as hexadecimal
strings, and this object module is designed to do the same, there
is in fact no implicit knowledge about the format of the IP addresses
in this module; I<ip-address> could stand for I<arbitrary-key>.

=head1 VARIABLES

=over

=item I<$M6::ARPSponge::Queue::DFL_DEPTH>
X<$M6::ARPSponge::Queue::DFL_DEPTH>

Default maximum depth for queue objects (1000).

=back

=head1 CONSTRUCTOR

=over

=item B<new> ( [ B<max_depth> =E<gt> I<MAXDEPTH> ] )
X<new>

Create a new object instance. Each buffer will have a maximum depth
of I<MAXDEPTH> (or I<$M6::ARPSponge::Queue::DFL_DEPTH> if not given).
Returns a reference to the newly created object.

=back

=head1 METHODS

=over

=item B<clear_all>
X<clear_all>

Clear all queues.

=item B<clear> ( I<IP> )
X<clear>

Clear the queue for I<IP>.

=item B<depth> ( I<IP> )
X<depth>

Return the depth of the queue for I<IP>.

=item B<rate> ( I<IP> )
X<rate>

Return the (average) query rate (as a real number) for I<IP> in queries
per minute.

=item B<max_depth>
X<max_depth>

Return the maximum depth of the queues.

=item B<is_full> ( I<IP> )
X<is_full>

Return whether or not the queue for I<IP> is full, i.e. is wrapping.

=item B<add> ( I<IP>, I<SRC_IP>, I<TIMESTAMP> )
X<add>

Add [I<SRC_IP>, I<TIMESTAMP>] to the queue for I<IP>,
wrapping the buffer ring if necessary. Returns the new
queue depth.

=item B<get_entry> ( I<IP> [, I<INDEX>] )
X<get_entry>

Return the [I<SRC_IP>, I<TIMESTAMP>] data tuple at position I<INDEX>
in the queue for I<IP>.  Zero (0) is the oldest; positive values for
I<INDEX> give increasingly more recent values. Negative numbers count
from the end of the queue, so C<-1> gives the most recently added value.

Compare:

   QUEUE->get_entry( IP, -n ) == QUEUE->get_entry( IP, QUEUE->depth(IP) - n )

   QUEUE->get_entry( IP ) == QUEUE->get_entry( IP, 0 );

Also:

   QUEUE->get_entry( IP, n ) == QUEUE->get_queue( IP )->[n]

=item B<get_timestamp> ( I<IP> [, I<INDEX>] )
X<get_timestamp>

Return the I<TIMESTAMP> at position I<INDEX>
in the queue for I<IP>. The value of I<INDEX> has the same meaning
as for L<get_entry()|/get_entry> above.

=item B<get_queue> ( I<IP> )
X<get_queue>

Return the timestamps for I<IP>.
I<NOTE:> this is a reference to the internal list of data, so take care
that you don't inadvertently modify it.

=item B<reduce> ( I<IP>, I<MAX_RATE> )
X<reduce>

Reduce the queue for I<IP> by comparing subsequent pairs of entries for
each source IP and removing the older one if the time delta between the
two is below 1/I<MAX_RATE>. This effectively means that a source that's
sending more than I<MAX_RATE> ARP queries per second will be largely
ignored. This can mitigate the effects of broadcast storms (e.g. due
to loops) or DoS attacking.

Returns the new queue depth after reducing.

=back

=head1 EXAMPLE

    use M6::ARPSponge::Queue;
    use M6::ARPSponge::Util qw( :all );
    use Time::HiRes qw( usleep time );
    use POSIX qw( strftime );

    my $some_ip_s = '10.1.1.1';
    my $some_ip   = ip2hex($some_ip_s);
    my @src_ip    = map { ip2hex($_) } qw(10.1.1.2 10.1.1.3 10.1.1.4);
    my $max_rate  = 10;

    $q = new M6::ARPSponge::Queue(100);

    printf("Filling queue for $some_ip_s (max %d)\n", $q->max_depth);

    $q->clear($some_ip);
    my $n = 0;
    while (!$q->is_full($some_ip)) {
        my $src_ip = $src_ip[$n];
        $n = ($n + 1) % int(@src_ip);
        $q->add($some_ip, $src_ip, time);
        print STDERR sprintf("\rdepth: %3d", $q->depth($some_ip));
        usleep(rand(5e4));
    }
    print "\rBefore reduce:\n";
    printf(" depth: %3d\n", $q->depth($some_ip));
    print strftime(" first: %H:%M:%S\n",
                   localtime($q->get_timestamp($some_ip, 0)));
    print strftime(" last:  %H:%M:%S\n",
                   localtime($q->get_timestamp($some_ip, -1)));
    printf(" rate:  %0.2f queries/minute\n", $q->rate($some_ip));

    #$" = ",";
    #foreach $entry (@{$q->get_queue($some_ip)}) {
    #   print qq{[@$entry]\n};
    #}

    $q->reduce($some_ip, $max_rate);
    print "\nAfter reduce:\n";
    printf(" depth: %3d\n", $q->depth($some_ip));
    print strftime(" first: %H:%M:%S\n",
                   localtime($q->get_timestamp($some_ip, 0)));
    print strftime(" last:  %H:%M:%S\n",
                   localtime($q->get_timestamp($some_ip, -1)));
    printf(" rate:  %0.2f queries/minute\n", $q->rate($some_ip));

    #foreach $entry (@{$q->get_queue($some_ip)}) {
    #   print qq{[@$entry]\n};
    #}


Output:

    Filling queue for 10.1.1.1 (max 100)
    100
    Before reduce:
     depth: 100
     first: 00:43:44
     last:  08:43:04
     rate:  2451.50 queries/minute

    After reduce:
     depth:  18
     first: 00:18:08
     last:  08:43:04
     rate:  438.50 queries/minute

=head1 SEE ALSO

L<M6::ARPSponge>(3p),
L<M6::ARPSponge::Util>(3p).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2005-2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
