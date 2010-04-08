##############################################################################
# @(#)$Id$
##############################################################################
#
# ARP Query Timestamp Queue 
#
# (c) Copyright AMS-IX B.V. 2004-2005;
#
# See the LICENSE file that came with this package.
#
# A.Vijn, S.Bakker.
#
###############################################################################
package M6::ARP::Queue;

use strict;

BEGIN {
	our $VERSION = 1.02;
}

=pod

=head1 NAME

M6::ARP::Queue - ARP query timestamp queue.

=head1 SYNOPSIS

 use M6::ARP::Queue;

 $q = new M6::ARP::Queue($max_depth);

 $q->clear($some_ip);
 $q->add($some_ip, $timestamp);

 while ( ! $q->is_full($some_ip) ) {
	...
 }

 $q_depth   = $q->depth($some_ip);
 $q_first   = $q->get($some_ip, 0);
 $q_last    = $q->get($some_ip, -1);

 $q_per_min = $q->rate($some_ip);

 $listref = $q->get_queue($some_ip);
 print "timestamps: ", join(", ", @{$listref}), "\n";

=head1 DESCRIPTION

This object class is mainly used by the L<M6::ARP::Sponge|M6::ARP::Sponge>
module to store timestamps for ARP queries. 

The object holds a collection of circular buffers that are accessed by 
unique keys (IP address strings in the typical usage scenario). Timestamps
are added to a queue until its size reaches the maximum depth, at which
point newly added values cause the oldest values to be shifted off the
queue.

Although primarily used for storing timestamps of ARP queries
for IP addresses, it can be used for more general work as well.
Any string can be used as a queue key and arbitrary data can be
added to the queues.

Only the L</rate|rate> method makes assumptions about the data
(i.e. that they are timestamps in seconds).

=head1 CONSTRUCTOR

=over

=item X<new>B<new> ( I<MAXDEPTH> )

Create a new object instance. Each queue will have a maximum depth
of I<MAXDEPTH>. Returns a reference to the newly created object.

=cut

sub new {
	my $type = shift;
	my $max_depth = shift;

	if (ref $type) { $type = ref $type }
	bless {'max_depth' => $max_depth}, $type;
}

=back

=head1 METHODS

=over

=item X<clear>B<clear> ( I<IP> )

Clear the queue for I<IP>.

=cut

sub clear     { delete $_[0]->{$_[1]} }

=item X<depth>B<depth> ( I<IP> )

Return the depth of the queue for I<IP>.

=cut

sub depth     { $_[0]->{$_[1]} ?  int(@{$_[0]->{$_[1]}}) : 0 }

=item X<rate>B<rate> ( I<IP> )

Return the (average) query rate (as a real number) for I<IP> in queries
per minute.

=cut

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
	my $q = $_[0]->{$_[1]};
	return undef unless defined($q) && @$q > 1;
	my $first = $q->[0];
	my $last  = $q->[$#$q];
	my $time  = ($first < $last) ? $last-$first : 1;
	my $n = int(@$q)-1;
	return ($n / $time) * 60;
}

=item X<max_depth>B<max_depth>

Return the maximum depth of the queues.

=cut

sub max_depth { $_[0]->{'max_depth'} }

=item X<is_full>B<is_full> ( I<IP> )

Return whether or not the queue for I<IP> is full, i.e. is wrapping.

=cut

sub is_full { $_[0]->depth($_[1]) >= $_[0]->max_depth }

=item X<add>B<add> ( I<IP>, I<TIMESTAMP> )

Add I<TIMESTAMP> to the queue for I<IP>, wrapping the buffer ring if
necessary. Returns the new queue depth.

=cut

sub add {
	my ($self, $ip, $val) = @_;
	if ($self->depth($ip) >= $self->max_depth) {
		shift @{$self->{$ip}};
	}
	push @{$self->{$ip}}, $val;
	return int(@{$self->{$ip}});
}


=item X<get>B<get> ( I<IP> [, I<INDEX>] )

Return the data value at position I<INDEX> in the queue for I<IP>.
Zero (0) is the oldest; positive values for I<INDEX> give increasingly
more recent values. Negative numbers count from the end of the queue,
so C<-1> gives the most recently added value.

Compare:

   QUEUE->get( IP, -n ) == QUEUE->get( IP, QUEUE->depth(IP) - n )

   QUEUE->get( IP ) == QUEUE->get( IP, 0 );

Also:

   QUEUE->get( IP, n ) == QUEUE->get-_queue( IP )->[n]

=cut

sub get {
	my ($self, $ip, $index) = @_;

	$index = 0 unless defined($index);
	if ($index < 0) {
		$index = int(@{$self->{$ip}}) + $index;
		$index = 0 if $index < 0;
	}
	return $self->{$ip}->[$index];
}


=item X<get_queue>B<get_queue> ( I<IP> )

Return the timestamps for I<IP>.
I<NOTE:> this is a reference to the internal list of data, so take care
that you don't inadvertently modify it.

=cut

sub get_queue {
	my ($self, $ip) = @_;
	return $self->{$ip};
}

1;

__END__

=back

=head1 EXAMPLE

 use M6::ARP::Queue;
 use Time::HiRes qw( usleep );
 use POSIX qw( strftime );

 my $some_ip = '10.1.1.1';

 $q = new M6::ARP::Queue(100);

 printf("filling queue for $some_ip (max %d)\n", $q->max_depth);

 $q->clear($some_ip);
 while (!$q->is_full($some_ip)) {
	$q->add($some_ip, time);
	print STDERR sprintf("\rdepth: %3d", $q->depth($some_ip));
	usleep(rand(5e5));
 }
 printf("\rdepth: %3d\n", $q->depth($some_ip));
 print strftime("first: %H:%M:%S\n", localtime($q->get($some_ip, 0)));
 print strftime("last:  %H:%M:%S\n", localtime($q->get($some_ip, -1)));
 printf("rate: %0.2f queries/minute\n", $q->rate($some_ip));

=head1 SEE ALSO

L<perl(1)|perl>, L<M6::ARP::Sponge(3)|M6::ARP::Sponge>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=cut
