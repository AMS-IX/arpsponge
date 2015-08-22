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

use M6::ARPSponge::NetPacket;

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
    return $self->table->{$ip} ? @{$self->_arp_table->{$ip}} : ();
}

sub update {
    my ($self, $ip, $mac, $time) = @_;

    if (defined $mac && $mac ne $ETH_ADDR_NONE) {
        $self->table->{$ip} = [ $mac, $time // time ];
    }
    else {
        delete $self->table->{$ip};
    }
}

sub delete {
    my ($self, $ip) = @_;
    delete $self->table->{$ip};
}

sub clear {
    my $self = shift;
    %{$self->table} = ();
}


1;

__END__


=head1 NAME

M6::ARPSponge::ARPTable - Perl object class for ARP information.

=head1 SYNOPSIS

 use M6::ARPSponge::ARPTable;

 my $table = M6::ARPSponge::ARPTable->new();

 $table->update(
 '525400853c0a', 
 '28b2bd906ab9',

 say "ARPSponge States:";
 for my $state ( M6::ARPSponge::State->ALL ) {
    printf("   %-10s %d\n", $state, $state);
 }

 print "\n";

 my $state_1 = ALIVE;
 my $state_2 = $state_1;

 printf "state_1: %d (%s)\n", $state_1, $state_1;
 printf "state_2: %d (%s)\n", $state_2, $state_2;

 say "decrementing state_2:";

 $state_2--;
 
 say "state_2 is ", ($state_2 == DEAD)   ? "" : "not ", "DEAD";
 say "state_2 is ", ($state_2 eq 'DEAD') ? "" : "not ", "DEAD";

=head1 DESCRIPTION

The M6::ARPSponge::State class represents the states that an IP address
can be in (as perceived by the sponge).

Instances of the class behave like simple integer scalars that stringify
to a textual description of the state.

=head1 STATE VALUES

The module defines a number of symbolic names for the states, which
can be imported using the C<:states> or C<:all> tag.

=over

=item B<NONE>
X<NONE>

Integer value I<undef>, string value C<NONE>.

=item B<ALIVE>
X<ALIVE>

Integer value C<-1>, string value C<ALIVE>.

=item B<DEAD>
X<DEAD>

Integer value C<-2>, string value C<DEAD>.

=item B<STATIC>
X<STATIC>

Integer value C<-3>, string value C<STATIC>.

=item B<PENDING> ( I<NUM> )
X<PENDING>

Integer value I<NUM> (>= 0), string value C<PENDING(NUM)>.

=back

=head1 CLASS METHODS

=over

=item B<ALL>
X<ALL>

Return a list of the state values (L<see above|/STATE VALUES>), except I<NONE>:

    STATIC, DEAD, ALIVE, PENDING(0)

=back

=head1 CONSTRUCTORS

You will probably never have to call a constructor explicitly; assignment
is overloaded, so you can simply assign one of the state constants to a
variable to instantiate a new instance:

   my $state = ALIVE;
   say $state;              # prints "ALIVE"

   $state = PENDING(0);
   say $state;              # prints "PENDING(0)"
   $state++;
   say $state;              # prints "PENDING(1)"

   $state = DEAD;
   say $state;              # prints "DEAD"

=over

=item B<new> ( I<ARG> )
X<new>

Create a new C<M6::ARPSponge::State> object with I<ARG> as its value.
I<ARG> can be a number representing a state, a string, or another 
C<M6::ARPSponge::State> reference. Depending on which type of argument
it gets, it will either call L</new_from_int> or L</new_from_string>.

=item B<new_from_int> ( I<INT> )
X<new_from_int>

Create a new C<M6::ARPSponge::State> object with I<INT> as its value.
I<INT> is a number representing a state.

=item B<new_from_string> ( I<STR> )
X<new_from_string>

Create a new C<M6::ARPSponge::State> object with I<STR> as its value.
I<STR> is a string representing a state.

=back

=head1 OVERLOADED OPERATORS AND COMPARISON

The '""' (stringify), '0+' (numify), '++', '--', and '=' operators are
overloaded and implemented by the L<methods below|/METHODS>.

Because of this overloading, instances of this class can be compared
with both integer comparison and string comparison.

=head1 METHODS

=over

=item B<to_string>
X<to_string>

Implements stringification.

=item B<to_num>
X<to_snum>

Implements numification.

=item B<increment>
X<increment>

Implements C<++>.

=item B<decrement>
X<decrement>

Implements C<-->.

=item B<clone>
X<clone>

Implements the assignment (C<=>) operator.

=back

=head1 CAVEATS

=over

=item Inconsistent comparison

Since we don't explicitly overload the comparision operators, they will
use the numified and stringified values of the object instances to compare.

Specifically, this means that:

=over

=item *

Integer comparison (C<E<lt>>, C<E<gt>>, C<==>, etc.) will use the integer
values and produce an ordering of:

  STATIC, DEAD, ALIVE, PENDING(0), PENDING(1), ...

=item *

String comparison (C<lt>, C<gt>, C<eq>, etc.) will use the stringified
values and produce an ordering of:

  STATIC, DEAD, ALIVE, PENDING(0), PENDING(1), ..., STATIC

(Also note that in lexical comparisons, C<PENDING(10)> will sort lower
than C<PENDING(2)>).

=back

=back

=head1 AUTHOR

Steven Bakker (steven.bakker AT ams-ix.net).

=head1 COPYRIGHT

Copyright 2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
