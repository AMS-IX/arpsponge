###############################################################################
#
# M6::ARPSponge::State
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
###############################################################################
package M6::ARPSponge::State;

use Modern::Perl;
use Scalar::Util qw( looks_like_number );

BEGIN {
    our $VERSION = '1.00';

    use parent qw( Exporter );

    my @states = qw(
        STATE_NONE
        STATE_STATIC STATE_DEAD
        STATE_ALIVE STATE_PENDING
    );

    our @EXPORT_OK = ( @states );
    our %EXPORT_TAGS = ( 
        'states' => \@states,
        'all'    => \@EXPORT_OK,
    );
}

# State constants/macros
use constant {
    INT_NONE      => -4,
    INT_STATIC    => -3,
    INT_DEAD      => -2,
    INT_ALIVE     => -1,
    INT_PENDING   =>  0,
};

use constant {
    MIN_INT_STATE => INT_NONE
};

sub STATE_NONE() {
    state $obj = __PACKAGE__->new_from_int( INT_NONE );
    return $obj;
}

sub STATE_STATIC() {
    state $obj = __PACKAGE__->new_from_int( INT_STATIC );
    return $obj;
}

sub STATE_DEAD() {
    state $obj = __PACKAGE__->new_from_int( INT_DEAD );
    return $obj;
}

sub STATE_ALIVE() {
    state $obj = __PACKAGE__->new_from_int( INT_ALIVE );
    return $obj;
}

sub STATE_PENDING($) {
    __PACKAGE__->new_from_int(0 + $_[$#_])
};

sub ALL() {
    return (STATE_STATIC, STATE_DEAD, STATE_ALIVE, STATE_PENDING(0));
}

my %STR_TO_INT = (
    'NONE'    => INT_NONE,
    'STATIC'  => INT_STATIC,
    'DEAD'    => INT_DEAD,
    'ALIVE'   => INT_ALIVE,
    'PENDING' => INT_PENDING,
);

my %INT_TO_STR = reverse %STR_TO_INT;

use overload
    '""'        => \&to_string,
    '0+'        => \&to_num,
    '='         => \&clone,
    '++'        => \&increment,
    '--'        => \&decrement,
    '+'         => \&_add,
    '-'         => \&_subtract,
    fallback    => 1;


sub new {
    my ($type, $val) = @_;
    if (!defined($val) or looks_like_number($val)) {
        return $type->new_from_int($val, @_);
    }
    return $type->new_from_string($val, @_);
}

sub new_from_int {
    my ($type, $val) = @_;
    my %opts = (-err => \(my $err_s), @_);

    $val //= INT_NONE;
    if ($val >= MIN_INT_STATE) {
        return bless \$val, $type;
    }
    ${$opts{-err}} = qq/"$val" is not a valid state/;
    return;
}

sub new_from_string {
    my ($type, $arg, @args) = @_;
    $arg = uc( $arg // 'NONE' );
    my %opts = (-err => \(my $err_s), @args);

    for ($arg) {
        s/^\s+//;
        s/\s+$//;
        if (/^PENDING\s*\(\s*(\d+)\s*\)$/) {
            return STATE_PENDING($1);
        }
        if (my $val = $STR_TO_INT{$_}) {
            return $type->new_from_int($val);
        }
    }
    substr($_, 20, -20) = '...' if length($_) > 43;
    ${$opts{-err}} = qq/"$_" is not a valid state/;
    return;
}

sub clone {
    my ($self) = @_;
    my $clone = int($$self);
    return bless \$clone, ref $self;
}

sub to_string {
    my ($self) = @_;

    for ($$self) {
        return 'NONE' unless defined $_;
        return sprintf("PENDING(%d)", $_ - INT_PENDING) if $_ >= INT_PENDING;
        return $INT_TO_STR{$_} // 'ILLEGAL';
    }
}

sub to_num {
    ${$_[0]}
}

sub increment {
    ++${$_[0]};
}

sub decrement {
    --${$_[0]};
}

sub _add {
    my ($self, $other) = @_;

    my $result = int($$self + $other);
    bless \$result;
}

sub _subtract {
    my ($self, $other, $swap) = @_;

    my $result = int($swap ? $other - $$self : $$self - $other);
    bless \$result;
}
1;

__END__

=head1 NAME

M6::ARPSponge::State - Perl "state" object for arpsponge(8)

=head1 SYNOPSIS

 use M6::ARPSponge::State qw( :states );

 say "ARPSponge States:";
 for my $state ( M6::ARPSponge::State->ALL ) {
    printf("   %-10s %d\n", $state, $state);
 }

 print "\n";

 my $state_1 = STATE_ALIVE;
 my $state_2 = $state_1;

 printf "state_1: %d (%s)\n", $state_1, $state_1;
 printf "state_2: %d (%s)\n", $state_2, $state_2;

 say "decrementing state_2:";

 $state_2--;
 
 say "state_2 is ", ($state_2 == STATE_DEAD)   ? "" : "not ", "DEAD";
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

=item B<STATE_ALIVE>
X<STATE_ALIVE>

Integer value C<-1>, string value C<ALIVE>.

=item B<STATE_DEAD>
X<STATE_DEAD>

Integer value C<-2>, string value C<DEAD>.

=item B<STATE_STATIC>
X<STATE_STATIC>

Integer value C<-3>, string value C<STATIC>.

=item B<STATE_NONE>
X<STATE_NONE>

Integer value C<-4>, string value C<NONE>.

=item B<STATE_PENDING> ( I<NUM> )
X<STATE_PENDING>

Integer value I<NUM> (>= 0), string value C<PENDING(NUM)>.

=back

=head1 CLASS METHODS

=over

=item B<ALL>
X<ALL>

Return a list of the state values (L<see above|/STATE VALUES>), except C<NONE>:

    STATE_STATIC, STATE_DEAD, STATE_ALIVE, STATE_PENDING(0)

=back

=head1 CONSTRUCTORS

You will probably never have to call a constructor explicitly; assignment
is overloaded, so you can simply assign one of the state constants to a
variable to instantiate a new instance:

   my $state = STATE_ALIVE;
   say $state;              # prints "ALIVE"

   $state = STATE_PENDING(0);
   say $state;              # prints "PENDING(0)"
   $state++;
   say $state;              # prints "PENDING(1)"

   $state = STATE_DEAD;
   say $state;              # prints "DEAD"

=over

=item B<new> ( I<ARG> [, B<-err> =E<gt> REF ] )
X<new>

Create a new C<M6::ARPSponge::State> object with I<ARG> as its value.
I<ARG> can be a number representing a state, a string, or another 
C<M6::ARPSponge::State> reference. Depending on which type of argument
it gets, it will either call L</new_from_int> or L</new_from_string>.

If the I<ARG> is invalid, the method will return C<undef> and (if given)
the I<REF> will contain an error message.

=item B<new_from_int> ( I<INT> [, B<-err> =E<gt> REF ] )
X<new_from_int>

Create a new C<M6::ARPSponge::State> object with I<INT> as its value.
I<INT> is a number representing a state.

If I<INT> is not defined, it is equated to I<STATE_NONE>.

If the I<INT> is invalid, the method will return C<undef> and (if given)
the I<REF> will contain an error message.

=item B<new_from_string> ( I<STR> [, B<-err> =E<gt> REF ] )
X<new_from_string>

Create a new C<M6::ARPSponge::State> object with I<STR> as its value.
I<STR> is a string representing a state.

If I<STR> is not defined, it is equated to I<STATE_NONE>.

If the I<STR> is invalid, the method will return C<undef> and (if given)
the I<REF> will contain an error message.

=back

=head1 OVERLOADED OPERATORS AND COMPARISON

The '""' (stringify), '0+' (numify), '++', '--', '+', '-', and '='
operators are overloaded.

Because of this overloading, instances of this class can be compared
using both integer comparison and string comparison.

Note that no bounds checks are performed on the arithmetic operators,
so the result may well be an C<ILLEGAL> state object.

=head1 METHODS

=over

=item B<to_string>
X<to_string>

Implements stringification. Returns C<ILLEGAL> for integer state values
that are out of range.

=item B<to_num>
X<to_snum>

Implements numification.

=item B<clone>
X<clone>

Returns a copy of the object.

=item B<increment>
X<increment>

=item B<decrement>
X<decrement>

Implement the C<++> and C<--> operators, resp. Can also be called as a
regular method.

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

  STATE_STATIC, STATE_DEAD, STATE_ALIVE,
  STATE_PENDING(0), STATE_PENDING(1), ...

=item *

String comparison (C<lt>, C<gt>, C<eq>, etc.) will use the stringified
values and produce an ordering of:

  STATE_STATIC, STATE_DEAD, STATE_ALIVE,
  STATE_PENDING(0),
  STATE_PENDING(1), STATE_PENDING(10), STATE_PENDING(11), ...
  STATE_PENDING(2), STATE_PENDING(20), STATE_PENDING(21), ...
  STATE_STATIC

(Also note that in lexical comparisons, C<PENDING(10)> will sort lower
than C<PENDING(2)>).

=back

=back

=head1 AUTHOR

Steven Bakker (steven.bakker AT ams-ix.net).

=head1 COPYRIGHT

Copyright 2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
