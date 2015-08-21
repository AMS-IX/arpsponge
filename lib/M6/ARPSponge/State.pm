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

use parent qw( Exporter );

BEGIN {
    our $VERSION = '1.00';

    my @states = qw( STATIC DEAD ALIVE PENDING NONE );

    our @EXPORT_OK = ( @states );
    our %EXPORT_TAGS = ( 
            'states' => \@states,
            'all'    => [ @states ]
        );
}

# State constants/macros
my $INT_NONE    = undef;
my $INT_STATIC  = -3;
my $INT_DEAD    = -2;
my $INT_ALIVE   = -1;
my $INT_PENDING = 0;

my ($OBJ_NONE, $OBJ_STATIC, $OBJ_DEAD, $OBJ_ALIVE);

sub NONE {
    return $OBJ_NONE //= __PACKAGE__->new_from_int( $INT_NONE );
}

sub STATIC {
    return $OBJ_STATIC //= __PACKAGE__->new_from_int( $INT_STATIC );
}

sub DEAD {
    return $OBJ_DEAD //= __PACKAGE__->new_from_int( $INT_DEAD );
}

sub ALIVE {
    return $OBJ_ALIVE //= __PACKAGE__->new_from_int( $INT_ALIVE );
}

sub PENDING { __PACKAGE__->new_from_int(0 + $_[$#_]) };

sub ALL {
    return (STATIC, DEAD, ALIVE, PENDING(0));
}

my %STR_TO_INT = (
    'STATIC'  => $INT_STATIC,
    'DEAD'    => $INT_DEAD,
    'ALIVE'   => $INT_ALIVE,
    'PENDING' => $INT_PENDING,
);

use overload 
    '""'        => \&to_string,
    '0+'        => \&to_num,
    '='         => \&clone,
    '++'        => \&increment,
    '--'        => \&decrements,
    fallback    => 1;


sub new {
    my $type = shift;
    my $val  = shift;
    if (!defined($val) or looks_like_number($val)) {
        return $type->new_from_int($val, @_);
    }
    else {
        return $type->new_from_string($val, @_);
    }
}

sub new_from_int {
    my $type = shift;
    my $val  = shift;
    my %opts = (-err => \(my $err_s), @_);

    if (!defined $val or $val >= $INT_STATIC) {
        return bless \$val, $type;
    }
    else {
        ${$opts{-err}} = qq/"$val" is not a valid state/;
        return;
    }
}

sub new_from_string {
    my $type = shift;
    my $arg = uc shift;
    my %opts = (-err => \(my $err_s), @_);

    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;
    
    my $val;
    if ($arg eq 'NONE')       { $val = $INT_NONE    }
    elsif ($arg eq 'STATIC')  { $val = $INT_STATIC  }
    elsif ($arg eq 'DEAD')    { $val = $INT_DEAD    }
    elsif ($arg eq 'ALIVE')   { $val = $INT_ALIVE   }
    elsif ($arg eq 'PENDING') { $val = $INT_PENDING }
    elsif ($arg =~ /^PENDING\s*\(\s*(\d+)\s*\)$/) {
        $val = $INT_PENDING + $1;
    }
    else {
        ${$opts{-err}} = qq/"$arg" is not a valid state/;
        return;
    }
    return $type->new_from_int($val);
}

sub clone {
    my $self = shift;
    my $clone = int($$self);
    return bless \$clone, ref $self;
}

sub to_string {
    my $self = shift;

    if (!defined $$self)        { return 'NONE' }
    elsif ($$self == STATIC)    { return 'STATIC' }
    elsif ($$self == DEAD)      { return 'DEAD' }
    elsif ($$self == ALIVE)     { return 'ALIVE' }
    elsif ($$self < PENDING(0)) { return 'ILLEGAL' }
    else {
        return sprintf("PENDING(%d)", $$self - PENDING(0));
    }
}

sub to_num    { ${$_[0]} },
sub increment { ++${$_[0]} }
sub decrement { --${$_[0]} }


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
