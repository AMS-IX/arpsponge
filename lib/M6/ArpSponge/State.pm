#===============================================================================
#
#       Module:  M6::ArpSponge::State
#
#  Description:  Define IP state constants.
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#      Created:  2025-07-22
#
#   Copyright (c) 2025 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6::ArpSponge::State;

use 5.014;
use warnings;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Exporter 'import';

BEGIN {
    my @func = qw(
        is_valid_state state_to_string
    );

    my @states = qw(
        STATIC DEAD ALIVE PENDING NONE
    );

    our @EXPORT_OK = ( @func, @states );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
        'func'   => \@func,
        'const'  => \@states,
        'all'    => \@EXPORT_OK,
    );
}

# State constants/macros
use constant NONE      => 0;
use constant ALIVE     => -1;
use constant DEAD      => -2;
use constant STATIC    => -3;
use constant STATE_MIN => STATIC;

# States 1 and above are "pending".
sub PENDING { 1 + $_[$#_] };

my %STATE_NAME = (
    NONE()   => 'NONE',
    STATIC() => 'STATIC',
    DEAD()   => 'DEAD',
    ALIVE()  => 'ALIVE',
);

my %STR_TO_STATE = (
    'PENDING' => PENDING(0),
    map { ($STATE_NAME{$_} => $_) } keys %STATE_NAME,
);

sub state_to_string {
    my ($state) = @_;

    $state //= NONE;
    if ($state >= PENDING(0)) {
        return sprintf("PENDING(%d)", $state - PENDING(0));
    }
    return $STATE_NAME{$state} // 'ILLEGAL';
}

sub is_valid_state {
    my $arg = uc $_[0];
    my $err_s;
    my %opts = (-err => \$err_s, @_[1..$#_]);

    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;

    if (exists $STR_TO_STATE{$arg}) {
        return $STR_TO_STATE{$arg};
    }
    elsif ($arg =~ /^PENDING\(\s*(\d+)\s*\)$/) {
        return PENDING($1);
    }

    ${$opts{-err}} = qq/'$arg' is not a valid state/;
    return;
}

1;

__END__

=pod

=head1 NAME

M6::ArpSponge::State - singing and dancing module

=head1 SYNOPSIS

 use M6::ArpSponge::State;

=head1 DESCRIPTION

This module defines symbolic constants and conversion routines for 
L<B<arpsponge>(1)|arpsponge> IP status fields.

=head1 CONSTANTS

The symbolic constants translate to integer values.

=over

=item B<STATIC>

IP address is statically sponged.

=item B<DEAD>

IP address is marked as "dead".

=item B<ALIVE>

IP address is marked as "alive".

=item B<PENDING>

Synonym for B<PENDING(0)>, that is, the IP address
is in "pending" (pre-sponge) state.

=back

=head1 FUNCTIONS

=head2 is_valid_state

    STATE_VAL = is_valid_state(STR);
    STATE_VAL = is_valid_state(STR, -err => REF);

=head2 state_to_string

    STR = state_to_string(STATE_VAL)

=head1 EXAMPLES

=head1 SEE ALSO

L<B<M6::ArpSponge::StateTable>(3)|M6::ArpSponge::StateTable>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2025.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 AMS-IX B.V.; All rights reserved.

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. See "perldoc perlartistic."

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
