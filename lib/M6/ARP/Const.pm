###############################################################################
###############################################################################
#
# ARP Sponge Flags
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
# S.Bakker, 2011;
#
###############################################################################
package M6::ARP::Const;

use strict;

use base qw( Exporter );

BEGIN {
    our $VERSION = 1.02;

    my @func   = qw(
        parse_update_flags update_flags_to_str is_valid_state
        state_to_string 
    );
    my @states = qw( STATIC DEAD ALIVE PENDING NONE );
    my @update_flags = qw(
        ARP_UPDATE_REPLY
        ARP_UPDATE_REQUEST
        ARP_UPDATE_GRATUITOUS
        ARP_UPDATE_NONE
        ARP_UPDATE_ALL
    );

    our @EXPORT_OK = ( @func, @states, @update_flags );
    our @EXPORT    = ();

    our %EXPORT_TAGS = ( 
        'func'   => \@func,
        'states' => \@states,
        'flags'  => \@update_flags,
        'all'    => [ @func, @states, @update_flags ]
    );
}

use constant ARP_UPDATE_REPLY      => 0x01;
use constant ARP_UPDATE_REQUEST    => 0x02;
use constant ARP_UPDATE_GRATUITOUS => 0x04;
use constant ARP_UPDATE_NONE       => 0x00;
use constant ARP_UPDATE_ALL        => 0x07;

our %UPDATE_FLAG_TO_STR = (
    ARP_UPDATE_REPLY()      => 'reply',
    ARP_UPDATE_REQUEST()    => 'request',
    ARP_UPDATE_GRATUITOUS() => 'gratuitous',
);

our %STR_TO_UPDATE_FLAG = (
    'none' => ARP_UPDATE_NONE,
    'all'  => ARP_UPDATE_ALL,
        map { ($UPDATE_FLAG_TO_STR{$_} => $_) } keys %UPDATE_FLAG_TO_STR,
);

# State constants/macros
use constant STATIC  => -3;
use constant DEAD    => -2;
use constant ALIVE   => -1;

sub PENDING { 0 + $_[$#_] };

our %STATE_TO_STR = (
        STATIC() => 'STATIC',
        DEAD()   => 'DEAD',
        ALIVE()  => 'ALIVE',
    );

our %STR_TO_STATE = (
        'PENDING' => PENDING(0),
        map { ($STATE_TO_STR{$_} => $_) } keys %STATE_TO_STR,
    );

=over

=item B<state_to_string> ( I<ARG> )
X<state_to_string>

=cut

sub state_to_string {
    my ($state) = @_;

    return 'NONE' if !defined $state;
    return $STATE_TO_STR{$state} // 'ILLEGAL' if $state < PENDING(0);
    return sprintf("PENDING(%d)", $state - PENDING(0));
}

=over

=item B<is_valid_state> ( I<ARG> [, B<-err =E<gt>> I<REF> )
X<is_valid_state>

=cut

sub is_valid_state {
    my $arg = uc $_[0];
    my $err_s;
    my %opts = (-err => \$err_s, @_[1..$#_]);

    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;

    return $STR_TO_STATE{$arg} if exists $STR_TO_STATE{$arg};

    ${$opts{-err}} = q/"$arg" is not a valid state/;
    return;
}

=item B<parse_update_flags> ( I<ARG> [, B<-err> =E<gt> I<REF>] )
X<parse_update_flags>

Check whether I<ARG> represents a valid list of ARP update flags. Returns an
integer representing the flags on success, C<undef> on error. Note that an
undefined I<ARG> is still valid, and represents C<ARP_UPDATE_NONE>.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=cut

sub parse_update_flags {
    my ($arg, @opts) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, @opts);

    my $flags = ARP_UPDATE_NONE;
    return $flags if ! defined $arg;
    for my $method (split(/\s*,\s*/, lc $arg)) {
        my $negate = 0;
        if ($method =~ s/^\!//) {
            $negate = 1;
        }
        if ($method eq 'none') {
            $method = 'all';
            $negate = !$negate;
        }

        if (! exists $STR_TO_UPDATE_FLAG{$method}) {
            ${$opts{-err}} = qq/"$method" is not a valid ARP update flag/;
            return;
        }

        if ($negate) {
            $flags &= ~ $STR_TO_UPDATE_FLAG{$method};
            next;
        }
        $flags |= $STR_TO_UPDATE_FLAG{$method};
    }
    return $flags;
}

=item B<update_flags_to_str> ( I<ARG> )
X<update_flags_to_str>

Translate the bits in I<ARG> to ARP update flag names and return a list of
them.

=cut

sub update_flags_to_str {
    my ($arg) = @_;
    my @list;
    
    if ($arg == ARP_UPDATE_NONE) {
        return ('none');
    }
    for my $mask ( sort keys %UPDATE_FLAG_TO_STR ) {
        if ($arg & $mask) {
            push @list, $UPDATE_FLAG_TO_STR{$mask};
        }
    }
    return @list;
}

=back

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut

1;
