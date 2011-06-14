###############################################################################
# @(#)$Id$
###############################################################################
#
# ARP Sponge Flags
#
# (c) Copyright AMS-IX B.V. 2004-2011;
#
# See the LICENSE file that came with this package.
#
# S.Bakker, 2011;
#
###############################################################################
package M6::ARP::Const;

use strict;

use base qw( Exporter );

BEGIN {
    our $VERSION = 1.01;

    my @func   = qw( parse_update_flags update_flags_to_str state_to_string );
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

=item X<state_to_string>B<state_to_string> ( I<ARG> )

=cut

sub state_to_string {
    my $state = shift;

    if (!defined $state) {
        return 'NONE';
    }
    elsif ($state < PENDING(0)) {
        return $STATE_TO_STR{$state} // 'ILLEGAL';
    }
    else {
        return sprintf("PENDING(%d)", $state - PENDING(0));
    }
}

=over

=item X<is_valid_state>B<is_valid_state> ( I<ARG>
[, B<-err =E<gt>> I<REF> )

=cut

sub is_valid_state {
    my $arg = uc shift;
    my $err_s;
    my %opts = (-err => \$err_s, @_);

    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;

    if (exists $STR_TO_STATE{$arg}) {
        return $STR_TO_STATE{$arg};
    }
    else {
        ${$opts{-err}} = q/"$arg" is not a valid state/;
        return;
    }
}

=item X<parse_update_flags>B<parse_update_flags> ( I<ARG>
[, B<-err> =E<gt> I<REF>]
)

Check whether I<ARG> represents a valid list of ARP update flags. Returns an
integer representing the flags on success, C<undef> on error. Note that an
undefined I<ARG> is still valid, and represents C<ARP_UPDATE_NONE>.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=cut

sub parse_update_flags {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, @_);

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
        if (exists $STR_TO_UPDATE_FLAG{$method}) {
            if ($negate) {
                $flags &= ~ $STR_TO_UPDATE_FLAG{$method};
            }
            else {
                $flags |= $STR_TO_UPDATE_FLAG{$method};
            }
        }
        else {
            ${$opts{-err}} = q/"$method" is not a valid ARP update flag/;
            return;
        }
    }
    return $flags;
}

=item X<update_flags_to_str>B<update_flags_to_str> ( I<ARG> )

Translate the bits in I<ARG> to ARP update flag names and return a list of
them.

=cut

sub update_flags_to_str {
    my $arg = shift;
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

1;
