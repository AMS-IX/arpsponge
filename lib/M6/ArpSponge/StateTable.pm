#===============================================================================
#
#       Module:  M6::ArpSponge::StateTable
#
#  Description:  State table for arpsponge.
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#      Created:  2025-07-16
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

package M6::ArpSponge::StateTable;

use 5.014;
use warnings;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Moo;
use M6::ArpSponge::State qw( :const );
use Types::Standard qw( HashRef );
use Time::HiRes qw( time );

use namespace::clean;

# Turn off auto-vivification for HASH elements.
no autovivification;

has _state   => ( is => 'rw', isa => HashRef, default => sub { {} } );
has _pending => ( is => 'rw', isa => HashRef, default => sub { {} } );

sub clear_all {
    my ($self) = @_;
    $self->_state({});
    $self->_pending({});
}

sub get_state_info     { return $_[0]->_state->{$_[1]} }
sub get_all_state_info { return $_[0]->_state }

sub is_pending         { return $_[0]->_pending->{$_[1]} }
sub get_all_pending    { return $_[0]->_pending }

sub has_state {
    return exists $_[0]->_state->{$_[1]};
}

sub get_state {
    my ($self, $ip) = @_;
    return $self->_state->{$ip}->{state};
}

sub get_mtime {
    my ($self, $ip) = @_;
    return $self->_state->{$ip}->{mtime};
}

sub set_mtime {
    my ($self, $ip, $time) = @_;
    return $self->_state->{$ip}->{mtime} = $time // time;
}

sub get_atime {
    my ($self, $ip) = @_;
    return $self->_state->{$ip}->{atime};
}

sub set_atime {
    my ($self, $ip, $time) = @_;
    return $self->_state->{$ip}->{atime} = $time // time;
}

sub set_state    {
    my ($self, $ip, $state, $time) = @_;

    if (!defined $state || $state == NONE) {
        delete $self->_state->{$ip};
        delete $self->_pending->{$ip};
        return;
    }

    $time //= time;
    @{$self->_state->{$ip}}{qw( state atime mtime )}
        = ($state, $time, $time);

    if ($state >= PENDING(0)) {
        $self->_pending->{$ip} = $state;
    }
    else {
        delete $self->_pending->{$ip};
    }
    return $state;
}

1;

__END__

=pod

=head1 NAME

M6::ArpSponge::StateTable - keep track of IP state for the arpsponge

=head1 SYNOPSIS

 use M6::ArpSponge::StateTable;
 use M6::ArpSponge::Util qw(:func);

 my $table = M6::ArpSponge::StateTable->new();

 $table->clear_all();

 $hexip = ip2hex($ip_str);

 $state_hash = get_state_info($hexip);

 $all_state_hash = $table->get_all_state_info(();

 $bool = $table->is_pending($hexip);

 $all_pending_hash = $table->get_all_pending();

 $bool = $table->has_state($hexip);

 $state = $table->get_state($hexip);
 $mtime = $table->get_mtime($hexip);
 $atime = $table->get_atime($hexip);

 $table->set_state($hexip, $state);
 $table->set_mtime($hexip, $mtime_epoch);
 $table->set_atime($hexip, $atime_epoch);

=head1 DESCRIPTION

B<M6::ArpSponge::StateTable> keeps state information for IP addresses
for the L<B<arpsponge>(1)|arpsponge>.

IP addresses are expected to be passed as hexadecimal strings, see also
L<B<ip2hex>()|M6::ArpSponge::Util/ip2hex>
and
L<B<hex2ip>()|M6::ArpSponge::Util/hex2ip>
in
L<B<M6::ArpSponge::Util>(3)|M6::ArpSponge::Util>. For this reason,
we refer to C<$hexip> and C<$HEXIP> in this document.

The table stores three things per IP address:
state,
modification time ("mtime"),
and access time ("atime").

Furthermore, it keeps track of which IP addresses are in a B<PENDING>
state.

=head1 CONSTRUCTORS

=head2 new

    OBJ = M6::ArpSponge::StateTable->new();

Create a new B<M6::ArpSponge::StateTable> object and return
a reference to it.

=head1 METHODS

=head2 clear_all

    $TABLE->clear_all();

Clears all state information from the I<$TABLE> object as if
it was freshly created via L<B<new>()|/new>.

=head2 get_all_pending

    $HASH = $TABLE->get_all_pending();

Returns a HashRef that contains an entry for each IP address that is
in one of the B<PENDING(>I<x>B<)> states
(see L<B<M6::ArpSponge::State>|M6::ArpSponge::State>):

    {
        HEXIP_1 => STATE_1,
        HEXIP_2 => STATE_2,
        ...
    }

This HashRef should be treated as B<read-only>.
Modifications to the underlying hash should be done through
L<B<clear_all>()|/clear_all> or L<B<set_state>()|/set_state>.

=head2 get_all_state_info

    $HASH = $TABLE->get_all_state_info();

Returns a HashRef that contains an entry for each IP address
for which a state is kept:

    {
        HEXIP_1 => {
            state => STATE_1,
            mtime => MTIME_1,
            atime => ATIME_1,
        }
        HEXIP_2 => {
            state => STATE_2,
            mtime => MTIME_2,
            atime => ATIME_2,
        }
        ...
    }

This HashRef should be treated as B<read-only>.
Modifications to the underlying hash should be done through
L<B<clear_all>()|/clear_all>,
L<B<set_atime>()|/set_atime>,
L<B<set_mtime>()|/set_mtime>,
or
L<B<set_state>()|/set_state>.

=head2 get_atime

    $ATIME = $TABLE->get_atime($HEXIP);

Returns the "access time" of I<$HEXIP>,
or C<undef> if I<$TABLE> has no state for I<$HEXIP>:

=head2 get_mtime

    $MTIME = $TABLE->get_mtime($HEXIP);

Returns the "modification time" of I<$HEXIP>,
or C<undef> if I<$TABLE> has no state for I<$HEXIP>:

=head2 get_state

    $STATE = $TABLE->get_state($HEXIP);

Returns the state of I<$HEXIP>
(one of the values defined in
L<B<M6::ArpSponge::State>|M6::ArpSponge::State>),
or C<undef> if I<$TABLE> has no state for I<$HEXIP>:

=head2 get_state_info

    $STATE_HASH = $TABLE->get_state_info($HEXIP);

Returns a HashRef with the state information of I<$HEXIP>,
or C<undef> if I<$TABLE> has no state for I<$HEXIP>:

    {
        state => $STATE,
        mtime => $MTIME,
        atime => $ATIME,
    }

This HashRef should be treated as B<read-only>.
Modifications to the underlying hash should be done through
L<B<clear_all>()|/clear_all>,
L<B<set_atime>()|/set_atime>,
L<B<set_mtime>()|/set_mtime>,
or
L<B<set_state>()|/set_state>.

=head2 has_state

    $BOOL = $TABLE->has_state($HEXIP);

Returns whether or not I<$TABLE> has state information for
I<$HEXIP>

=head2 is_pending

    $STATE = $TABLE->is_pending($HEXIP);

Returns the state for I<$HEXIP> if it is in one of the pending states
(B<PENDING(0)> and up), C<undef> otherwise.

=head2 set_atime

    $TABLE->set_atime($HEXIP);
    $TABLE->set_atime($HEXIP, $ATIME);

Sets the "access time" of I<$HEXIP>.
If I<$ATIME> is not given, it will set it to the current time
(using L<B<Time::HiRes>(3)|Time::HiRes>).

=head2 set_mtime

    $TABLE->set_mtime($HEXIP);
    $TABLE->set_mtime($HEXIP, $MTIME);

Sets the "modification time" of I<$HEXIP>.
If I<$MTIME> is not given, it will set it to the current time
(using L<B<Time::HiRes>(3)|Time::HiRes>).

=head2 set_state

    $TABLE->set_state($HEXIP, $STATE);
    $TABLE->set_state($HEXIP, $STATE, $TIME);

Sets the state of I<$HEXIP> in I<$TABLE>.
If I<$STATE> is B<NONE> or C<undef>,
then all state information for I<$HEXIP> will be deleted from I<$TABLE>.
Otherwise, I<$HEXIP>'s state is set to I<$STATE>
and its L<acces time|/get_atime> and L<modification time|/get_mtime>
are set to I<$TIME>
(or the current time if I<$TIME> is not given or C<undef>).

=head1 SEE ALSO

L<B<arpsponge>(1)|arpsponge>,
L<B<M6::ArpSponge::State>(3)|M6::ArpSponge::State>,
L<B<M6::ArpSponge::Util>(3)|M6::ArpSponge::Util>,
L<B<Time::HiRes>(3)|Time::HiRes>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2025.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 AMS-IX B.V.; All rights reserved.

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. See "perldoc perlartistic."

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
