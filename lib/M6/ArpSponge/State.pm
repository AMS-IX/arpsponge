#===============================================================================
#
#       Module:  M6::ArpSponge::State
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

package M6::ArpSponge::State;

use 5.014;
use warnings;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Moo;
use M6::ArpSponge::Const qw( :states );
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

    if (!defined $state) {
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

MODNAME - singing and dancing module

=head1 SYNOPSIS

 use MODNAME;

=head1 DESCRIPTION

=head1 CONSTANTS

=head1 CONSTRUCTORS

=over

=item B<new> ( B<key> =E<gt> I<val> ... )
X<new>

Create a new MODNAME object and return a reference to it.

=back

=head1 METHODS

=head1 FUNCTIONS

=head1 EXAMPLES

=head1 FILES

=over

=item F</dev/null>

Bit-bucket.

=back

=head1 SEE ALSO

L<perl>(1).

=head1 CAVEATS

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2025.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 AMS-IX B.V.; All rights reserved.

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. See "perldoc perlartistic."

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut


