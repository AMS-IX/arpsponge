#############################################################################
##############################################################################
#
# ARP sponge control socket, base class.
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
# S.Bakker, 2011
#
###############################################################################
package M6::ARP::Control::Base;

use strict;
use base qw( IO::Socket::UNIX );
use M6::ARP::Control;

use IO::Socket;

BEGIN {
	our $VERSION = '0.03';
}

sub error { return M6::ARP::Control->error() };

sub _set_error {
    my ($self, @args) = @_;
    return M6::ARP::Control->_set_error(@args);
}

# $handle = $handle->_send_data("something\n", ...);
#
#   Wrapper around "syswrite" on a socket handle.
#   This catches SIGPIPE for when the remote end has disconnected.
#   In case of a SIGPIPE or other error, this will return undef,
#   otherwise it will return the object itself, allowing chaining:
#
#       $handle->_send_data("hello world\n");
#       $handle->_send_data("hello", " world\n");
#
#       $handle->_send_data("hello")->_send_data(" world\n");
#
sub _send_data {
    my ($self, @args) = @_;
    my $data = join('', @args);

    local($::SIG{PIPE}) = 'IGNORE';

    # Temporarily force blocking to avoid socket overflow
    # on large data buffers.
    my $oldblocking = $self->blocking(1);

    my $nwritten = $self->syswrite($data);
    if (!$nwritten && length($!)) {
        return $self->_set_error($!);
    }

    # Restore blocking.
    $self->blocking($oldblocking);
    return $self;
}

# $data = $handle->_get_data($blocking);
#
#   Wrapper around "sysread" on a socket handle. This normally
#   implements a non-blocking read on a socket, regardless of
#   what the current blocking mode on the socket is. Returns
#   "undef" if there is no data. Tries to read no more than
#   $M6::ARP::Control::BUFSIZ bytes, but may run over that if
#   the last character is not a newline.
#
#       $data = $handle->_get_data($blocking);
#
sub _get_data {
    my ($self, $blocking) = @_;

    $blocking //= 0;

    my $buf;
    my $old_blocking = $self->blocking($blocking);
    my $n = $self->sysread($buf, $M6::ARP::Control::BUFSIZ);

    if ($buf !~ /\n\Z/) {
        my $char;
        while ($self->sysread($char, 1)) {
            $buf .= $char;
            $n++;
            last if $char eq "\n";
        }
    }
    $self->blocking($old_blocking);
    return $n ? $buf : undef;
}

1;

__END__

=pod

=head1 NAME

M6::ARP::Control::Base - base class for arpsponge control communications

=head1 SYNOPSIS

 package SomeSocket;

 use base qw( M6::ARP::Control::Base );

 sub do_something {
    my $self = shift;
    my $arg  = "@_";

    if ($arg !~ /^Simon says, /) {
        return $self->_set_error("You forgot the magic prefix");
    }
    
    $self->_send_data($arg) || return;
    return $self->_get_data;
 }

 package main;

 my $thing = SomeSocket->new(
                    Peer      => $socket_file,
                    Type      => SOCK_STREAM,
                );

 if (my $result = $self->do_something(@ARGV)) {
    print "OK: $result\n";
 }
 else {
    print STDERR "** ERROR: ", $thing->error, "\n";
 }

=head1 DESCRIPTION

This module implements the basis of a simple client/server
protocol for controlling the ARP sponge using (UNIX domain)
sockets.

This object class is only supposed to be used as a base class
from which other (usable) classes are derived, see
L<M6::ARP::Control::Server|/M6::ARP::Control::Server>
and
L<M6::ARP::Control::Client|/M6::ARP::Control::Client>.

It is a fairly thin wrapper around L<IO::Socket::UNIX>(3p),
implementing some defaults and handling exceptions (most
notably the SIGPIPE when writing to a disconnected peer).

=head1 CONSTRUCTORS

This object defines no constructors of its own, i.e. it
inherits from L<IO::Socket::UNIX>(3).

=head1 METHODS

=over

=item X<error>B<error>

Callable as an object or class method. Returns the most recent
error string.

Wrapper around L<M6::ARP::Control/error>.

=item X<_set_error>B<_set_error> ( I<MESSAGE>, ... )

Set the class' last error message. Always returns undef/empty list, so
it can be used efficiently as:

    if ($some_error) {
        return $self->_set_error("something bad happened: $!");
    }

Wrapper around L<M6::ARP::Control/_set_error>.

=item X<_send_data>B<_send_data> ( I<DATA>, ... )

Wrapper around C<syswrite()>, writing I<DATA> to the remote end.
This catches SIGPIPE for when the remote end has disconnected.
In case of a SIGPIPE or other error, this will return undef,
otherwise it will return the object itself, allowing chaining.

Equivalent:

    $handle->_send_data("hello world\n");
    $handle->_send_data("hello", " world\n");

All arguments are concatenated and the result is sent to the remote end.

Slightly less efficient:

    $handle->_send_data("hello")->_send_data(" world\n");

This may cause your program to die if the first _send_data() fails.

=item X<_get_data>B<_get_data> ( I<BLOCKING> )

Wrapper around C<sysread()> on a socket handle. This normally
implements a non-blocking read on a socket, regardless of
the current blocking mode on the sockets. Returns
C<undef> if there is no data (or an error occurs).

Specify a true value for the I<BLOCKING> parameter
if you want the call to block for input.

In case there is data, it will read all the available data up to
L<$M6::ARP::Control::BUFSIZ|M6::ARP::Control/$M6::ARP:Control::BUFSIZ>
bytes.

Tries to read no more than I<BUFSIZ> characters, but may run over that
until it encounters a newline.

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<M6::ARP::Control>(3),
L<M6::ARP::Control::Server>(3),
L<M6::ARP::Control::Client>(3),
L<IO::Socket|IO::Socket>(3).
L<arpsponge|arpsponge>(8).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
