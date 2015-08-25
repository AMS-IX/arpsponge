#############################################################################
# @(#)$Id$
##############################################################################
#
# ARP sponge control socket.
#
#   Copyright (c) 2011 AMS-IX B.V.; All rights reserved.
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
package M6::ARP::Control;

use strict;

BEGIN {
	our $VERSION = '0.02';
}

our $Error       = undef;
our $BUFSIZ      = 8*1024;    # Max. buffer we read at once.
our $MAXLOGLINES = 1024;      # Max no. of log lines to keep in buffer.

sub error { return $Error };

sub _set_error {
    shift @_;
    $Error = join('', @_);
    return;
}

1;

__END__

=pod

=head1 NAME

M6::ARP::Control - client/server implementation for arpsponge control

=head1 SYNOPSIS

 use M6::ARP::Control;

 M6::ARP::Control->_set_error("something scwewwy");

 print M6::ARP::Control->error, "\n";

 $M6::ARP::Control::BUFSIZ      = 8*1024;
 $M6::ARP::Control::MAXLOGLINES = 1024;

 # Modules that actually do some work:
 use M6::ARP::Control::Base;
 use M6::ARP::Control::Server;
 use M6::ARP::Control::Client;

=head1 DESCRIPTION

The C<M6::ARP::Control> modules implement a simple client/server
protocol for controlling the ARP sponge using UNIX domain sockets.

The server (L<arpsponge>) uses a
L<M6::ARP::Control::Server>
object, the client (L<asctl>) uses 
L<M6::ARP::Control::Client>.

The implementation consists of a fairly thin wrapper around
L<IO::Socket::UNIX>(3p), with sponge command handling in the
L<M6::ARP::Control::Server>
part.

You will probably never have to deal with this module directly,
but rather use 
L<M6::ARP::Control::Server>
or
L<M6::ARP::Control::Client>.

=head1 PROTOCOL

=head2 General

The basic protocol implemented by this module is very simple:

=over

=item 1. 

Client connects to server.

=item 2.

Server responds with "\014READY\n"

=item 3.

Client issues command, sent as one line, terminated with a newline.

=item 4.

Server handles command and sends a reply, followed by "\014READY\n".

=back

=head2 Logging

The server may send unsollicited logging data to the client
which is prefixed by "\014LOG\t" and terminated with a newline.

The client should be aware that these lines can show up where
normal command output is expected.

The 
L<M6::ARP::Control::Client>
object knows how to handle this and will store logging information
in an internal buffer.

=head1 VARIABLES

=over

=item X<$M6::ARP::Control::Error>I<$M6::ARP::Control::Error>

Global control socket error message. Use
L<_set_error|/_set_error> and L<error|/error>
to manipulate this variable.

=item X<$M6::ARP::Control::BUFSIZ>I<$M6::ARP::Control::BUFSIZ>

Maximum size of data chunk we try to read in at once. See also
L<M6::ARP::Control::Base/_get_data>.

=item X<$M6::ARP::Control::MAXLOGLINES>I<$M6::ARP::Control::MAXLOGLINES>

Maximum number of log lines that a 
L<M6::ARP::Control::Client> should buffer internally.

=back

=head1 CLASS METHODS

The following must be called as B<M6::ARP::Control-E<gt>>I<method>.

=over

=item X<error>B<error>

Return latest error reported by any control socket connection.

=item X<_set_error>B<_set_error> ( I<MSG> ... )

Set the control socket error string. Should be called as a class
method.

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<M6::ARP::Control::Server>,
L<M6::ARP::Control::Client>,
L<M6::ARP::Control::Base>,
L<M6::ARP::Sponge>(3),
L<IO::Socket|IO::Socket>(3),
L<arpsponge>(8), L<asctl>(1).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=head1 COPYRIGHT

Copyright 2011, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
