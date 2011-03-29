#############################################################################
# @(#)$Id$
##############################################################################
#
# ARP sponge control socket.
#
# (c) Copyright AMS-IX B.V. 2011;
#
# See the LICENSE file that came with this package.
#
# S.Bakker, 2011
#
###############################################################################
package M6::ARP::Control;

use strict;
use base qw( IO::Socket::UNIX );

use IO::Socket;
use Scalar::Util qw( blessed );

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
    my $self = shift;
    my $data = join('', @_);

    local($::SIG{PIPE}) = 'IGNORE';
    my $nwritten = $self->syswrite($data);
    if (!$nwritten && length($!)) {
        return $self->_set_error($!);
    }
    return $self;
}

# $data = $handle->_get_data($blocking);
#
#   Wrapper around "sysread" on a socket handle. This normally
#   implements a non-blocking read on a socket, regardless of
#   what the current blocking mode on the socket is. Returns
#   "undef" if there is no data. Tries to read no more than $BUFSIZ
#   bytes, but may run over that if the last character is not a newline.
#
#       $data = $handle->_get_data($blocking);
#
sub _get_data {
    my $self = shift;
    my $blocking = @_ ? int(shift) : 0;

    my $buf;
    my $old_blocking = $self->blocking($blocking);
    my $n = $self->sysread($buf, $BUFSIZ);

    if ($buf !~ /\n\Z/) {
        my $char;
        while ($self->sysread($char, 1)) {
            $buf .= $char;
            last if $char eq "\n";
        }
    }
    $self->blocking($old_blocking);
    return $n ? $buf : undef;
}

package M6::ARP::Control::Server;

use POSIX qw( strftime );

use base qw( M6::ARP::Control );

use IO::Socket;

sub create_server {
    my $type = shift @_;
       $type = ref $type || $type;

    my $socketname = shift;
    my $maxclients = @_ ? shift : 5;

    print STDERR "M6::ARP::Control::create_server($socketname, $maxclients)\n";
    # Fill in some harmless defaults...
    #my $self = $type->new(
    my $self = IO::Socket::UNIX->new(
                    Local  => $socketname,
                    Type   => SOCK_STREAM,
                    Listen => $maxclients,
             ) or return $type->_set_error($!);

    $self->blocking(0); # Make sure we never hang as a server.
    bless $self, $type;
}

sub new {
    my $type = shift @_;
       $type = ref $type || $type;

    print STDERR "M6::ARP::Control::Server::new($type, @_)\n";

    my %args = @_;
    my $self = IO::Socket::UNIX->new(%args) or return $type->_set_error($!);

    $self->blocking(0); # Make sure we never hang as a server.
    bless $self, $type;
}

sub accept {
    my $self = shift;

    my $socket = $self->SUPER::accept() or return $self->_set_error($!);
    
    bless $socket, ref $self;
    $socket->blocking(0); # Make sure we never hang as a server.
    return $socket->_send_data("\014READY\n");
}

sub get_command {
    my $self = shift;
    return $self->_get_data();
}

sub send_response {
    my $self = shift;
    my $response = join('', @_);
    $response .= "\n" if $response !~ /\n\Z/;
    return $self->_send_data("$response\014READY\n");
}

sub send_log {
    my $self = shift;
    my $log  = join('', @_);
    chomp($log);
    my $tstamp = strftime("%Y-%m-%d %H:%M:%S", localtime(time));
    my @log = map { "\014LOG\t$tstamp [$$] $_\n" } split(/\n/, $log);
    return $self->_send_data(@log);
}

package M6::ARP::Control::Client;

use base qw( M6::ARP::Control );

use IO::Socket;

# $ref = $handle->_log_buffer;
# $handle->_log_buffer($ref);
#
#   Get/set the internal buffer of logging lines received from
#   the server end. The log_buffer acts as a circular buffer of
#   $MAXLOGLINES lines.
#
sub _log_buffer {
    my $self = shift;
    if (@_) {
        ${*$self}{'m6_arp_control_client_log_buffer'} = shift;
        return $self;
    }
    else {
        return ${*$self}{'m6_arp_control_client_log_buffer'};
    }
}

# $leftover = $handle->_parse_log_buffer($data [, \@logbuffer]);
#
#   Remove the "\014LOG\t" log lines from $data, store them in the
#   internal log buffer (or @logbuffer if given) and return the rest
#   of $data.
#
sub _parse_log_buffer {
    my $self = shift;
    my $data = shift;

    my ($log, $maxloglines);

    if (@_) {
        $log         = shift;
        $maxloglines = 0;
    }
    else {
        $log         = $self->_log_buffer;
        $maxloglines = $MAXLOGLINES;
    }

    while ($data =~ s/^\014LOG\t(.*?\n)//m) {
        if ($maxloglines && @$log > $maxloglines) {
            shift @$log;    # Rotate log buffer if necessary.
        }
        push @$log, $1;
    }
    return $data;
}


# $data = $handle->get_log_buffer;
#
#   Return the internal log buffer as a single string. Gather
#   any other log information you can get if it is available.
#
sub get_log_buffer {
    my $self = shift;
    my %args = (-order => +1, @_);

    # Tease out log data from the socket.
    my $buf = $self->_parse_log_buffer($self->_get_data(0));

    # Anything else is weird. Tag it as such.
    if (length $buf) {
        $buf =~ s/^/UNEXPECTED: /gm;
    }

    my $log = $self->_log_buffer;

    $buf = $buf . join('', $args{-order} < 0 ? reverse @$log : @$log);

    return length $buf ? $buf : undef;
}

# $handle->clear_log_buffer;
#
#   Clear the internal log buffer.
#
sub clear_log_buffer {
    @{$_[0]->_log_buffer} = ();
    return $_[0];
}


# @lines = $handle->read_log_data( [ -blocking => {0|1} ] );
#
#   Read logging data from $handle. Default is to block for input,
#   but can be overridden with "-blocking => 0".
#
sub read_log_data {
    my $self = shift;
    my %args = (-blocking => 1, @_);

    my $blocking = $args{-blocking};
    my @lines;

    # Tease out log data from the socket.
    my $buf = $self->_parse_log_buffer($self->_get_data($blocking), \@lines);

    # Anything else is weird. Tag it as such.
    if (length $buf) {
        push @lines, map { "UNEXPECTED: $_\n" } split(/\n/, $buf);
    }
    return @lines;
}

# $data = $handle->_get_response;
#
#   Wrapper around "sysread" on a socket handle, reads data
#   until it sees the "ready" prompt or an EOF. Strips the
#   ready prompt.
#
#   Returns undef on EOF or error, a string with the response
#   otherwise. Note that the response string may be empty.
#
sub _get_response {
    my $self     = shift;
    my $response = '';
    my $buf      = '';
    my $ok       = undef;

    while (my $n = $self->sysread($buf, $BUFSIZ)) {
        $response .= $buf;
        if ($response =~ s/^\014READY\n//m) {
            $ok = 1;
            last;
        }
    }
    $response = $self->_parse_log_buffer($response);
    return $ok ? $response : undef;
}

sub create_client {
    my ($type, $sockfile) = @_;
    my $self = IO::Socket::Client->new(
                        Peer      => $sockfile,
                        Type      => SOCK_STREAM,
                    ) or return;

    return bless $self, $type;
}

sub new {
    my ($type, @args) = @_;
    my $self = IO::Socket::UNIX->new(@args) or return $type->_set_error($!);

    bless $self, $type;
    $self->_log_buffer([]);
    return defined $self->_get_response ? $self : undef;
}

# $reply = $handle->send_command($command);
#
#   Send $command to the remote end and wait for the answer.
#   Returns the answer (minus any LOG lines). Returns undef
#   on error, in which case the connection is considered to
#   be lost.
#
sub send_command {
    my $self = shift;
    my $command = join(' ', split(' ', join('', @_)))."\n";

    $self->_send_data($command) || return;
    return $self->_get_response;
}

1;

__END__

=pod

=head1 NAME

M6::ARP::Control - client/server implementation for arpsponge control

=head1 SYNOPSIS

 use M6::ARP::Control;

 $server = M6::ARP::Control::Server->create_server($socket_file);

 # Alternative method (equivalent to above):
 $server = M6::ARP::Control::Server->new(
                    Local  => $socket_file,
                    Type   => SOCK_STREAM,
                    Listen =>5
                );

 $conn = $server->accept();

 $command = $conn->read_command();

 if (!defined $command) {
    print STDERR "Client disconnected\n";
    $conn->close;
 }

 if (!$conn->send_reply('Ok')) {
    print STDERR "Client disconnected\n";
    $conn->close;
 }

 # ---------------------------------------------

 $client = M6::ARP::Control::Client->create_client($socket_file);

 # Alternative method (equivalent to above):
 $client = M6::ARP::Control::Client->new(
                        Peer      => $socket_file,
                        Type      => SOCK_STREAM,
                    );

 $reply = $client->send_command('something important');

 if (!defined $reply) {
    print STDERR "Server disconnected\n";
    $client->close;
 }

=head1 DESCRIPTION

This module implements a simple client/server protocol for
controlling the ARP sponge using UNIX domain sockets.

The L<arpsponge>(8) uses a
L<M6::ARP::Control::Server|/M6::ARP::Control::Server>
object, the L<asctl>(1) program uses 
L<M6::ARP::Control::Client|/M6::ARP::Control::Client>.

It is a fairly thin wrapper around L<IO::Socket::UNIX>(3p),
implementing some defaults and handling exceptions (most
notably the SIGPIPE when writing to a disconnected peer).

=head1 PROTOCOL

The protocol implemented by this module is very simple:

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

=head1 M6::ARP::Control::Server

The
C<M6::ARP::Control::Server>
class is designed with single-threaded servers in mind that uses a
C<select()> loop to detect input on a socket. Hence, the default
I/O mode these objects is non-blocking.

=head2 Constructor

=over

=item X<new>B<new> ( I<%ARGS> )

Create a new object instance and return a reference to it. Because
this object inherits from L<IO::Socket>(3), we must keep the same
semantics for the arguments.

The L</create_server> method is preferred.

=item X<create_server>B<create_server> ( I<SOCKNAME> [, I<MAXCLIENTS> ] )

Create a new server instance, listening on I<SOCKNAME> and returning
a reference to the client object.

On error, returns C<undef> and sets the module's error field.

=cut

=back

=head1 M6::ARP::Control::Client

=head2 Constructor

=over

=item X<new>B<new> ( I<%ARGS> )

Create a new object instance and return a reference to it. Because
this object inherits from L<IO::Socket>(3), we must keep the same
semantics for the arguments.

The L</create_client> method is preferred.

=item X<create_client>B<create_client> ( I<SOCKNAME> )

Create a new client instance, connecting to I<SOCKNAME> and return
a reference to the client object.

On error, returns C<undef> and sets the module's error field.

=cut

=back

=head2 Methods

=over

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<perl(1)|perl>, L<arpsponge|arpsponge>(8),
L<M6::ARP::Sponge|M6::ARP::Sponge>(3),
L<IO::Socket|IO::Socket>(3).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=cut
