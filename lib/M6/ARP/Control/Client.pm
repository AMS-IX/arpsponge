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
package M6::ARP::Control::Client;

use base qw( M6::ARP::Control::Base );

use IO::Socket;

use M6::ARP::Control;

#use IO::Socket;

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
        $maxloglines = $M6::ARP::Control::MAXLOGLINES;
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

    while (my $buf = $self->_get_data(1)) {
        $response .= $buf;
        if ($response =~ s/^\014READY\n//m) {
            $ok = 1;
            last;
        }
    }
    #print STDERR "BUFFER:<$response>\n";
    $response = $self->_parse_log_buffer($response);
    return $ok ? $response : undef;
}

sub create_client {
    my ($type, $sockfile) = @_;
    my $self = $type->new(
                        Peer      => $sockfile,
                        Type      => SOCK_STREAM,
                    ) or return;

    return bless $self, $type;
}

sub new {
    my ($type, @args) = @_;
    my $self = $type->SUPER::new(@args) or return $type->_set_error($!);

    bless $self, $type;
    $self->_log_buffer([]);
    if (defined $self->_get_response) {
        return $self;
    }
    else {
        print STDERR "__PACKAGE__ new: _get_response returned undef\n";
        return;
    }
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

M6::ARP::Control::Client - client part of arpsponge control

=head1 SYNOPSIS

 use M6::ARP::Control::Client;

 $client = M6::ARP::Control::Client->create_client($socket_file);

 # Alternative method (equivalent to above):
 use IO::Socket;
 $client = M6::ARP::Control::Client->new(
                        Peer      => $socket_file,
                        Type      => SOCK_STREAM,
                    );

 $reply = $client->send_command('something important');

 if (!defined $reply) {
    if ($err = $client->error) {
        print STDERR "Error: $err\n";
    }
    print STDERR "Server disconnected\n";
    $client->close;
 }

=head1 DESCRIPTION

This module implements the client side of the
L<arpsponge>(8)
control connection.

=head1 CONSTRUCTORS

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

=back

=head1 METHODS

=over

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<M6::ARP::Sponge>(3),
L<M6::ARP::Control>(3),
L<M6::ARP::Control::Base>(3),
L<M6::ARP::Control::Server>(3),
L<IO::Socket|IO::Socket>(3),
L<arpsponge|arpsponge>(8), L<asctl>(1).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=cut
