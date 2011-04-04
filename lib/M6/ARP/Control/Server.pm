#############################################################################
# @(#)$Id$
##############################################################################
#
# ARP sponge control socket, server side.
#
# (c) Copyright AMS-IX B.V. 2011;
#
# See the LICENSE file that came with this package.
#
# S.Bakker, 2011
#
###############################################################################
package M6::ARP::Control::Server;

use strict;
use base qw( M6::ARP::Control::Base );

use IO::Socket;
use M6::ARP::Util qw( :all );

use POSIX qw( strftime );

BEGIN {
	our $VERSION = '0.03';
}

my %Command_Dispatch = map { $_ => "_cmd_$_" } qw(
    quit ping get_status get_arp clear_arp get_ip
    clear_ip set_dead set_alive set_pending set_queue set_rate
);

# my $server = M6::ARP::Control::Server->create_server(
#                   $socketname [, $maxclients]
#              );
#
#   Convenience wrapper around new().
#
sub create_server {
    my $type = shift @_;
       $type = ref $type || $type;

    my $socketname = shift;
    my $maxclients = @_ ? shift : 5;

    # Fill in some harmless defaults...
    my $self = $type->new(
                    Local  => $socketname,
                    Type   => SOCK_STREAM,
                    Listen => $maxclients,
             ) or return $type->_set_error($!);

    $self->blocking(0); # Make sure we never hang as a server.
    bless $self, $type;
}

# my $obj = M6::ARP::Control::Server->new($socketname [, $maxclients]);
#
#   Convenience wrapper around new().
#
sub new {
    my $type = shift @_;
       $type = ref $type || $type;

    my %args = @_;
    my $self = $type->SUPER::new(%args) or return $type->_set_error($!);

    $self->blocking(0); # Make sure we never hang as a server.
    bless $self, $type;
}

# my $conn = $obj->accept();
#
#   Wrapper around accept. Sends a prompt to the client.
#
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

sub send_ok {
    my $self = shift;
    my $response = join('', @_);
       chomp($response);
       $response .= "\n" if length($response);
    return $self->send_response("${response}[OK]\n");
}

sub send_error {
    my $self = shift;
    my $response = join('', @_);
       chomp($response);
       $response .= "\n" if length($response);
    return $self->send_response("${response}[ERR]\n");
}

# $obj->send_log($msg, ...);
#
#   Send a LOG message to the client, prefixed by a timestamp
#   and the server PID.
#
sub send_log {
    my $self = shift;
    my $log  = join('', @_);
    chomp($log);
    my $tstamp = time;
    my @log = map { "\014LOG\t$tstamp\t$$\t$_\n" } split(/\n/, $log);
    return $self->_send_data(@log);
}

###############################################################################
# $success = $conn->handle_command($sponge);
#
#    Read a command from the client on $conn and handle it. Return true
#    if the communication succeeded, false if it failed (ie. remote
#    end disconnected).
#
sub handle_command {
    my ($self, $sponge) = @_;

    my $buf = $self->get_command or return;
    
    my ($cmd, @args) = split(' ', $buf);

    my $sub_name = $Command_Dispatch{lc $cmd};
    if (!$sub_name) {
        $sponge->print_log("[client %d] unknown command <%s>",
                            $self->fileno, $cmd);
        $self->send_error(qq/unknown command "$cmd"/);
        return; # Signal caller to disconnect misbehaving client.
    }
    elsif (!$self->can($sub_name)) {
        # We forgot to implement something.
        $sponge->print_log("FIXME: $cmd -> $sub_name not implemented!");
        return $self->send_error("FIXME: $cmd not implemented!");
    }
    my $retval = eval '$self->'.$sub_name.'($sponge, @args)';
    if ($@) {
        $self->send_log("INTERNAL ERROR: $@");
        $self->send_error("INTERNAL ERROR: $@");
        return 1;
    }
    return $retval;
}

sub _get_status_info_s {
    my ($self, $sponge) = @_;

    my $now        = time;
    my $start_time = $sponge->user('start_time');
    my $learning   = $sponge->user('learning');

    my @response = (
        sprintf("%s=%s\n", 'id', $sponge->syslog_ident),
        sprintf("%s=%d\n", 'pid', $$),
        sprintf("%s=%s\n", 'version', $sponge->user('version')),
        sprintf("%s=%d\n", 'date', $now),
        sprintf("%s=%d\n", 'started', $start_time),
        sprintf("%s=%s\n", 'network', $sponge->network),
        sprintf("%s=%d\n", 'prefixlen', $sponge->prefixlen),
        sprintf("%s=%s\n", 'interface', $sponge->device),
        sprintf("%s=%s\n", 'ip', $sponge->my_ip),
        sprintf("%s=%s\n", 'mac', $sponge->my_mac),
        sprintf("%s=%d\n", 'queue_depth', $sponge->queuedepth),
        sprintf("%s=%0.2f\n", 'max_rate', $sponge->max_rate),
        sprintf("%s=%0.2f\n", 'flood_protection', $sponge->flood_protection),
        sprintf("%s=%d\n", 'max_pending', $sponge->max_pending),
        sprintf("%s=%d\n", 'sweep_period', $sponge->user('sweep_sec')),
        sprintf("%s=%d\n", 'sweep_age', $sponge->user('sweep_age')),
        sprintf("%s=%d\n", 'proberate', 1/$sponge->user('probesleep')),
        sprintf("%s=%d\n", 'next_sweep', $sponge->user('next_sweep')),
        sprintf("%s=%d\n", 'learning', $sponge->user('learning')),
        sprintf("%s=%d\n", 'dummy', int($sponge->is_dummy)),
    );
    return join('', @response);
}

sub _get_ip_info_s {
    my ($self, $sponge, $ip_arg) = @_;

    my $states = $sponge->state_table;
    my $queue  = $sponge->queue;

    my @ip_list = defined $ip_arg ? ($ip_arg) : keys %$states;
    print STDERR "ip_arg: <$ip_arg>\n";
    print STDERR "ip_list: ", int(@ip_list), " elements\n";
    print STDERR "ip_list: @ip_list\n";
    my @output = ();
    for my $ip (sort { $a cmp $b } @ip_list) {
        my $state = $states->{$ip};
        next unless defined $state;
        push @output, join('',
            sprintf("%s=%s\n", 'ip', $ip),
            sprintf("%s=%s\n", 'state', $sponge->state_name($state)),
            sprintf("%s=%s\n", 'queue', $queue->depth($ip)),
            sprintf("%s=%0.2f\n", 'rate',  $queue->rate($ip)),
            sprintf("%s=%s\n", 'state_changed',  $sponge->state_mtime($ip)),
            sprintf("%s=%s\n", 'last_queried',   $sponge->state_atime($ip)),
        );
    }
    return join("\n", @output);
}

sub _get_arp_info_s {
    my ($self, $sponge, $ip_arg) = @_;

    my $arp_table = $sponge->arp_table;
    my @ip_list = defined $ip_arg ? ($ip_arg) : keys %$arp_table;
    my @output = ();

    for my $ip (sort { $a cmp $b } @ip_list) {
        my $entry = $arp_table->{$ip};
        my ($mac, $mtime) = $entry ? @{$entry} : (mac2hex(0), 0);
        push @output, join('',
                sprintf("%s=%s\n", 'ip', $ip),
                sprintf("%s=%s\n", 'mac', $mac),
                sprintf("%s=%s\n", 'mac_changed', $mtime),
            );
    }

    return join("\n", @output);
}


###############################################################################
# $success = $conn->cmd_quit($sponge, @args);
sub _cmd_quit {
    my ($self, $sponge, @args) = @_;
    $self->send_ok("bye");
    return;
}

sub _cmd_ping {
    my ($self, $sponge, @args) = @_;
    return $self->send_ok("ping $$");
}

sub _cmd_get_status {
    my ($self, $sponge, @args) = @_;
    
    my $status = $self->_get_status_info_s($sponge);
    return $self->send_ok($status);
}

sub _cmd_get_ip {
    my ($self, $sponge, @args) = @_;

    my $ip;
    if (@args >1 ) {
        return $self->send_error("too many arguments");
    }
    elsif (@args) {
        $ip = shift @args;
        if (!$sponge->is_my_network($ip)) {
            return $self->send_error("$ip: address out of range");
        }
    }
    return $self->send_ok($self->_get_ip_info_s($sponge, $ip));
}

sub _cmd_get_arp {
    my ($self, $sponge, @args) = @_;

    my $ip;
    if (@args >1 ) {
        return $self->send_error("too many arguments");
    }
    elsif (@args) {
        $ip = shift @args;
        if (!$sponge->is_my_network($ip)) {
            return $self->send_error("address out of range");
        }
    }
    return $self->send_ok($self->_get_arp_info_s($sponge, $ip));
}

sub _cmd_clear_arp {
    my ($self, $sponge, @args) = @_;
    my $ip;
    if (@args >1 ) {
        return $self->send_error("too many arguments");
    }
    elsif (@args) {
        $ip = shift @args;
        if (!$sponge->is_my_network($ip)) {
            return $self->send_error("address out of range");
        }
    }
    $sponge->arp_table($ip, undef);
    return $self->send_ok();
}

sub _cmd_clear_ip {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}
sub _cmd_set_dead {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}
sub _cmd_set_alive {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}
sub _cmd_set_pending {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}
sub _cmd_set_queue {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}
sub _cmd_set_rate {
    my ($self, $sponge, @args) = @_;
    return $self->send_error("Not implemented yet");
}

1;

__END__

=pod

=head1 NAME

M6::ARP::Control::Server - server implementation for arpsponge control

=head1 SYNOPSIS

 use M6::ARP::Control::Server;

 $server = M6::ARP::Control::Server->create_server($socket_file);

 # Alternative method (equivalent to above):
 $server = M6::ARP::Control::Server->new(
                    Local  => $socket_file,
                    Type   => SOCK_STREAM,
                    Listen => 5
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

 $status = $conn->handle_command($sponge);

=head1 DESCRIPTION

This module implements the server side of the
L<arpsponge>(8)
control connection.

The
C<M6::ARP::Control::Server>
class is designed with single-threaded servers in mind that use a
C<select()> loop to detect input on a socket. Hence, the default
I/O mode on these objects is non-blocking.

=head1 CONSTRUCTORS

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
L<M6::ARP::Control::Client>(3),
L<IO::Socket|IO::Socket>(3),
L<arpsponge|arpsponge>(8), L<asctl>(1).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=cut
