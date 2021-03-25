##############################################################################
#
# ARP sponge control socket, server side.
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
package M6::ARP::Control::Server;

use strict;
use base qw( M6::ARP::Control::Base );

use IO::Socket;
use M6::ARP::Const     qw( :states :flags );
use M6::ARP::Util      qw( :all );
use M6::ARP::NetPacket qw( :vars );
use M6::ARP::Log       qw( :func :macros );
use M6::ARP::Event     qw( :func :macros );
use Time::HiRes        qw( time );

use POSIX qw( strftime );

BEGIN {
    our $VERSION = '0.04';
}

my %Command_Dispatch = map { $_ => "_cmd_$_" } qw(
    clear_arp clear_ip clear_ip_all
    get_param get_arp get_ip get_status get_log ping quit
    set_queuedepth set_max_rate set_max_pending set_learning
    set_proberate set_flood_protection set_dummy
    set_sweep_age set_sweep_sec set_sweep_skip_alive
    set_alive set_dead set_pending set_static
    set_static_mode set_passive_mode
    set_arp_update_flags
    set_log_level set_log_mask
    probe inform
);

# my $server = M6::ARP::Control::Server->create_server(
#                   $socketname [, $maxclients]
#              );
#
#   Convenience wrapper around new().
#
sub create_server {
    my ($type, $socketname, $maxclients) = @_;
    $type = ref $type || $type;

    $maxclients //= 5;

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
    my ($type, %args) = @_;
    $type = ref $type || $type;

    my $self = $type->SUPER::new(%args) or return $type->_set_error($!);

    $self->blocking(0); # Make sure we never hang as a server.
    bless $self, $type;
}

sub _log_ctl {
    my ($self, @args) = @_;
    event_notice(EVENT_CTL, @args);
}

sub _log_crit {
    my ($self, @args) = @_;
    event_crit(EVENT_CTL, @args);
}

# my $conn = $obj->accept();
#
#   Wrapper around accept. Sends a prompt to the client.
#
sub accept {
    my ($self) = @_;

    my $socket = $self->SUPER::accept() or return $self->_set_error($!);

    bless $socket, ref $self;
    $socket->blocking(0); # Make sure we never hang as a server.
    return $socket->_send_data("\014READY\n");
}

sub get_command {
    return $_[0]->_get_data();
}

sub send_response {
    my ($self, @args) = @_;
    my $response = join('', @args);
    $response .= "\n" if $response !~ /\n\Z/;
    return $self->_send_data("$response\014READY\n");
}

sub send_ok {
    my ($self, @args) = @_;
    chomp(my $response = join('', @args));
    $response .= "\n" if length($response);
    return $self->send_response("${response}[OK]\n");
}

sub send_error {
    my ($self, @args) = @_;
    chomp(my $response = join('', @args));
    $response .= "\n" if length($response);
    return $self->send_response("${response}[ERR]\n");
}

# $obj->send_log($msg, ...);
#
#   Send a LOG message to the client, prefixed by a timestamp
#   and the server PID.
#
sub send_log {
    my ($self, @args) = @_;
    chomp(my $log  = join('', @args));
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
        $self->_log_ctl(
            "[client %d] unknown command <%s>", $self->fileno, $cmd);
        $self->send_error(qq/unknown command "$cmd"/);
        return; # Signal caller to disconnect misbehaving client.
    }
    if (!$self->can($sub_name)) {
        # We forgot to implement something.
        $self->_log_crit("FIXME: $cmd -> $sub_name not implemented!");
        return $self->send_error("FIXME: $cmd not implemented!");
    }

    my $retval = eval '$self->'.$sub_name.'($sponge, $cmd, @args)';

    if ($@) {
        $self->send_log("INTERNAL ERROR: $@");
        $self->send_error("INTERNAL ERROR: $@");
        return 1;
    }
    return $retval;
}

sub _get_param_info_s {
    my ($self, $s) = @_;

    my $probesleep = $s->user('probesleep');
    my $proberate = $probesleep ? 1/$probesleep : 1e6;

    my @response = (
        sprintf("%s=%d\n", 'queue_depth', $s->queuedepth),
        sprintf("%s=%0.2f\n", 'max_rate', $s->max_rate),
        sprintf("%s=%0.2f\n", 'flood_protection', $s->flood_protection),
        sprintf("%s=%d\n", 'max_pending', $s->max_pending),
        sprintf("%s=%d\n", 'sweep_period', $s->user('sweep_sec')),
        sprintf("%s=%d\n", 'sweep_age', $s->user('sweep_age')),
        sprintf("%s=%d\n", 'sweep_skip_alive', $s->user('sweep_skip_alive')),
        sprintf("%s=%d\n", 'proberate', $proberate),
        sprintf("%s=%d\n", 'learning', $s->user('learning')),
        sprintf("%s=%d\n", 'dummy', int($s->is_dummy)),
        sprintf("%s=%d\n", 'passive', $s->user('passive')),
        sprintf("%s=%d\n", 'static', $s->user('static')),
        sprintf("%s=%d\n", 'arp_update_flags', $s->arp_update_flags),
        sprintf("%s=%d\n", 'log_level', log_level()),
        sprintf("%s=%d\n", 'log_mask', event_mask()),
    );
    return join('', @response);
}

sub _get_status_info_s {
    my ($self, $sponge) = @_;

    my $now        = time;
    my $start_time = $sponge->user('start_time');
    my $learning   = $sponge->user('learning');

    my @response = (
        sprintf("%s=%s\n", 'id', $M6::ARP::Log::Syslog_Ident),
        sprintf("%s=%d\n", 'pid', $$),
        sprintf("%s=%s\n", 'version', $sponge->user('version')),
        sprintf("%s=%d\n", 'date', $now),
        sprintf("%s=%d\n", 'started', $start_time),
        sprintf("%s=%s\n", 'network', $sponge->network),
        sprintf("%s=%d\n", 'prefixlen', $sponge->prefixlen),
        sprintf("%s=%s\n", 'interface', $sponge->device),
        sprintf("%s=%s\n", 'ip', $sponge->my_ip),
        sprintf("%s=%s\n", 'mac', $sponge->my_mac),
        sprintf("%s=%d\n", 'next_sweep', $sponge->user('next_sweep')),
    );
    return join('', @response);
}

sub _get_ip_info_s {
    my ($self, $sponge, $ip_arg) = @_;

    my $states = $sponge->state_table;
    my $queue  = $sponge->queue;

    my @ip_list = defined $ip_arg ? ($ip_arg) : keys %$states;
    #print STDERR "ip_arg: <$ip_arg>\n";
    #print STDERR "ip_list: ", int(@ip_list), " elements\n";
    #print STDERR "ip_list: @ip_list\n";
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
    my ($self, $sponge, $command, @args) = @_;
    $self->send_ok("bye");
    return;
}

sub _cmd_ping {
    my ($self, $sponge, $command, @args) = @_;
    return $self->send_ok("ping $$");
}

sub _cmd_get_status {
    my ($self, $sponge, $cmd, @args) = @_;

    my $status = $self->_get_status_info_s($sponge);
    return $self->send_ok($status);
}

sub _cmd_get_param {
    my ($self, $sponge, $cmd, @args) = @_;

    my $status = $self->_get_param_info_s($sponge);
    return $self->send_ok($status);
}

sub _cmd_get_log {
    my ($self, $sponge, $cmd, @args) = @_;

    my $count = 0;
    if (@args) {
        $count = is_valid_int($args[0], -min=>1);
        defined $count or return $self->send_error("$cmd [<COUNT>]");
    }
    my @output;
    my $buffer = get_log_buffer();
    my $nlines = int @{$buffer};
    my $start  = ($count == 0 || $count > $nlines) ? 0 : $nlines-$count;
    for (my $i = $start; $i < $nlines; $i++) {
        my $log = $buffer->[$i];
        push @output, $log->[0]."\t$$\t".$log->[1];
    }
    return $self->send_ok(join("\n", @output));
}

sub _cmd_get_ip {
    my ($self, $sponge, $cmd, @args) = @_;

    my $ip;
    if (@args >1 ) {
        return $self->send_error("$cmd [<IP>]");
    }

    if (@args) {
        $ip = $args[0];
        if (!$sponge->is_my_network($ip)) {
            return $self->send_error(hex2ip($ip), ": address out of range");
        }
    }
    return $self->send_ok($self->_get_ip_info_s($sponge, $ip));
}

sub _cmd_get_arp {
    my ($self, $sponge, $cmd, @args) = @_;

    my $ip;
    if (@args >1 ) {
        return $self->send_error("$cmd [<IP>]");
    }
    if (@args) {
        $ip = $args[0];
        if (!$sponge->is_my_network($ip)) {
            return $self->send_error(hex2ip($ip), ": address out of range");
        }
    }
    return $self->send_ok($self->_get_arp_info_s($sponge, $ip));
}

sub _cmd_clear_arp {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args != 1 ) {
        return $self->send_error("$cmd <IP>");
    }

    my $ip = $args[0];
    if (!$sponge->is_my_network($ip)) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    $sponge->arp_table($ip, undef);
    return $self->send_ok();
}

sub _cmd_clear_ip_all {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args) {
        return $self->send_error("$cmd");
    }

    $self->_log_ctl("[client %d] %s", $self->fileno, $cmd);
    $sponge->init_all_state();
    return $self->send_ok();
}

sub _cmd_clear_ip {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args != 1 ) {
        return $self->send_error("$cmd <IP>");
    }

    my $ip = $args[0];
    if (!$sponge->is_my_network($ip)) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    $sponge->set_state($ip, undef);
    $sponge->arp_table($ip, undef);
    $self->_log_ctl(
        "[client %d] %s %s", $self->fileno, $cmd, hex2ip($ip));
    return $self->send_ok();
}

sub _cmd_set_pending {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args == 0 || @args > 2) {
        return $self->send_error("$cmd <IP> [<STATE>]");
    }
    my $ip = $args[0];
    my $state = @args > 1 ? $args[1] : 0;
    if ( ! $sponge->is_my_network($ip) ) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    $self->_log_ctl(
        "[client %d] %s %s %d",
        $self->fileno, $cmd, hex2ip($ip), $state);

    my $old_s = $sponge->state_name($sponge->get_state($ip));
    $state = $sponge->set_pending($ip, PENDING($state));
    my $new_s = $sponge->state_name($state);
    my $rate = sprintf("%0.1f", $sponge->queue->rate($ip) // 0.0);
    return $self->send_ok("ip=$ip\nold=$old_s\nnew=$new_s\nrate=$rate");
}

sub _cmd_set_static {
    my ($self, $sponge, $cmd, @args) = @_;
    if (@args != 1) {
        return $self->send_error("$cmd <IP>");
    }
    my $ip = $args[0];
    if ( ! $sponge->is_my_network($ip) ) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    $self->_log_ctl(
        "[client %d] %s %s", $self->fileno, $cmd, hex2ip($ip));

    my $old_s = $sponge->state_name($sponge->get_state($ip));
    $sponge->set_dead($ip);
    my $new_s = $sponge->state_name(DEAD());
    my $rate = sprintf("%0.1f", $sponge->queue->rate($ip) // 0.0);
    return $self->send_ok("ip=$ip\nold=$old_s\nnew=$new_s\nrate=$rate");
}

sub _cmd_set_dead {
    my ($self, $sponge, $cmd, @args) = @_;
    if (@args != 1) {
        return $self->send_error("$cmd <IP>");
    }
    my $ip = $args[0];
    if ( ! $sponge->is_my_network($ip) ) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    $self->_log_ctl(
        "[client %d] %s %s", $self->fileno, $cmd, hex2ip($ip));

    my $old_s = $sponge->state_name($sponge->get_state($ip));
    $sponge->set_dead($ip);
    my $new_s = $sponge->state_name(DEAD());
    my $rate = sprintf("%0.1f", $sponge->queue->rate($ip) // 0.0);
    return $self->send_ok("ip=$ip\nold=$old_s\nnew=$new_s\nrate=$rate");
}

sub _cmd_set_alive {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args < 1 || @args > 2) {
        return $self->send_error("$cmd <IP> [<MAC>]");
    }
    my $ip = $args[0];
    if ( ! $sponge->is_my_network($ip) ) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }
    my $old_s = $sponge->state_name($sponge->get_state($ip));
    my ($mac) = $sponge->set_alive(@args);
    my $new_s = $sponge->state_name($sponge->get_state($ip));
    my $rate = sprintf("%0.1f", $sponge->queue->rate($ip) // 0.0);
    $self->_log_ctl(
        "[client %d] %s %s %s",
        $self->fileno, $cmd, hex2ip($ip), hex2mac($mac));

    return $self->send_ok("ip=$ip\nold=$old_s\nnew=$new_s\n"
                         ."rate=$rate\nmac=$mac");
}

sub _cmd_set_queuedepth {
    my ($self, $sponge, $cmd, @args) = @_;

    my $max = is_valid_int($args[0], -min=>1);
    if (!defined $max) {
        return $self->send_error("$cmd <POSITIVE-INT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $max);
    my $old = $sponge->queuedepth();
    $sponge->queuedepth($max);
    $max    = $sponge->queuedepth();
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $max));
}

sub _cmd_set_log_level {
    my ($self, $sponge, $cmd, @args) = @_;

    my $level = is_valid_int($args[0], -min=>LOG_EMERG, -max=>LOG_DEBUG);
    if (!defined $level) {
        return $self->send_error(sprintf("%s {%d-%d}", $cmd,
                                    LOG_EMERG, LOG_DEBUG));
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $level);
    my $old = log_level($level);
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $level));
}

sub _cmd_set_log_mask {
    my ($self, $sponge, $cmd, @args) = @_;

    my $mask = is_valid_int($args[0], -min=>EVENT_NONE, -max=>EVENT_ALL);
    if (!defined $mask) {
        return $self->send_error(sprintf("%s {%#06x-%#06x}", $cmd,
                                    EVENT_NONE, EVENT_ALL));
    }
    $self->_log_ctl(
        "[client %d] %s %#06x", $self->fileno, $cmd, $mask);
    my $old = event_mask($mask);
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $mask));
}

sub _cmd_set_learning {
    my ($self, $sponge, $cmd, @args) = @_;

    my $int = is_valid_int($args[0], -min=>0);
    if (!defined $int) {
        return $self->send_error("$cmd <NON-NEGATIVE-INT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $int);
    my $old = $sponge->user('learning');
    $sponge->user('learning', $int);
    $int    = $sponge->user('learning');
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $int));
}

sub _cmd_set_max_pending {
    my ($self, $sponge, $cmd, @args) = @_;

    my $max = is_valid_int($args[0], -min=>1);
    if (!defined $max) {
        return $self->send_error("$cmd <POSITIVE-INT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $max);
    my $old = $sponge->max_pending();
    $sponge->max_pending($max);
    $max    = $sponge->max_pending();
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $max));
}

sub _cmd_set_arp_update_flags {
    my ($self, $sponge, $cmd, @args) = @_;
    my $flags = is_valid_int($args[0], -min=>ARP_UPDATE_NONE, -max=>ARP_UPDATE_ALL);
    if (!defined $flags) {
        return $self->send_error(
                sprintf("%s <%d-%d>", $cmd, ARP_UPDATE_NONE(), ARP_UPDATE_ALL())
            );
    }
    my $old = $sponge->arp_update_flags;
    $flags &= ARP_UPDATE_ALL; # Sanitise.
    $sponge->arp_update_flags($flags);
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $flags));
}

sub _cmd_set_sweep_sec {
    my ($self, $sponge, $cmd, @args) = @_;

    my $sec = is_valid_int($args[0], -min=>0);
    if (!defined $sec) {
        return $self->send_error("$cmd <NON-NEGATIVE-INT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $sec);
    my $old = $sponge->user('sweep_sec');
    $sponge->user('sweep_sec', $sec);
    my $new = $sponge->user('sweep_sec');

    my $next_sweep = 0;
    if ($new >= 1) {
        # Fix sweep age (threshold) if not previously set.
        if (!$sponge->user('sweep_age')) {
            $sponge->user('sweep_age', $new);
        }
        # Determine new "next sweep" time.
        my $old_next = $sponge->user('next_sweep') // 0;
        if ($old_next > $old) {
            # Adjust existing setting.
            $next_sweep = $old_next - $old + $new;
        }
        else {
            # No previous setting; make a brand new one.
            $next_sweep = time + $new;
        }
    }
    $sponge->user('next_sweep', $next_sweep);
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $new));
}

sub _cmd_set_sweep_age {
    my ($self, $sponge, $cmd, @args) = @_;

    my $sec = is_valid_int($args[0], -min=>1);
    if (!defined $sec) {
        return $self->send_error("$cmd <POSITIVE-INT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $sec);
    my $old = $sponge->user('sweep_age');
    $sponge->user('sweep_age', $sec);
    my $new = $sponge->user('sweep_age');
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $new));
}

sub _cmd_set_sweep_skip_alive {
    my ($self, $sponge, $cmd, @args) = @_;

    my $int = is_valid_int($args[0], -min=>0, -max=>1);
    if (!defined $int) {
        return $self->send_error("$cmd {0|1}");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $int);
    my $old = $sponge->user('sweep_skip_alive');
    $sponge->user('sweep_skip_alive', $int);
    $int = $sponge->user('sweep_skip_alive');
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $int));
}

sub _cmd_set_dummy {
    my ($self, $sponge, $cmd, @args) = @_;

    my $int = is_valid_int($args[0], -min=>0, -max=>1);
    if (!defined $int) {
        return $self->send_error("$cmd {0|1}");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $int);
    my $old = $sponge->is_dummy;
    $sponge->is_dummy($int);
    $int    = $sponge->is_dummy;
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $int));
}

sub _cmd_set_static_mode {
    my ($self, $sponge, $cmd, @args) = @_;

    my $int = is_valid_int($args[0], -min=>0, -max=>1);
    if (!defined $int) {
        return $self->send_error("$cmd {0|1}");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $int);
    my $old = $sponge->user('static');
    $sponge->user('static', $int);
    $int    = $sponge->user('static');
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $int));
}

sub _cmd_set_passive_mode {
    my ($self, $sponge, $cmd, @args) = @_;

    my $int = is_valid_int($args[0], -min=>0, -max=>1);
    if (!defined $int) {
        return $self->send_error("$cmd {0|1}");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $int);
    my $old = $sponge->user('passive');
    $sponge->user('passive', $int);
    $int    = $sponge->user('passive');
    return $self->send_ok(sprintf("old=%d\nnew=%d", $old, $int));
}

sub _cmd_set_max_rate {
    my ($self, $sponge, $cmd, @args) = @_;

    my $max = is_valid_float($args[0], -min=>0, -inclusive=>0);
    if (!defined $max) {
        return $self->send_error("$cmd <POSITIVE-FLOAT>");
    }
    $self->_log_ctl("[client %d] %s %d", $self->fileno, $cmd, $max);
    my $old = $sponge->max_rate();
    $sponge->max_rate($max);
    $max    = $sponge->max_rate();
    return $self->send_ok(sprintf("old=%0.2f\nnew=%0.2f", $old, $max));
}

sub _cmd_set_flood_protection {
    my ($self, $sponge, $cmd, @args) = @_;

    my $rate = is_valid_float($args[0], -min=>0, -inclusive=>0);
    if (!defined $rate) {
        return $self->send_error("$cmd <POSITIVE-FLOAT>");
    }
    $self->_log_ctl("[client %d] %s %0.2f", $self->fileno, $cmd, $rate);
    my $old = $sponge->flood_protection();
    $sponge->flood_protection($rate);
    $rate   = $sponge->flood_protection();
    return $self->send_ok(sprintf("old=%0.2f\nnew=%0.2f", $old, $rate));
}

sub _cmd_set_proberate {
    my ($self, $sponge, $cmd, @args) = @_;

    my $rate = is_valid_float($args[0], -min=>0, -inclusive=>0);
    if (!defined $rate) {
        return $self->send_error("$cmd <POSITIVE-FLOAT>");
    }
    my $newsleep = 1.0 / $rate;
    $sponge->print_log("[client %d] %s %0.2f (probesleep=%0.2fms)",
                        $self->fileno, $cmd, $rate, $newsleep*1000);
    my $old = 1.0 / $sponge->user('probesleep');
    $sponge->user('probesleep', $newsleep);
    $rate   = 1.0 / $sponge->user('probesleep');
    return $self->send_ok(sprintf("old=%0.2f\nnew=%0.2f", $old, $rate));
}

sub _cmd_inform {
    my ($self, $sponge, $cmd, @args) = @_;

    if (@args != 2 ) {
        return $self->send_error("$cmd <IP1> <IP2>");
    }
    my ($ip1, $ip2) = @args;

    if (!$sponge->is_my_network($ip1)) {
        return $self->send_error(hex2ip($ip1), ": address out of range");
    }
    if (!$sponge->is_my_network($ip2)) {
        return $self->send_error(hex2ip($ip2), ": address out of range");
    }

    my ($mac1, $time1) = $sponge->arp_table($ip1);
    if (!defined $mac1 || $mac1 eq $ETH_ADDR_NONE) {
        $self->send_error(hex2ip($ip1), ": no MAC address available");
        return 1;
    }

    my ($mac2, $time2);
    my $state = $sponge->get_state($ip2);
    if (defined $state && $state == DEAD()) {
        # IP address is DEAD, so update the neighbor's cache to point to us.
        $mac2 = $sponge->my_mac; # Try _our_ address..
    }
    else {
        ($mac2, my $time2) = $sponge->arp_table($ip2);
        if (!defined $mac2 || $mac2 eq $ETH_ADDR_NONE) {
            $self->send_error(hex2ip($ip2), ": no MAC address available");
            return 1;
        }
    }

    $sponge->send_arp_update(
        sha => $mac2, spa => $ip2,
        tha => $mac1, tpa => $ip1,
        tag => '[asctl] ',
    );
    return $self->send_ok(
        "sha=$mac2\nspa=$ip2\ntha=$mac1\ntpa=$ip1\nmsg=update sent"
    );
}

sub _cmd_probe {
    my ($self, $sponge, $cmd, $ip) = @_;

    if (!defined $ip) {
        return $self->send_error("$cmd <IP>");
    }

    if (!$sponge->is_my_network($ip)) {
        return $self->send_error(hex2ip($ip), ": address out of range");
    }

    $sponge->send_query($ip);
    return $self->send_ok("[ip=$ip] query sent");
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

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
