#!@PERL@ -I../lib
# ============================================================================
# @(#)$Id$
# ============================================================================
#
#         File:  asctl.pl
#
#        Usage:  see POD at end
#
#  Description:  ArpSponge ConTroL utility.
#
#       Author:  Steven Bakker (SB), <steven.bakker@ams-ix.net>
#      Created:  2011-03-24 15:38:13 CET
#
#   Copyright (c) 2011 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# ============================================================================

$0 =~ s|.*/||g;

use feature ':5.10';
use strict;
use warnings;
use Getopt::Long qw( GetOptions GetOptionsFromArray );
use POSIX qw( strftime floor );
use Pod::Usage;
use M6::ARP::Control::Client;
use Time::HiRes qw( time sleep );
use M6::ARP::Util qw( :all );
use Term::ReadLine;

my $SPONGE_VAR    = '@SPONGE_VAR@';
my $OUT           = \*STDOUT;
my $IN            = \*STDIN;
my $TERM          = undef;
my $CONN          = undef;
my $STATUS        = {};
my $INTERACTIVE   = 0;

# Values set on the Command Line.
my $opt_verbose   = undef;
my $opt_debug     = 0;
my $rundir        = $SPONGE_VAR;
my $MAX_HISTORY   = 1000;
my $HISTFILE      = "$::ENV{HOME}/.$0_history";

($::VERSION) = '$Revision$' =~ /Revision: (\S+) \$/;
my $app_header = "\nThis is $0, v$::VERSION\n\n"
               . "See \"perldoc $0\" for more information.\n"
               ;

END {
    if ($CONN) {
        $CONN->close;
    }
}

sub rl_completion;

sub verbose(@) { print @_ if $opt_verbose; }

sub Main {
    my ($sockname, $args) = initialise();

    verbose "connecting to arpsponge on $sockname\n";
    $CONN = M6::ARP::Control::Client->create_client($sockname)
                or die M6::ARP::Control::Client->error."\n";

    ($STATUS) = get_status($CONN, {raw=>0, format=>1});
    verbose "$$STATUS{id}, v$$STATUS{version} (pid #$$STATUS{pid})\n";

    my $err = 0;

    if (@$args) {
        my $command = do_command($CONN, join(' ', @$args));
    }
    else {
        ($TERM, my $prompt, $IN, $OUT) = init_readline($args);

        while ( defined (my $input = $TERM->readline($prompt)) ) {
            next if $input =~ /^\s*(?:#.*)?$/;
            my $command = do_command($CONN, $input);

            if (!defined $CONN->send_command("ping")) {
                if ($command eq 'quit') {
                    verbose "connection closed\n";
                }
                else {
                    $err++;
                    print STDERR "** connection closed unexpectedly\n";
                }
                last;
            }
        }
    }
    $CONN->close;
    exit $err;
}

sub check_send_command {
    my $conn = shift;
    my $command = join(' ', @_);

    my $reply = $conn->send_command($command) or return;
       $reply =~ s/^\[(\S+)\]\s*\Z//m;

    if ($1 eq 'OK') {
        return $reply;
    }
    else {
        return print_error($reply);
    }
}

sub expand_ip_run {
    my $args = shift;
    my $code = shift;

    my $arg_str = join(' ', @$args);
       $arg_str =~ s/\s*(?:-|\.\.|to)\s*/-/g;
       $arg_str =~ s/\s*,\s*/ /;

    @$args = split(' ', $arg_str);

    my @reply;
    for my $ip_s (@$args) {
        my ($lo_s, $hi_s) = split(/-/, $ip_s);
        my ($lo, $hi);
        $lo = ip2int($lo_s)
            or return print_error(qq{"$lo_s": invalid IP address});
        if ($hi_s) {
            $hi = ip2int($hi_s)
                or return print_error(qq{"$lo_s": invalid IP address});
        }
        else { $hi = $lo }
        for (my $ip = $lo; $ip <= $hi; $ip++) {
            my $sub = $code->(ip2hex(int2ip($ip)));
            return if !defined $sub;
            push @reply, $sub if length($sub);
        }
    }
    return join("\n", @reply);
}

sub dispatch {
    my $conn    = shift;
    my $parsed  = shift;
    my $args    = shift;
    my $valid   = shift;
    my $params  = @_ ? shift : {};

    my $prefix = join('', map { $_.'_' } @$parsed);
       $prefix =~ s/-/_/g;

    my %commands;
    for my $sub (@$valid) {
        my $func_name = "do_${prefix}${sub}";
        $func_name =~ s/-/_/g;
        $commands{$sub} = eval '\&'.$func_name;
    }

    my $command = lc shift @$args;
    push @$parsed, $command;
    if (exists $commands{lc $command}) {
        my $func = $commands{lc $command};
        if (defined $func) {
            return $func->($conn, $parsed, $args, $params);
        }
        else {
            print_error("[INTERNAL] @$parsed: not implemented!");
        }
    }
    else {
        print_error("@$parsed: command unknown");
    }
    return 0;
}

sub do_command {
    my $conn  = shift;
    my @args = split(' ', shift);

    dispatch($conn,
                    [],
                    [ @args ],
                    [ qw( ping quit status show set clear sponge unsponge ) ]
           );

    return $args[0];
}

# $delay = check_bool_arg('toggle', 'dummy', $arg);
sub check_bool_arg {
    my ($name, $command, $arg) = @_;

    if ($arg =~ /^(1|yes|true|on)$/i) {
        return 1;
    }
    elsif ($arg =~ /^(0|no|false|off)$/i) {
        return 0;
    }
    else {
        return print_error(qq{"$arg" is not a valid boolean});
    }
}

# $delay = check_float_arg('delay', 0.001, undef, 'ping', $arg);
sub check_float_arg {
    my ($name, $min, $max, $command, $arg) = @_;

    if ($arg !~ /^[\+\-]?(?:\d*\.)?\d+$/) {
        return print_error(qq{"$arg" is not a valid floating point number});
    }
    if (defined $min && $arg < $min) {
        if (defined $max && $max != $min) {
            return print_error(
                    qq{$name must be between $min and $max (inclusive)}
                );
        }
        else {
            return print_error(qq{$name must be at least $min});
        }
    }
    elsif (defined $max && $arg > $max) {
        if (defined $max && $max != $min) {
            return print_error(
                    qq{$name must be between $min and $max (inclusive)}
                );
        }
        else {
            return print_error(qq{$name cannot be more than $max});
        }
    }
    return $arg;
}

# $param = check_int_arg('count', 1, 255, 'ping', $arg);
sub check_int_arg {
    my ($name, $min, $max, $command, $arg) = @_;

    if ($arg !~ /^[\+\-]?\d+$/) {
        return print_error(qq{"$arg" is not a valid integer});
    }
    if (defined $min && $arg < $min) {
        if (defined $max && $max != $min) {
            return print_error(
                    qq{$name must be between $min and $max (inclusive)}
                );
        }
        else {
            return print_error(qq{$name must be at least $min});
        }
    }
    elsif (defined $max && $arg > $max) {
        if (defined $max && $max != $min) {
            return print_error(
                    qq{$name must be between $min and $max (inclusive)}
                );
        }
        else {
            return print_error(qq{$name cannot be more than $max});
        }
    }
    return $arg;
}

sub check_arg_count {
    my ($min, $max, $command, $args) = @_;

    if (defined $min && int(@$args) < $min) {
        return print_error(qq{"$command" - not enough arguments});
    }
    if (defined $max && int(@$args) > $max) {
        return print_error(qq{"$command" - too many arguments});
    }
    return 1;
}

sub do_quit {
    my ($conn, $parsed, $args) = @_;
    my $reply = check_send_command($conn, 'quit') or return;
    print_output($reply);
}

sub do_ping {
    my ($conn, $parsed, $args) = @_;

    my $count = 1;
    my $delay = 1;
    check_arg_count(0,2,"@$parsed", $args) or return;
    if (@$args) {
        $count = check_int_arg('count', 1, 255, "@$parsed", shift @$args)
                // return;
    }
    if (@$args) {
        $delay = check_float_arg('delay', 0.001, undef, "@$parsed", $$args[0])
                // return;
    }

    my @rtt;
    my ($min_rtt, $max_rtt, $tot_rtt) = (undef,undef,0);
    my $interrupt = 0;
    local ($::SIG{INT}) = sub { $interrupt++ };
    my ($ns, $nr) = (0,0);
    my $global_start = time;
    for (my $n=0; $n<$count; $n++) {
        my $start = time;
        $ns++;
        if (my $reply = check_send_command($conn, 'ping')) {
            my $rtt   = (time - $start)*1000;
            $tot_rtt += $rtt;
            if (!defined $min_rtt) {
                $min_rtt = $max_rtt = $rtt;
            }
            else {
                $min_rtt = $rtt if $rtt < $min_rtt;
                $max_rtt = $rtt if $rtt > $max_rtt;
            }
            push @rtt, $rtt;
            $nr++;
            print_output(
                sprintf("%d bytes from #%d: time=%0.3f ms\n",
                        length($reply), $$STATUS{pid}, $rtt
                    )
            );
        }
        else {
            last;
        }
        sleep($delay) if $n < $count - 1;
        if ($interrupt) {
            print_error("** Interrupt");
            last;
        }
    }
    if ($count>1) {
        my $loss = ($ns - $nr) / ($ns ? $ns : 1) * 100;
           $loss = floor($loss+0.5);
        my $time = (time - $global_start)*1000;
           $time = floor($time+0.5);
        my $avg_rtt = $tot_rtt / ($nr ? $nr : 1);
        my $mdev_rtt = 0;
        for my $x (@rtt) { $mdev_rtt += abs($avg_rtt - $x) }
        $mdev_rtt = $mdev_rtt / ($nr ? $nr : 1);
        print_output("--- $$STATUS{id} ping statistics ---\n",
            sprintf("%d packets transmitted, %d received, ", $ns, $nr),
            sprintf("%d%% packet loss, time %dms\n", $loss, $time),
            sprintf("rtt min/avg/max/mdev = %0.3f/%0.3f/%0.3f/%0.3f ms\n",
                    $min_rtt, $avg_rtt, $max_rtt, $mdev_rtt)
        );
    }
}

###############################################################################
# SHOW commands
###############################################################################

# cmd: show
sub do_show {
    my ($conn, $parsed, $args) = @_;
    my $format  = 1;
    my $command = join(' ', @$parsed);

    check_arg_count(1,undef,$command, $args) or return;

    return dispatch($conn,
                    $parsed,
                    $args,
                    [ qw( status log version uptime ip arp ) ]
           );
}

# cmd: show status
sub do_show_status {
    return do_status(@_);
}

# cmd: show log
sub do_show_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    GetOptionsFromArray($args,
                'raw!'     => \(my $raw = 0),
                'format!'  => \$format,
                'reverse!' => \(my $reverse = 1),
                'nf'       => sub { $format = 0 },
            ) or return;

    $format &&= !$raw;

    check_arg_count(0,1,"@$parsed", $args) or return;

    my $nlines = 0;
    if (@$args) {
        $nlines = check_int_arg('line count', 1, undef, "@$parsed", shift @$args)
                  or return;
    }

    my @args = $nlines ? ($nlines) : ();
    my $log = check_send_command($conn, 'get_log', @args) or return;
    if ($format) {
        $log =~ s/^(\S+)\t(\d+)\t/format_time($1,' ')." [$2] "/gme;
    }
    if ($reverse) {
        $log = join("\n", reverse split(/\n/, $log));
    }
    print_output($log);
}

# cmd: show version
sub do_show_version {
    my ($conn, $parsed, $args) = @_;
    check_arg_count(0,0,"@$parsed", $args) or return;
    print_output($STATUS->{'version'}."\n");
}

# cmd: show uptime
sub do_show_uptime {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(0,0,"@$parsed", $args) or return;

    ($STATUS) = get_status($conn, {raw=>0, format=>1});

    return if !$STATUS;

    print_output(
        sprintf("%s up %s (started: %s)\n",
            strftime("%H:%M:%S", localtime(time)),
            relative_time($STATUS->{'started'}, 0),
            format_time($STATUS->{'started'}),
        )
    );
}

# cmd: show arp
sub do_show_arp {
    my ($conn, $parsed, $args) = @_;

    if (@$args && grep { lc $_ eq 'all' } @$args) {
        $args = [];
    }

    my ($opts, $output, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_arp', $parsed, $args);

    defined $output or return;

    if (!$$opts{format}) {
        print_output($output);
        return;
    }

    my @output;
    if ($$opts{summary}) {
        if ($$opts{header}) {
            push @output, sprintf("%-17s %-17s %-11s %s",
                                  "MAC", "IP", "Epoch", "Time");
        }
        for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$output) {
            push @output,
                    sprintf("%-17s %-17s %-11d %s",
                        $$info{mac}, $$info{ip}, 
                        $$info{mac_changed},
                        format_time($$info{mac_changed}),
                    );
        }
    }
    else {
        for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$output) {
            print STDERR "tagfmt: $tag_fmt\n";
            push @output, join('',
                sprintf("$tag_fmt%s\n", 'ip:', $$info{ip}),
                sprintf("$tag_fmt%s\n", 'mac:', $$info{mac}),
                sprintf("$tag_fmt%s (%s) [%d]\n", 'mac changed:',
                        format_time($$info{mac_changed}),
                        relative_time($$info{mac_changed}),
                        $$info{mac_changed}),
            );
        }
    }
    print_output(join("\n", @output));
}

# cmd: show ip
sub do_show_ip {
    my ($conn, $parsed, $args) = @_;

    my $filter_state;
    if (@$args && grep { lc $_ eq 'all' } @$args) {
        $args = [];
    }

    if (@$args && $$args[0] =~ /^(?:dead|alive|pending|none)$/i) {
        $filter_state = uc shift @$args;
    }

    my ($opts, $output, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_ip', $parsed, $args);

    defined $output or return;

    if (!$$opts{format}) {
        print_output($output);
        return;
    }

    my @output;
    if ($$opts{summary}) {
        if ($$opts{header}) {
            push @output, sprintf("%-17s %-12s %7s %12s %7s",
                                    "IP", "State", "Queue",
                                    "Rate (q/min)", "Updated");
        }
        for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$output) {
            next if defined $filter_state && $$info{state} ne $filter_state;
            push @output,
                    sprintf("%-17s %-12s %7d %8.3f     %s",
                            $$info{ip}, $$info{state}, $$info{queue},
                            $$info{rate},
                            format_time($$info{state_changed}),
                    );
        }
    }
    else {
        for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$output) {
            next if defined $filter_state && $$info{state} ne $filter_state;
            push @output, join('',
                sprintf("$tag_fmt%s\n", 'ip:', $$info{ip}),
                sprintf("$tag_fmt%s\n", 'state:', $$info{state}),
                sprintf("$tag_fmt%d\n", 'queue:', $$info{queue}),
                sprintf("$tag_fmt%0.2f\n", 'rate:', $$info{rate}),
                sprintf("$tag_fmt%s (%s) [%d]\n", 'state changed:',
                        format_time($$info{state_changed}),
                        relative_time($$info{state_changed}),
                        $$info{state_changed}),
                sprintf("$tag_fmt%s (%s) [%d]\n", 'last queried:',
                        format_time($$info{last_queried}),
                        relative_time($$info{last_queried}),
                        $$info{last_queried}),
            );
        }
    }
    print_output(join("\n", @output));
}

# ($opts, $output, $tag_fmt) =
#       shared_show_arp_ip($conn, $command, $parsed, $args);
#
#   Executes the specified command and parses the result, translating
#   hex strings to ip and mac addresses where necessary.
#
#   Parameters:
#       $conn       connection handle
#       $command    base command to execute
#       $parsed     ref to list of already parsed words
#       $args       ref to list of still to parse arguments
#
#   Return values:
#       $opts       ref to hash with key=>val options from the @$args
#       $output     either a string (in case of --noformat or --raw),
#                   or a reference to an array of output records. Each
#                   record is a hash (ref) containing key=>value pairs.
#       $tag_fmt    printf format string for the largest "key" string,
#                   e.g. "%-20s".
#
sub shared_show_arp_ip {
    my ($conn, $command, $parsed, $args) = @_;
    my %opts = (
            'header'  => 1,
            'format'  => 1,
            'summary' => 1,
            'raw'     => 0,
        );

    GetOptionsFromArray($args,
            'header!'  => \$opts{header},
            'raw!'     => \$opts{raw},
            'format!'  => \$opts{format},
            'long!'    => sub { $opts{summary} = !$_[1] },
            'summary!' => sub { $opts{summary} = $_[1] },
            'nf'       => sub { $opts{format}  = 0  },
            'nh'       => sub { $opts{header}  = 0  },
        ) or return;

    $opts{format} &&= !$opts{raw};

    check_arg_count(0,undef,"@$parsed", $args) or return;
    
    my $reply = '';
    if (@$args) {
        my $arg_count = 0;
        $reply = expand_ip_run($args, 
                    sub {
                        $arg_count++;
                        return check_send_command($conn, "$command $_[0]");
                    }
                );
        $opts{summary} //= ($arg_count > 1);
    }
    else {
        $reply = check_send_command($conn, $command);
        $opts{summary} //= 1;
    }

    return parse_server_reply($reply, \%opts);
}

# ($output, $tag_fmt) = parse_server_reply($reply, \%opts, [, $key]);
#
#   Helper function for parsing replies from server.
#
#   Parameters:
#
#       $opts     - Hash ref with options:
#                        raw    : don't convert IP/MAC addresses (dfl. false).
#                        format : split up into records (dfl. 1).
#       $reply    - Raw reply from server.
#
#       $key      - Key to store records under. If not given, records will be
#                   stored in an array.
#
#   Returns:
#
#       $opts     - The input hash, but with default values filled in.
#       $output   - Either a string (in case of format=0 or raw=1),
#                   or a reference to an array of output records. Each
#                   record is a hash (ref) containing key=>value pairs.
#       $tag_fmt  - Printf format string for the largest "key" string,
#                   e.g. "%-20s".
#
sub parse_server_reply {
    my $reply = shift;
    my $opts  = @_ ? shift : {};

    %$opts = (
            'format' => 1,
            'raw'    => 0,
            %$opts,
        );

    return if !defined $reply;

    if (!$opts->{raw}) {
        $reply =~ s/^(network|ip)=([\da-f]+)$/"$1=".hex2ip($2)/gme;
        $reply =~ s/^(mac)=([\da-f]+)$/"$1=".hex2mac($2)/gme;
    }
    if (!$opts->{format}) {
        return ($opts, $reply, '');
    }

    my @output;
    my $taglen  = 0;
    for my $record (split(/\n\n/, $reply)) {
        my %info = map { split(/=/, $_) } split("\n", $record);

        if (my $ip = $info{'network'}) {
            $info{'hex_network'} = ip2hex($ip);
        }
        if (my $ip = $info{'ip'}) {
            $info{'hex_ip'} = ip2hex($ip);
        }
        if (my $mac = $info{'mac'}) {
            $info{'hex_mac'} = mac2hex($mac);
        }

        push @output, \%info;

        foreach (keys %info) {
            $taglen = length($_) if length($_) > $taglen;
        }
    }
    $taglen++;
    my $tag_fmt = "%-${taglen}s ";

    return ($opts, \@output, $tag_fmt);
}

###############################################################################
# CLEAR commands
###############################################################################

# cmd: clear
sub do_clear {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    check_arg_count(1,undef, "@$parsed", $args) or return;

    return dispatch($conn,
                    $parsed,
                    $args,
                    [ qw( log ip arp ) ]
           );
}

# cmd: clear ip
sub do_clear_ip {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,undef, "@$parsed", $args) or return;

    if (@$args && grep { lc $_ eq 'all' } @$args) {
        return check_send_command($conn, 'clear_ip_all') or return;
    }

    expand_ip_run($args, 
                    sub {
                        return check_send_command($conn, "clear_ip $_[0]");
                    }
                );
    return;
}

# cmd: clear arp
sub do_clear_arp {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,undef, "@$parsed", $args) or return;

    expand_ip_run($args, 
                    sub {
                        return check_send_command($conn, "clear_arp $_[0]");
                    }
                );
    return;
}


# cmd: clear log
sub do_clear_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    check_arg_count(0,0,"@$parsed", $args) or return;

    my $log = $conn->get_log_buffer(-order => -1);
    $conn->clear_log_buffer;
    print_output(length($log)." bytes cleared");
}

###############################################################################
# SET commands
###############################################################################

# cmd: set
sub do_set {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    check_arg_count(1,undef, "@$parsed", $args) or return;

    return dispatch($conn,
                    $parsed,
                    $args,
                    [ qw(
                        ip max-pending queuedepth max-rate learning
                        flood-protection proberate dummy sweep
                    ) ],
           );
}

# cmd: set max-pending
sub do_set_max_pending {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_int_arg('max-pending', 1, 255, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_max_pending', $max) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("max-pending changed from %d to %d",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set queuedepth
sub do_set_queuedepth {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_int_arg('queuedepth', 1, undef, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_queuedepth', $max) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("queuedepth changed from %d to %d",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set max-rate
sub do_set_max_rate {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_float_arg('max-rate', 1, undef, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_max_rate', $max) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("max-rate changed from %0.2f to %0.2f q/min",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set learning
sub do_set_learning {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_int_arg('secs', 1, undef, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_learning', $max) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("learning changed from %d to %d secs",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set flood-protection
sub do_set_flood_protection {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_float_arg('rate', 0.01, undef, 
                              "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_flood_protection', $max) 
                or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf(
                    "flood-protection changed from %0.2f to %0.2f q/min",
                    $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set proberate
sub do_set_proberate {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $max = check_float_arg('rate', 0.01, undef, 
                              "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_proberate', $max) 
                or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("proberate changed from %0.2f to %0.2f q/sec",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set dummy
sub do_set_dummy {
    my ($conn, $parsed, $args) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $mode = check_bool_arg('rate', "@$parsed", shift @$args);
    return if ! defined $mode;
    my $reply = check_send_command($conn, 'set_dummy', $mode) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("dummy changed from <%s> to <%s>",
                        ($output->[0]->{old} ? 'yes' : 'no'),
                        ($output->[0]->{new} ? 'yes' : 'no'),
                    ));
}
 
# cmd: set sweep
sub do_set_sweep {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(2,2, "@$parsed", $args) or return;

    return dispatch($conn, $parsed, $args,
                    [ qw( period age ) ],
                    $params,
           );
}

# cmd: set sweep period
sub do_set_sweep_period {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $secs = check_int_arg('secs', 1, undef, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_sweep_sec', $secs) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("sweep period changed from %d to %d secs",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set sweep age
sub do_set_sweep_age {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(1,1,"@$parsed", $args) or return;
    my $secs = check_int_arg('secs', 1, undef, "@$parsed", shift @$args)
                or return;
    my $reply = check_send_command($conn, 'set_sweep_age', $secs) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    print_output(sprintf("sweep age changed from %d to %d secs",
                        $output->[0]->{old}, $output->[0]->{new}));
}

# cmd: set ip
sub do_set_ip {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(2,undef, "@$parsed", $args) or return;

    my $ip_s = shift @$args;

    my $ip = ip2hex($ip_s) or return print_error("$ip_s: invalid IP address");

    $params->{'ip'} = $ip;

    return dispatch($conn, $parsed, $args,
                    [ qw( pending alive dead mac ) ],
                    $params,
           );
}

# cmd: set ip pending
sub do_set_ip_pending {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(undef,1, "@$parsed", $args) or return;

    my $ip = $params->{'ip'};

    my $state = @$args ? shift @$args : 0;

    check_send_command($conn, 'set_pending', $ip, $state);
}

# cmd: set ip dead
sub do_set_ip_dead {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(0,0, "@$parsed", $args) or return;

    my $ip = $params->{'ip'};

    check_send_command($conn, 'set_dead', $ip);
}

# cmd: set ip alive
sub do_set_ip_alive {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(0,1, "@$parsed", $args) or return;

    my $ip = $params->{'ip'};

    if (@$args) {
        my $mac_s = shift @$args;
        my $mac = max2hex($mac_s)
            or return print_error(qq{"$mac_s": invalid MAC address});
        return check_send_command($conn, 'set_alive', $ip, $mac);
    }
    return check_send_command($conn, 'set_alive', $ip);
}

# cmd: set ip mac
#
#   Alias for "set ip alive" with a mandatory MAC argument.
sub do_set_ip_mac {
    my ($conn, $parsed, $args, $params) = @_;

    check_arg_count(1,1, "@$parsed", $args) or return;
    return do_set_ip_alive($conn, $parsed, $args, $params);
}

###############################################################################
# STATUS command
###############################################################################

# cmd: status
sub do_status {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    my %opts = ( raw => 0, format => 1 );

    GetOptionsFromArray($args,
            'raw!'     => \$opts{raw},
            'format!'  => \$opts{format},
            'nf'       => sub { $opts{format} = 0 },
        ) or return;

    $opts{format} &&= !$opts{raw};

    check_arg_count(0,0,"@$parsed", $args) or return;
    
    my $reply = check_send_command($conn, 'get_status') or return;

    my ($opts, $output, $tag) = parse_server_reply($reply, \%opts);

    if (!$opts->{format}) {
        return print_output($output);
    }
    my $info = $output->[0];
    print_output(
        sprintf("$tag%s\n", 'id:', $$info{id}),
        sprintf("$tag%d\n", 'pid:', $$info{pid}),
        sprintf("$tag%s\n", 'version:', $$info{version}),
        sprintf("$tag%s [%d]\n", 'date:',
                format_time($$info{date}), $$info{date}),
        sprintf("$tag%s [%d]\n", 'started:',
                format_time($$info{started}), $$info{started}),
        sprintf("$tag%s/%d\n", 'network:',
                $$info{network}, $$info{prefixlen}),
        sprintf("$tag%s\n", 'interface:', $$info{interface}),
        sprintf("$tag%s\n", 'IP:', $$info{ip}),
        sprintf("$tag%s\n", 'MAC:', $$info{mac}),
        sprintf("$tag%d\n", 'queue depth:', $$info{queue_depth}),
        sprintf("$tag%0.2f q/min\n", 'max rate:', $$info{max_rate}),
        sprintf("$tag%0.2f q/sec\n", 'flood protection:',
                $$info{flood_protection}),
        sprintf("$tag%d\n", 'max pending:', $$info{max_pending}),
        sprintf("$tag%d secs\n", 'sweep period:', $$info{sweep_period}),
        sprintf("$tag%d secs\n", 'sweep age:', $$info{sweep_age}),
        sprintf("$tag%d pkts/sec\n", 'proberate:', $$info{proberate}),
        sprintf("$tag%s (in %d secs) [%d]\n", 'next sweep:',
                format_time($$info{next_sweep}),
                $$info{next_sweep}-$$info{date},
                $$info{next_sweep}),
        sprintf("$tag%s\n", 'learning', 
                    $$info{learning}?"yes ($$info{learning} secs)":'no'),
        sprintf("$tag%s\n", 'dummy', $$info{dummy}?'yes':'no'),
    );
}

# ($output, $tag_fmt) = get_status($conn, \%opts);
#
#   Helper function for status. Similar to the ip/arp thing.
#
sub get_status {
    my ($conn, $opts) = @_;

    my $reply = check_send_command($conn, 'get_status') or return;

    if (!$$opts{raw}) {
        $reply =~ s/^(network|ip)=([\da-f]+)$/"$1=".hex2ip($2)/gme;
        $reply =~ s/^(mac)=([\da-f]+)$/"$1=".hex2mac($2)/gme;
    }

    if (!$$opts{format}) {
        return ($reply, '%s ');
    }

    my %info = map { split(/=/, $_) } split("\n", $reply);
    my $taglen = 0;
    foreach (keys %info) {
        $taglen = length($_) if length($_) > $taglen;
    }
    $taglen++;
    return (\%info, "%-${taglen}s ");
}

###############################################################################
# Initialisation
###############################################################################

sub initialise {
    my ($sockname, $interface);
    GetOptions(
        'verbose'     => \$opt_verbose,
        'help|?'      =>
            sub { pod2usage(-msg => $app_header, -exitval=>0, -verbose=>0) },
        'interface=s' => \$interface,
        'rundir=s'    => \$rundir,
        'socket=s'    => \$sockname,
        'manual'      => sub { pod2usage(-exitval=>0, -verbose=>2) },
    ) or pod2usage(-exitval=>2);

    if ($sockname) {
        if ($interface) {
            die "$0: --socket and --interface are mutually exclusive\n";
        }
    }
    elsif ($interface) {
        $sockname = "$rundir/$interface/control";
    }
    else {
        for my $entry (glob("$rundir/*")) {
            if (-S "$entry/control") {
                $sockname = "$entry/control";
                last;
            }
        }
        if (!$sockname) {
            die "$0: cannot find sponge instance in $rundir\n";
        }

    }

    $INTERACTIVE = -t STDIN && -t STDOUT;
    $opt_verbose //= $INTERACTIVE && !@ARGV;

    return ($sockname, [@ARGV]);
}

# print_error($msg, ...);
#
#   Always returns false, always prints to STDERR, always ends
#   with a newline.
#
sub print_error {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;
    print STDERR $out;
    return;
}

# print_output($msg, ...);
#
#   Print output, through pager if interactive.
#
sub print_output {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;

    if ($INTERACTIVE) {
        open(MORE, "|less"
                ." --no-lessopen --no-init --dumb"
                ." --quit-at-eof --quit-if-one-screen");
        print MORE $out;
        close MORE;
    }
    else {
        print $out;
    }
}

##############################################################################
# READLINE STUFF
##############################################################################

sub list_ip_completion {
    my ($text, $line, $start) = @_;

    my $network   = $$STATUS{'network'};
    my $prefixlen = $$STATUS{'prefixlen'};
    
    my $fixed_octets = int($prefixlen / 8);
    if ($fixed_octets == 4) {
        return $network;
    }
    if ($fixed_octets) {
        my $fixed = join('.', (split(/\./, $network))[0..$fixed_octets-1] );
        if ($start < length $line) {
            my $have_len = length($line) - $start;
            my @completions = (map { "$fixed.$_" } (0..255));
            if ($have_len >= $fixed_octets) {
                # Turn IP addresses into "91.200.17.1[x[x[x]]]"
                # That is, keep the part that has already matched
                # and reveal only the next digit, turn the rest into "x".
                my %completions = map {
                        my $keep = substr($_, 0, $have_len+1);
                        my $hide = length($_) > $have_len+1 
                                    ? substr($_, $have_len+1)
                                    : '';
                        $hide =~ s/[\da-f]/x/gi;
                        $keep.$hide => 1;
                    } @completions;
                return keys %completions;
                #return grep { length($_) <= $have_len+1 } @completions;
            }
            else {
                return grep { length($_) == length($fixed)+2 } @completions;
            }
        }
        else {
            return "$fixed.";
        }
    }
    else {
        return;
    }
}

my %Completions = (
    ''          => [qw( quit ping sponge unsponge clear set show status )],
    'clear'     => [qw( ip arp log )],
    'set'       => [qw( ip max-pending queuedepth max-rate
                     flood-protection learning proberate
                     dummy sweep )],
    'set sweep' => [qw( age period )],
    'show'      => [qw( status arp version uptime log ip )],
);

my @Completion_Patterns = (
  [ qr/^set ip \S+ dead$/i,                 undef ],

  [ qr/^set ip \S+ pending$/i,              [ '<num>' ] ],
  [ qr/^set ip \S+ pending \S+$/i,          undef ],

  [ qr/^set ip \S+ alive$/i,                [ '<mac>', '(return)' ] ],
  [ qr/^set ip \S+ alive \S+$/i,            undef ],

  [ qr/^set pending$/i,                     [ '<num>' ] ],
  [ qr/^set pending \S+$/i,                 undef ],

  [ qr/^set max-rate$/i,                    [ '<rate>' ] ],
  [ qr/^set max-rate \S+$/i,                undef ],

  [ qr/^set queuedepth$/i,                  [ '<size>' ] ],
  [ qr/^set queuedepth \S+$/i,              undef ],

  [ qr/^set flood-protection$/i,            [ '<rate>' ] ],
  [ qr/^set flood-protection \S+$/i,        undef ],

  [ qr/^set proberate$/i,                   [ '<rate>' ] ],
  [ qr/^set proberate \S+$/i,               undef ],

  [ qr/^set learning$/i,                    [ '<secs>' ] ],
  [ qr/^set learning \S+$/i,                undef ],

  [ qr/^set sweep age$/i,                   [ '<secs>' ] ],
  [ qr/^set sweep age \S+$/i,               undef ],

  [ qr/^set sweep period$/i,                [ '<secs>' ] ],
  [ qr/^set sweep period \S+$/i,            undef ],

  [ qr/^set dummy \S+$/i,                   undef ],

  [ qr/^show log$/i,                        [ qw( <count> (return) ) ] ],

  [ qr/^ping$/i,                            [ qw( <count> (return) ) ] ],
  [ qr/^ping \S+$/i,                        [ qw( <delay> (return) ) ] ],
  [ qr/^ping \S+ \S+$/i,                    undef ], 
);

sub rl_completion {
    my ($text, $line, $start) = @_;

    my $so_far = substr($line, 0, $start);
    $so_far =~ s/\s+/ /g;
    $so_far =~ s/(?:^ )|(?: $)//g;

    if (my $list = $Completions{$so_far}) {
        if (@$list) {
            return @$list;
        }
        else {
            print "\n\t(return)\n";
            $TERM->on_new_line(); return;
        }
    }
    for my $entry (@Completion_Patterns) {
        my ($pat, $list) = @$entry;
        if ($so_far =~ /$pat/) {
            if ($list) {
                print "\n\t", join(' | ', @$list), "\n";
                $TERM->on_new_line(); return;
            }
            else {
                print "\n\t(return)\n";
                $TERM->on_new_line(); return;
            }
        }
    }

    given ($so_far) {
        when (/^(?:un)?sponge$/) {
            return ('all', list_ip_completion($text, $line, $start));
        }
        when (/^clear ip$/) {
            return ('all', list_ip_completion($text, $line, $start));
        }
        when (/^clear arp$/) {
            return list_ip_completion($text, $line, $start);
        }
        when ('set ip') {
            return ('all', list_ip_completion($text, $line, $start));
        }
        when (/^set ip \S+$/) {
            return qw( pending alive dead mac );
        }
        when ('show ip') {
            return ('all', 'alive', 'dead', 'pending', 'none',
                    list_ip_completion($text, $line, $start));
        }
        when ('show arp') {
            return ('all', list_ip_completion($text, $line, $start));
        }
    }
    return;
}

sub do_signal {
    die("\n** $_[0] signal -- exiting\n");
}

sub init_readline {
    my $args = shift;
    my $term = new Term::ReadLine $0;

    if (-f $HISTFILE) {
    }

    my $attribs = $term->Attribs;
        #$attribs->{attempted_completion_function} = \&rl_completion;
        $attribs->{completion_function} = \&rl_completion;

    $term->set_key('?', 'possible-completions'); # Behave as a Brocade :-)
    #$term->clear_signals();
    $term->StifleHistory($MAX_HISTORY);

    my $in     = $term->IN  || \*STDIN;
    my $out    = $term->OUT || \*STDOUT;
    select $out;
    $| = 1;

    my $prompt = '';
    if ($INTERACTIVE) {
        $prompt = "$0> ";
        $::SIG{INT} = 'IGNORE';
    }

    return ($term, $prompt, $in, $out);
}

##############################################################################

Main();

__END__

=head1 NAME

xxx - do xxx

=head1 SYNOPSIS

 xxx [--verbose|--quiet] infile

=head1 DESCRIPTION

=head1 OPTIONS

=over

=item X<--verbose>X<--quiet>B<--verbose> | B<--quiet>

By default, only a short summary of the progress is printed to STDOUT.
The C<--verbose> flag causes the program to be a little more talkative,
the C<--quiet> flag suppresses all non-error output to STDOUT.

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<perl(1)|perl>.

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011.

=cut

