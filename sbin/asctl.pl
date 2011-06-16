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
use M6::ARP::Log qw( :standard :macros );
use Time::HiRes qw( time sleep );
use M6::ARP::Util qw( :all );
use M6::ReadLine qw( :all );
use NetAddr::IP;
use Term::ReadLine;
use M6::ARP::Const qw( :all );

my $SPONGE_VAR      = '@SPONGE_VAR@';
my $CONN            = undef;
my $STATUS          = {};

my $DFL_PROBE_DELAY = 0.1;
my $MIN_PROBE_DELAY = 0.001;
my $DFL_PROBE_RATE  = 1/$DFL_PROBE_DELAY;
my $MAX_PROBE_RATE  = 1/$MIN_PROBE_DELAY;

# Values set on the Command Line.
my $opt_verbose   = 0;
my $opt_debug     = 0;
my $opt_test      = 0;
my $rundir        = $SPONGE_VAR;
my $INTERACTIVE   = 1;
my $MAX_HISTORY   = 1000;
my $HISTFILE      = "$::ENV{HOME}/.$0_history";

my ($REVISION) = '$Revision$' =~ /Revision: (\S+) \$/;
my $VERSION    = '@RELEASE@'."($REVISION)";
my $app_header = "\nThis is $0, v$VERSION\n\n"
               . "See \"perldoc $0\" for more information.\n"
               ;

END {
    $CONN && $CONN->close;
}

sub verbose(@) { print @_ if $opt_verbose; }
sub DEBUG(@)   { print_error(@_) if $opt_debug; }

my @IP_STATES = qw(all alive dead pending none);
my %Syntax = (
    'quit' => { '?'       => 'Disconnect and quit.', },
    'help' => { '?'       => 'Show command summary.', },
    'ping $count? $delay?' => {
        '?'       => '"ping" the daemon, display response RTT.',
        '$count'  => { type=>'int',   min=>1,    default=>1 },
        '$delay'  => { type=>'float', min=>0.01, default=>1 }, },
    'clear ip $ip'   => {
        '?'       => 'Clear state table for given IP(s).',
        '$ip'     => { type=>'ip-any'    } },
    'clear arp $ip'  => {
        '?'       => 'Clear ARP table for given IP(s).',
        '$ip'     => { type=>'ip-range'  } },
    'probe $ip'   => {
        '?'       => 'Send ARP requests for given IP(s).',
        '$ip'     => { type=>'ip-range'  } },
    'show ip $ip?'   => {
        '?'       => 'Show state table for given IP(s).',
        '$ip'     => { type=>'ip-filter' } },
    'show arp $ip?'  => {
        '?'       => 'Show ARP table for given IP(s).',
        '$ip'     => { type=>'ip-any'    } },
    'show parameters' => { '?' => 'Show daemon parameters.'   },
    'show status'  => { '?' => 'Show daemon status.'   },
    'show version' => { '?' => 'Show daemon version.'  },
    'show uptime'  => { '?' => 'Show daemon uptime.'   },
    'show log $nlines?' => {
        '?'       => 'Show daemon log (most recent <nlines>).',
        '$nlines' => { type=>'int', min=>1 }, },
    'sponge $ip' => {
        '?'       => 'Sponge given IP(s); see also "set ip dead".',
        '$ip'     => { type=>'ip-range' } },
    'unsponge $ip' => {
        '?'       => 'Unsponge given IP(s); see also "set ip alive".',
        '$ip'     => { type=>'ip-range' } },
    'inform $dst_ip about $src_ip' => {
        '?'       => 'Force <dst_ip> to update its ARP entry for <src_ip>.',
        '$dst_ip' => { type=>'ip-address' },
        '$src_ip' => { type=>'ip-address' } },
    'set arp_update_flags $flags' => {
        '?'       => 'Set the methods (comma-separated list) by which the'
                    .' sponge is to update its neighbor caches',
        '$flags'  => { type=>'arp-update-flags' },
        },
    'set ip $ip dead'   => {
        '?'       => 'Sponge given IP(s).',
        '$ip'      => { type=>'ip-range'  } },
    'set ip $ip pending $pending?' => {
        '?'        => 'Set given IP(s) to pending state'
                    . ' <pending> (default 0).',
        '$ip'      => { type=>'ip-range'  },
        '$pending' => { type=>'int', min=>0, default=>0 }, },
    'set ip $ip mac $mac' => {
        '?'        => 'Statically store <ip> -> <mac> in the ARP table.',
        '$ip'      => { type=>'ip-range'    },
        '$mac'     => { type=>'mac-address' }, },
    'set ip $ip alive $mac?' => {
        '?'        => 'Unsponge given IP(s) (associate them with <mac>).',
        '$ip'      => { type=>'ip-range'    },
        '$mac'     => { type=>'mac-address' }, },
    'set max_pending $num' => {
        '?'        => 'Set max. number of "pending" probes before'
                      .' sponging an IP',
        '$num'     => { type=>'int', min=>1 }, },
    'set log_level $level' => {
        '?'        => 'Set logging threshold',
        '$level'   => { type=>'log-level', min=>1 }, },
    'set queuedepth $num' => {
        '?'        => 'Max. ARP queue size per IP address.',
        '$num'     => { type=>'int', min=>1 }, },
    'set max_rate $rate' => {
        '?'        => 'Set rate parameters.',
        '$rate'    => { type=>'float', min=>0.001 }, },
    'set flood_protection $rate' => {
        '?'        => 'Set rate parameters.',
        '$rate'    => { type=>'float', min=>0.001 }, },
    'set proberate $rate' => {
        '?'        => 'Set rate parameters.',
        '$rate'    => { type=>'float', min=>0.001 }, },
    'set learning $secs' => {
        '?'        => 'Switch to/out of learning mode.',
        '$secs'    => { type=>'int', min=>0 }, },
    'set dummy $bool' => {
        '?'        => 'Enable/disable DUMMY mode.',
        '$bool'    => { type=>'bool' }, },
    'set sweep_age $secs' => {
        '?'        => 'Set sweep/probe parameters.',
        '$secs'    => { type=>'int', min=>1 }, },
    'set sweep_period $secs' => {
        '?'        => 'Set sweep/probe parameters.',
        '$secs'    => { type=>'int', min=>1 }, },
);

sub Main {
    my ($sockname, $args) = initialise();

    compile_syntax(\%Syntax) or die("** cannot continue\n");

    verbose "connecting to arpsponge on $sockname\n";
    if (!$opt_test) {
        $CONN = M6::ARP::Control::Client->create_client($sockname)
                    or die "$sockname: ".M6::ARP::Control::Client->error."\n";
    }
    ($STATUS) = get_status($CONN, {raw=>0, format=>1});
    verbose "$$STATUS{id}, v$$STATUS{version} (pid #$$STATUS{pid})\n";
    my $err = 0;

    if (@$args) {
        my $command = do_command(join(' ', @$args), $CONN);
    }
    else {
        $M6::ReadLine::IP_NETWORK =
            NetAddr::IP->new("$$STATUS{network}/$$STATUS{prefixlen}");

        init_readline() if $INTERACTIVE;

        while (1) {
            my $input = $TERM ? $TERM->readline($PROMPT) : <>;
            last if !defined $input;

            next if $input =~ /^\s*(?:#.*)?$/;
            my $command = do_command($input, $CONN);

            if (!$CONN) {
                if ($command eq 'quit') {
                    verbose "connection closed\n";
                    last;
                }
            }
            elsif (!defined $CONN->send_command("ping")) {
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
    $CONN && $CONN->close;
    exit $err;
}

END {
    exit_readline();
}

sub do_command {
    my ($line, $conn) = @_;
    my %args = (-conn => $conn);
    my @parsed = ();

    if (parse_line($line, \@parsed, \%args)) {
        my $func_name = "do @parsed";
        $func_name =~ s/[\s-]+/_/g;
        DEBUG "func_name: $func_name";
        my $func; eval '$func = \&'.$func_name;
        if (!defined $func) {
            return print_error(qq{@parsed: NOT IMPLEMENTED});
        }
        else {
            $func->($conn, \@parsed, \%args);
            return "@parsed";
        }
    }
    return "@parsed";
}

sub expand_ip_range {
    my ($arg_str, $name, $silent) = @_;

    $arg_str =~ s/\s*(?:-|\.\.|to)\s*/-/g;
    $arg_str =~ s/\s*,\s*/ /g;

    my @args = split(' ', $arg_str);

    DEBUG "range: <$arg_str>:", map {" <$_>"} @args;

    my @list;
    for my $ip_s (@args) {
        my ($lo_s, $hi_s) = split(/-/, $ip_s, 2);

        check_ip_address_arg({name=>$name}, $lo_s, $silent) or return;
        my $lo = ip2int($lo_s);
        DEBUG "lo: <$lo_s> $lo";
        my $hi;
        if ($hi_s) {
            check_ip_address_arg({name=>$name}, $hi_s, $silent) or return;
            $hi = ip2int($hi_s);
            DEBUG "hi: <$hi_s> $hi";
        }
        else { $hi = $lo; }

        if ($hi < $lo) {
            $silent or print_error(
                        qq{$name: "$lo_s-$hi_s" is not a valid IP range});
            return;
        }
        push @list, [ $lo, $hi, $lo_s, $hi_s ];
    }
    return \@list;
}

sub check_ip_range_arg {
    my ($spec, $arg, $silent) = @_;
    DEBUG sprintf("check_ip_range_arg: <%s> <%d>", $arg, $silent ? $silent : 0);
    return expand_ip_range($arg, $spec->{name}, $silent) ? $arg : undef;
}

sub complete_ip_range {
    my $partial = shift @_;
    my @words   = split(/,/, $partial);
    if ($partial =~ /,$/) {
        $partial = '';
    }
    else {
        $partial = @words ? pop @words : '';
    }
    my $prefix  = join('', map { "$_," } @words);
    if ($partial =~ /^(.+-)(.*)$/) {
        $prefix .= $1;
        $partial = $2;
    }
    DEBUG "\ncomplete_ip_range: partial:<$partial>; prefix:<$prefix>";
    return map { "$prefix$_" } complete_ip_address_arg($partial);
}

sub check_ip_filter_arg {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_ip_filter_arg: <$arg>";
    if (my $s = match_prefix($arg, \@IP_STATES, $silent)) {
        return $s;
    }
    elsif (defined last_error()) {
        return;
    }
    return check_ip_range_arg(@_);
}

sub complete_ip_filter {
    my $partial = shift;
    DEBUG "check_ip_filter: <$partial>";
    return (@IP_STATES, complete_ip_range($partial));
}

sub check_ip_any_arg {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_ip_filter_arg: <$arg>";
    if ($arg =~ /^all$/i) {
        return $arg;
    }
    return check_ip_range_arg(@_);
}

sub complete_ip_any {
    my $partial = shift;
    DEBUG "check_ip_filter: <$partial>";
    return (qw( all ), complete_ip_range($partial));
}

sub check_log_level {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_log_level $arg";
    if (defined $arg && length($arg)) {
        my $err;
        my $level = is_valid_log_level($arg, -err => \$err);
        if (!defined $level) {
            $silent or print_error($err);
            return;
        }
        return $level;
    }
}

sub complete_log_level {
    return map { log_level_to_string($_) } (LOG_EMERG .. LOG_DEBUG);
}

sub check_arp_update_flags {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_arp_update_flags: $arg";
    if (defined $arg && length($arg)) {
        my $err;
        my $flags = parse_update_flags($arg, -err => \$err);
        if (!defined $flags) {
            $silent or print_error($err);
            return;
        }
        return $flags;
    }
}

sub complete_arp_update_flags {
    my $partial = shift @_;
    my @words   = split(/,/, $partial);
    if ($partial =~ /,$/) {
        $partial = '';
    }
    else {
        $partial = @words ? pop @words : '';
    }
    my $prefix  = join('', map { "$_," } @words);
    DEBUG "\ncomplete_arp_update_flags partial:<$partial>; prefix:<$prefix>";
    
    my @names;
    for my $name (keys %M6::ARP::Const::STR_TO_UPDATE_FLAG) {
        if (substr($name, 0, length($partial)) eq $partial) {
            push @names, $name;
        }
        if (substr("!$name", 0, length($partial)) eq $partial) {
            push @names, $name;
        }
    }
    if (@names==1) {
        push @names, "$names[0],";
    }
    return map { "$prefix$_" } @names;
}


sub check_send_command {
    my $conn = shift;
    my $command = join(' ', @_);

    return if !$conn;

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
    my $arg_str = shift;
    my $code    = shift;
    my $delay   = shift;

    my @args = split(' ', $arg_str);

    my @reply;
    my $list = expand_ip_range($arg_str, 'ip') or return;

    for my $elt (@$list) {
        my ($lo, $hi, $lo_s, $hi_s) = @$elt;
        for (my $ip = $lo; $ip <= $hi; $ip++) {
            my $sub = $code->(ip2hex(int2ip($ip)));
            return if !defined $sub;
            push @reply, $sub if length($sub);
            sleep($delay) if defined $delay && $delay > 0;
        }
    }
    return join("\n", @reply);
}

sub do_quit {
    my ($conn, $parsed, $args) = @_;
    GetOptionsFromArray($$args{-options}) or return;
    my $reply = check_send_command($conn, 'quit') or return;
    print_output($reply);
}

sub do_help_pod {
    my $maxlen = 72;
    my $out = qq{=head1 COMMAND SUMMARY\n\n}
            . qq{=over\n}
            ;

    my %help;
    for my $cmd (keys %Syntax) {
        my $text = $cmd;
        $text =~ s/(^|\s)([a-z][\w\-]*)/$1B<$2>/g;
        $text =~ s/\$(\S+)\?/[I<$1>]/g;
        $text =~ s/\$(\S+)/I<$1>/g;
        $text =~ s/(\S+)\|(\S+)/{B<$1>|B<$1>}/g;
        $help{$text} = $Syntax{$cmd}->{'?'};
    }

    for my $cmd (sort keys %help) {
        $out .= qq{\n=item $cmd\n\n}
              . fmt_text('', $help{$cmd}, $maxlen, 0)
              ;
    }
    $out .= "\n=back\n";
    print_output($out);
}

sub do_help {
    my ($conn, $parsed, $args) = @_;
    my $pod = 0;
    GetOptionsFromArray($$args{-options}, 'pod' => \$pod) or return;

    if ($pod) {
        do_help_pod();
        return;
    }

    my ($rows, $cols) = $TERM ? $TERM->get_screen_size() : (25, 80);
    my $maxlen = $cols - 4;
    my $out = "=" x $maxlen;
    my $head = uc " $0 command summary ";
    substr($out, (length($out)-length($head))/2, length($head)) = $head;
    $out .= "\n";

    my %help;
    my $indent = 0;
    for my $cmd (keys %Syntax) {
        my $text = $cmd;
        $text =~ s/\$(\S+)\?/[<$1>]/g;
        $text =~ s/\$(\S+)/<$1>/g;
        $text =~ s/(\S+\|\S+)/\($1\)/g;
        $help{$text} = $Syntax{$cmd}->{'?'};
        $indent = length($text) if length($text) > $indent;
    }
    $indent += 2;

    for my $cmd (sort keys %help) {
        $out .= fmt_text($cmd, $help{$cmd}, $maxlen, $indent);
    }
    print_output($out);
}

sub fmt_text {
    my ($prefix, $text, $maxlen, $indent) = @_;
    $prefix .= ' ' x ($indent - length($prefix));
    my $indent_text = ' ' x $indent;
    my @words = split(' ', $text);
    my $pos = length($prefix);
    my $out = $prefix;
    for my $w (@words) {
        if ($pos + length($w) + 1 > $maxlen) {
            $out .= "\n$indent_text";
            $pos = $indent;
        }
        if ($pos>$indent) { $out .= ' '; $pos++ }
        $out .= $w;
        $pos += length($w);
    }
    $out .= "\n";
}

sub do_ping {
    my ($conn, $parsed, $args) = @_;

    GetOptionsFromArray($$args{-options}) or return;

    my $count = $args->{'count'};
    my $delay = $args->{'delay'};

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

sub do_inform_about {
    my ($conn, $parsed, $args) = @_;

    GetOptionsFromArray($args->{-options}) or return;
    my ($src, $dst) = (ip2hex($$args{'src_ip'}), ip2hex($$args{'dst_ip'}));
    my $reply = check_send_command($conn, 'inform', $dst, $src) or return;
    my ($opts, $output, $tag) = parse_server_reply($reply, {format=>0});
    print_output($output);
}

###############################################################################
# SHOW commands
###############################################################################

# cmd: show status
sub do_show_status {
    return do_status(@_);
}

# cmd: show status
sub do_show_parameters {
    return do_param(@_);
}

# cmd: show log
sub do_show_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    GetOptionsFromArray($args->{-options},
                'raw!'     => \(my $raw = 0),
                'format!'  => \$format,
                'reverse!' => \(my $reverse = 1),
                'nf'       => sub { $format = 0 },
            ) or return;

    $format &&= !$raw;

    my @args = defined $args->{'nlines'} ? ($args->{'nlines'}) : ();
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
    GetOptionsFromArray($args->{-options});
    print_output($STATUS->{'version'}."\n");
}

# cmd: show uptime
sub do_show_uptime {
    my ($conn, $parsed, $args) = @_;
    GetOptionsFromArray($args->{-options});

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

    my $filter_state;
    my $ip = $args->{'ip'};

    if (defined $ip) {
        if ($ip eq 'all') {
            delete $args->{'ip'};
        }
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
    my $ip = $args->{'ip'};

    if (defined $ip) {
        if ($ip eq 'all') {
            delete $args->{'ip'};
        }
        elsif (grep { lc $ip eq $_ } @IP_STATES) {
            $filter_state = lc $ip;
            delete $args->{'ip'};
        }
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
            next if defined $filter_state && lc $$info{state} ne $filter_state;
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
#       $args       ref to hash with parameters
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

    GetOptionsFromArray($args->{-options},
            'header!'  => \$opts{header},
            'raw!'     => \$opts{raw},
            'format!'  => \$opts{format},
            'long!'    => sub { $opts{summary} = !$_[1] },
            'summary!' => sub { $opts{summary} = $_[1] },
            'nf'       => sub { $opts{format}  = 0  },
            'nh'       => sub { $opts{header}  = 0  },
        ) or return;

    $opts{format} &&= !$opts{raw};

    my $reply = '';
    if ($args->{'ip'}) {
        my $arg_count = 0;
        $reply = expand_ip_run($args->{'ip'}, 
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
        $reply =~ s/\b(tpa|spa|network|ip)=([\da-f]+)\b/"$1=".hex2ip($2)/gme;
        $reply =~ s/\b(tha|sha|mac)=([\da-f]+)\b/"$1=".hex2mac($2)/gme;
        $reply =~ s/\b(arp_update_flags)=(\d+)\b
                   /"$1=".join(q{,}, update_flags_to_str($2))
                   /gxme;
        $reply =~ s/\b(log_level)=(\d+)\b/"$1=".log_level_to_string($2)/gme;
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

# cmd: clear ip
sub do_clear_ip {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    GetOptionsFromArray($args->{-options}) or return;

    if ($ip eq 'all') {
        return check_send_command($conn, 'clear_ip_all') or return;
    }

    expand_ip_run($ip,
                  sub {
                      return check_send_command($conn, "clear_ip $_[0]");
                  }
                );
    return;
}

# cmd: clear arp
sub do_clear_arp {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    GetOptionsFromArray($args->{-options}) or return;

    expand_ip_run($ip, 
                  sub {
                      return check_send_command($conn, "clear_arp $_[0]");
                  }
                );
    return;
}

###############################################################################
# PROBE commands
###############################################################################

# cmd: probe
sub do_probe {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};
    my %opts;

    GetOptionsFromArray($args->{-options},
            'delay=f'  => \$opts{delay},
            'rate=f'   => \$opts{raw},
        ) or return;

    my $delay = $opts{'delay'};
    my $rate  = $opts{'rate'};
    if (defined $delay) {
        if (defined $rate) {
            print_error("** warning: --rate ignored in favour of --delay");
        }
        if ($delay <= 0) {
            print_error("** warning: delay of $delay ignored;",
                        " using $DFL_PROBE_DELAY");
            $delay = $DFL_PROBE_DELAY;
        }
    }
    elsif (defined $rate) {
        if ($rate > $MAX_PROBE_RATE) {
            my $dfl_rate = sprintf("%0.2f", $DFL_PROBE_RATE);
            print_error("** warning: rate of $rate ignored;",
                        " using $dfl_rate");
            $delay = $DFL_PROBE_DELAY;
        }
    }

    my $start = time;
    my $n = 0;
    expand_ip_run($ip, 
        sub {
            my $r = check_send_command($conn, "probe $_[0]") or return;
            my ($o, $out, $t) = parse_server_reply($r, {format=>0});
            print_output($out);
            $n++;
        },
        $delay,
    );
    my $elapsed = time - $start;

    print_output(sprintf("%d probe(s) sent in %0.2fs", $n, $elapsed));
    return;
}

###############################################################################
# SET commands
###############################################################################

sub do_set_generic {
    my %opts      = @_;
    my $conn      = $opts{-conn};
    my $arg       = $opts{-val};
    my $name      = $opts{-name};
    my $type      = $opts{-type};
    my $unit      = $opts{-unit}    // '';
    my $command   = $opts{-command} // "set_$name";

    $command =~ s/[-\s]+/_/g;

    GetOptionsFromArray($opts{-options}) or return;

    my $reply = check_send_command($conn, $command, $arg) or return;

    DEBUG "do_set_generic: reply=<$reply>";

    my ($opts, $output, $tag) = parse_server_reply($reply);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    given ($type) {
        when ('log-level') {
            $old = log_level_to_string($old);
            $new = log_level_to_string($new);
        }
        when ('arp-update-flags') {
            $old = '('.join(',', update_flags_to_str($old)).')';
            $new = '('.join(',', update_flags_to_str($new)).')';
        }
        when ('boolean') {
            $old = $old ? 'yes' : 'no';
            $new = $new ? 'yes' : 'no';
            $type = '%s';
        }
        when ('int') {
            $type = '%d';
        }
        when ('float') {
            $fmt = '%0.2f';
        }
    }
    print_output(sprintf("%s changed from $fmt to $fmt%s",
                         $name, $old, $new, $unit));
}

# cmd: set queuedepth
sub do_set_queuedepth {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'queuedepth',
                   -val     => $args->{'num'},
                   -options => $args->{-options},
                   -type    => 'int');
}

# cmd: set arp-update-flags
sub do_set_arp_update_flags {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'arp_update_flags',
                   -val     => $args->{'flags'},
                   -options => $args->{-options},
                   -type    => 'arp-update-flags');
}

# cmd: set log-level
sub do_set_log_level {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'log_level',
                   -val     => $args->{'level'},
                   -options => $args->{-options},
                   -type    => 'log-level');
}

# cmd: set max-pending
sub do_set_max_pending {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max-pending',
                   -val     => $args->{'num'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'integer');
}

# cmd: set max-rate
sub do_set_max_rate {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max-rate',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/min',
                   -type    => 'float');
}

# cmd: set learning
sub do_set_learning {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'learning',
                   -val     => $args->{'secs'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'int');
}

# cmd: set flood-protection
sub do_set_flood_protection {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'flood-protection',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/sec',
                   -type    => 'float');
}

# cmd: set proberate
sub do_set_proberate {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'proberate',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/sec',
                   -type    => 'float');
}

# cmd: set dummy
sub do_set_dummy {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'dummy',
                   -val     => $args->{'bool'},
                   -options => $args->{-options},
                   -type    => 'bool');
}
 
# cmd: set sweep period
sub do_set_sweep_period {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'sweep period',
                   -command => 'set_sweep_sec',
                   -val     => $args->{'secs'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'int');
}

# cmd: set sweep age
sub do_set_sweep_age {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'sweep age',
                   -val     => $args->{'secs'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'int');
}

sub do_set_ip_generic {
    my %opts      = @_;
    my $conn      = $opts{-conn};
    my $arg       = $opts{-val};
    my $ip        = ip2hex($opts{-ip});
    my $name      = $opts{-name} // 'arg';
    my $type      = $opts{-type} // 'string';
    my $unit      = $opts{-unit} // '';
    my $command   = $opts{-command} // "set_ip_$name";

    DEBUG "do_set_ip_generic\n"
        . "  command = " . $command . "\n"
        . "  ip      = " . $ip . "\n"
        . "  name    = " . ($arg // '(none)') . "\n"
        ;

    $command =~ s/[-\s]+/_/g;

    GetOptionsFromArray($opts{-options}) or return;

    my @command_args = ($command, $ip);
    push(@command_args, $arg) if defined $arg;
    my $reply = check_send_command($conn, @command_args) or return;

    my ($opts, $output, $tag) = parse_server_reply($reply);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    given ($type) {
        when ('boolean') {
            $old = $old ? 'yes' : 'no';
            $new = $new ? 'yes' : 'no';
            $type = '%s';
        }
        when ('int') {
            $type = '%d';
        }
        when ('float') {
            $fmt = '%0.2f';
        }
    }
    print_output(sprintf("%s: %s changed from $fmt to $fmt%s",
                         $output->[0]->{ip},
                         $name, $old, $new, $unit));
}

# cmd: set ip pending
sub do_set_ip_pending {
    my ($conn, $parsed, $args) = @_;

    DEBUG "set ip pending";
    do_set_ip_generic(-conn    => $conn,
                      -command => 'set_pending',
                      -name    => 'state',
                      -val     => $args->{'pending'} // 0,
                      -ip      => $args->{'ip'},
                      -options => $args->{-options},
                      -type    => 'string');
}

# cmd: set ip dead
sub do_set_ip_dead {
    my ($conn, $parsed, $args) = @_;

    expand_ip_run($args->{'ip'}, 
        sub {
            do_set_ip_generic(-conn    => $conn,
                      -command => 'set_dead',
                      -name    => 'state',
                      -ip      => hex2ip($_[0]),
                      -options => $args->{-options});
        }
    );
}

# cmd: sponge
sub do_sponge { &do_set_ip_dead }

# cmd: unsponge
sub do_unsponge { &do_set_ip_alive }

# cmd: set ip alive
sub do_set_ip_alive {
    my ($conn, $parsed, $args) = @_;

    DEBUG "set ip alive $$args{ip} mac="
         .($args->{'mac'}?$args->{'mac'} : 'none');

    my $mac = $args->{'mac'} ? mac2hex($args->{'mac'}) : undef;

    expand_ip_run($args->{'ip'}, 
        sub {
            do_set_ip_generic(
                -conn    => $conn,
                -command => 'set_alive',
                -name    => 'state',
                -val     => $mac,
                -ip      => hex2ip($_[0]),
                -options => $args->{-options});
        }
    );
}

# cmd: set ip mac
#
#   Alias for "set ip alive" with a mandatory MAC argument.
sub do_set_ip_mac {
    my ($conn, $parsed, $args) = @_;

    print "set ip $$args{ip} mac $$args{mac}\n";
    return do_set_ip_alive($conn, $parsed, $args);
}

###############################################################################
# STATUS command
###############################################################################

# cmd: status
sub do_status {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    my %opts = ( raw => 0, format => 1 );

    GetOptionsFromArray($args->{-options},
            'raw!'     => \$opts{raw},
            'format!'  => \$opts{format},
            'nf'       => sub { $opts{format} = 0 },
        ) or return;

    $opts{format} &&= !$opts{raw};

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
        sprintf("$tag%s (in %d secs) [%d]\n", 'next sweep:',
                format_time($$info{next_sweep}),
                $$info{next_sweep}-$$info{date},
                $$info{next_sweep}),
    );
}

sub do_param {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    my %opts = ( raw => 0, format => 1 );

    GetOptionsFromArray($args->{-options},
            'raw!'     => \$opts{raw},
            'format!'  => \$opts{format},
            'nf'       => sub { $opts{format} = 0 },
        ) or return;

    $opts{format} &&= !$opts{raw};

    my $reply = check_send_command($conn, 'get_param') or return;

    my ($opts, $output, $tag) = parse_server_reply($reply, \%opts);

    if (!$opts->{format}) {
        return print_output($output);
    }
    my $info = $output->[0];
    print_output(
        sprintf("$tag= %d\n", 'queue_depth', $$info{queue_depth}),
        sprintf("$tag= %0.2f q/min\n", 'max_rate', $$info{max_rate}),
        sprintf("$tag= %0.2f q/sec\n", 'flood_protection',
                $$info{flood_protection}),
        sprintf("$tag= %d\n", 'max_pending', $$info{max_pending}),
        sprintf("$tag= %d secs\n", 'sweep_period', $$info{sweep_period}),
        sprintf("$tag= %d secs\n", 'sweep_age', $$info{sweep_age}),
        sprintf("$tag= %d pkts/sec\n", 'proberate', $$info{proberate}),
        sprintf("$tag= %s\n", 'learning', 
                    $$info{learning}?"yes ($$info{learning} secs)":'no'),
        sprintf("$tag= %s\n", 'dummy', $$info{dummy}?'yes':'no'),
        sprintf("$tag= %s\n", 'arp_update_flags', $$info{arp_update_flags}),
        sprintf("$tag= %s\n", 'log_level', $$info{log_level}),
    );
}

# ($output, $tag_fmt) = get_status($conn, \%opts);
#
#   Helper function for status. Similar to the ip/arp thing.
#
sub get_status {
    my ($conn, $opts) = @_;

    my $reply;
    
    if ($conn) {
        $reply = check_send_command($conn, 'get_status') or return;
    }
    else {
        $reply = qq{id=arpsponge-test\n}
               . qq{version=0.0\n}
               . qq{pid=0\n}
               . qq{network=}.ip2hex('192.168.1.0').qq{\n}
               . qq{prefixlen=24\n}
               ;
    }

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
    my $opt_c = undef;

    GetOptions(
        'command|c=s' => sub {
                            $opt_c = $_[1];
                            die('!FINISH');
                         },
        'verbose+'    => \$opt_verbose,
        'debug!'      => \$opt_debug,
        'help|?'      =>
            sub { pod2usage(-msg => $app_header, -exitval=>0, -verbose=>0) },
        'interface=s' => \$interface,
        'rundir=s'    => \$rundir,
        'socket=s'    => \$sockname,
        'test!'       => \$opt_test,
        'manual'      => sub { pod2usage(-exitval=>0, -verbose=>2) },
    ) or pod2usage(-exitval=>2);

    if ($opt_c) {
        unshift @ARGV, $opt_c;
    }

    $opt_verbose += $opt_debug;

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

    $M6::ReadLine::TYPES{'ip-range'} = {
            'verify'   => \&check_ip_range_arg,
            'complete' => \&complete_ip_range,
        };
    $M6::ReadLine::TYPES{'ip-filter'} = {
            'verify'   => \&check_ip_filter_arg,
            'complete' => \&complete_ip_filter,
        };
    $M6::ReadLine::TYPES{'ip-any'} = {
            'verify'   => \&check_ip_any_arg,
            'complete' => \&complete_ip_any,
        };
    $M6::ReadLine::TYPES{'arp-update-flags'} = {
            'verify'   => \&check_arp_update_flags,
            'complete' => \&complete_arp_update_flags,
        };
    $M6::ReadLine::TYPES{'log-level'} = {
            'verify'   => \&check_log_level,
            'complete' => \&complete_log_level,
        };

    $INTERACTIVE = -t STDIN && -t STDOUT && !@ARGV;
    $opt_verbose += $INTERACTIVE;

    return ($sockname, [@ARGV]);
}

sub do_signal {
    die("\n** $_[0] signal -- exiting\n");
}

##############################################################################

Main();

__END__

=head1 NAME

asctl - Arp Sponge ConTroL utility

=head1 SYNOPSIS

=over 6

=item B<asctl>

[B<--verbose>]
[B<--debug>]
[B<--test>]
[B<--rundir>=I<dir>]
[B<--interface>=I<ifname>]
[B<--socket>=I<sock>]
[[B<--command>] I<command> ...]

=back

=head1 DESCRIPTION

The C<asctl> program connects to a running L<arpsponge(8)|arpsponge>'s control
socket, and executes commands that either come from standard input, or from
the command line.

By default, the program connects to the first control socket it finds in
F<@SPONGE_VAR@> (see L<FILES|/FILES>), but see L<OPTIONS|/OPTIONS> below
for ways to override this.

=head1 OPTIONS

=over

=item B<--command> I<command> ...

Signals to the program that whatever follows the C<--command> option should be
considered as input to the program. This is useful if you want to specify
options to the program's commands. The following are sort of equivalent:

  asctl -c show status --no-format
  asctl -- show status --no-format
  asctl 'show status --no-format'

Note that you cannot specify C<--command> without at least one argument.

=item B<--debug>

Print debugging information to F<stderr> while executing.

=item B<--interface>=I<ifname>

Connect to the L<arpsponge> instance for interface I<ifname>.

=item B<--rundir>=I<dir>

Override the default top directory for the L<arpsponge> control files.
See also L<FILES|/FILES> below.

=item B<--socket>=I<sock>

Explicitly specify the path of the control socket to connect to. Mutually
exclusive with L<--interface|/--interface>.

=item B<--test>

Do not connect to any daemon or send any commands. This is really only
used during development to check command parsing, etc.

=item X<--verbose>B<--verbose>

The C<--verbose> flag causes the program to be a little more talkative.

=back

=head1 COMMANDS

In the list below, the following constructions are used:

    $ip        ::= valid IPv4 address
    $ip-range  ::= $ip[-$ip][,$ip-range]
    $ip-any    ::= {$ip-range|all}
    $ip-filter ::= {alive|dead|pending|none|$ip-any}

=over

=item B<clear arp> I<ip-range>

Clear ARP table for given IP(s)

=item B<clear ip> I<ip-range>

Clear state table for given IP(s)

=item B<help>

Show command summary

=item B<inform> I<dst_ip> B<about> I<src_ip>

Force I<dst_ip> to update its ARP entry for I<src_ip>. See also
"L<set arp_update_flags|/arp_update_flags>" below.

=item B<ping> [[I<count> [I<delay>]]

Send I<count> "ping" probes to the daemon, waiting I<delay>
seconds between probes, display response RTT per probe and
a summary at the end. Can be stopped by an interrupt signal
(C<Ctrl-C>).

=item B<probe> [B<--delay>=I<sec> | B<--rate>=I<rate>] I<ip-range> 

Send broadcast ARP queries (probes) for addresses in I<ip-range>.
By default, the request rate is 10 probes per second (delay is 0.1),
but this can be changed with the C<--delay> or C<--rate> options.

=item B<quit>

disconnect and quit

=item X<arp_update_flags>B<set> B<arp_update_flags> I<flag>[,I<flag>,...]

Set the methods (comma-separated list) by which the sponge is to update
its neighbor caches.

Assuming we want to update I<stanley> about I<livingston>, the possible
values for I<flag> are:

=over

=item C<reply>

Spoof an unsollicited ARP reply on behalf of I<livingston>, hoping that
I<stanley> will pick it up:

  SRC = my-MAC
  DST = stanley-MAC
  PKT = ARP livingston-IP IS AT livingston-MAC

=item C<request>

Spoof an ARP request for I<stanley> on behalf of I<livingston>. This should
update I<stanley>'s ARP cache as well, but will result in a response to
I<livingston>, where it will be treated as an unsollicited response (most
likely will be dropped):

  SRC = my-MAC
  DST = stanley-MAC
  PKT = ARP WHO HAS stanley-IP TELL livingston-IP @ livingston-MAC

=item C<gratuitous>

Spoof a gratuitous ARP, effectively sending a "unicast proxy gratuitous ARP
request":

  SRC = my-MAC
  DST = stanley-MAC
  PKT = ARP WHO HAS livingston-IP TELL livingston-IP @ livingston-MAC

This should result in no extra traffic, while hopefully still updating the ARP
cache at I<stanley>.

=item C<all>

All of the above.

=item C<none>

None of the above.

=back

It is possible to combine these flags and negate them, so the following are
equivalent:

  all
  !none
  gratuitous,reply,request

As are these:

  all,!request
  !none,!request
  gratuitous,reply

=item B<set dummy> I<bool>

Enable/disable DUMMY mode; I<bool> can be any of:
C<yes>, C<true>, C<on>, C<1>,
C<no>, C<false>, C<off>, C<0>.

=item B<set ip> I<ip-range> B<alive> [I<mac>]

Unsponge given IP(s) (associate them with I<mac>)

=item B<set ip> I<ip-range> B<dead>

Sponge given IP(s)

=item B<set ip> I<ip-range> B<mac> I<mac>

Statically store <ip> -> <mac> in the ARP table

=item B<set ip> I<ip-range> pending [I<pending>]

Set given IP(s) to pending state I<pending> (default 0)

=item B<set learning> I<secs>

Switch in to/out of learning mode

=item B<set log_level> I<level>

Set the level of logging for the daemon. Values are the same as
L<syslog(3)|syslog> levels. In decreasing importance:

=over

=item C<emerg>

=item C<alert>

Currently not used.

=item C<crit>

Log critical errors. These are typically fatal errors.

=item C<err>

Log errors.

=item C<warning>

Logs warnings of misplaced ARP requests (for the wrong IP range), possible ARP
spoofing, etc.

=item C<notice>

Default level. Logs sponge actions.

=item C<info>

Log the comings and goings of control clients.

=item C<debug>

Currently not used.

=back

When the C<log_level> is set to I<level>, all messages of level I<level> and
higher importance are logged, so C<notice> will log C<warning>, C<err>, etc.
but not C<info> or C<debug>.

=item B<set> {B<max-pending>|B<queuedepth>} I<num>

Set queue parameters

=item B<set> {B<max-rate>|B<flood-protection>|B<proberate>} I<rate>

Set rate parameters

=item B<set sweep> {B<age>|B<period>} I<secs>

Set sweep/probe parameters

=item B<show arp> [I<ip-any>]

Show ARP table for given IP(s)

=item B<show ip> [I<ip-filter>]

Show state table for given IP(s)

=item B<show log> [I<nlines>]

Show daemon log (most recent <nlines>)

=item B<show> {B<parameters>|B<status>|B<uptime>|B<version>}

Show general information

=item B<sponge> I<ip-range>

=item B<unsponge> I<ip-range>

Sponge/unsponge given IP(s); see also C<set ip alive> and C<set ip dead>.

=back

=cut

=head1 COMMAND OPTIONS

Most C<show> commands accept the following options:

=over

=item X<--raw>X<--noraw>B<--raw>, B<--noraw>

Don't translate timestamps, IP addresses or MAC addresses. Implies
C<--noformat>.

=item X<--format>B<--format>

=item X<--nf>X<--noformat>B<--nf>, B<--noformat>

=back

=head1 FILES

=over

=item F<@SPONGE_VAR@>

Default top-level directory location for per-interface control sockets:
the L<arpsponge> on interface I<ifname> will have its control socket at
F<@SPONGE_VAR@/>I<ifname>F</control>.

=back

=head1 SEE ALSO

L<arpsponge(8)|arpsponge>,
L<asctl(8)|asctl>,
L<tail(1)|tail>,
L<perl(1)|perl>.

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011.
