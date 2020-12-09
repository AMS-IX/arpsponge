#!@PERL@ -I../lib
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
#   Copyright 2011-2016 AMS-IX B.V.; All rights reserved.
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
use Getopt::Long    qw( GetOptions GetOptionsFromArray );
use POSIX           qw( strftime floor );
use Pod::Usage;
use IO::String;
use Time::HiRes     qw( time sleep );
use NetAddr::IP;
use Term::ReadLine;
use IO::File;
use Scalar::Util    qw( reftype );

use M6::ARP::Control::Client;
use M6::ARP::Event     qw( :standard );
use M6::ARP::Log       qw( :standard :macros );
use M6::ARP::Util      qw( :all );
use M6::ReadLine       qw( :all );
use M6::ARP::Const     qw( :all );
use M6::ARP::NetPacket qw( :vars );

my $SPONGE_VAR      = '@SPONGE_VAR@';
my $CONN            = undef;
my $ERR             = 0;
my $STATUS          = {};

my $DFL_PROBE_DELAY = 0.1;
my $MIN_PROBE_DELAY = 0.001;
my $DFL_PROBE_RATE  = 1/$DFL_PROBE_DELAY;
my $MAX_PROBE_RATE  = 1/$MIN_PROBE_DELAY;

# Values set on the Command Line.
my $opt_quiet     = 0;
my $opt_verbose   = 0;
my $opt_debug     = 0;
my $opt_test      = 0;
my $rundir        = $SPONGE_VAR;

my $INTERACTIVE   = 1;

my $VERSION    = '@RELEASE@';
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
    'load status $file' => {
        '?'        => 'Load IP/ARP state from dump file.',
        '$file'   => { type=>'filename' }, },
    'dump status $file?' => {
        '?'        => 'Either dump daemon status to <file>,'
                     .' or signal the daemon to dump to its'
                     .' "standard" location (user needs'
                     .' privileges to send signals to the'
                     .' daemon process).',
        '$file'   => { type=>'filename' }, },
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
        '$dst_ip' => { type=>'ip-filter' },
        '$src_ip' => { type=>'ip-filter' } },
    'set arp_update_flags $flags' => {
        '?'       => q{Set the methods (comma-separated list) by which the}
                    .q{ sponge is to update its neighbors' ARP caches},
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
    'set log_mask $mask' => {
        '?'       => q{Specify a comma-separated list of events that}
                    .q{ should be logged by the daemon (default: all).},
        '$mask'  => { type=>'log-mask', min=>1 }, },
    'set log_level $level' => {
        '?'        => 'Set logging threshold.',
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
        '$secs'    => { type=>'int', min=>0 }, },
    'set sweep_skip_alive $bool' => {
        '?'        => 'Enable/disable sweeping of ALIVE addresses.',
        '$bool'    => { type=>'bool' }, },
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

    my $exit = 0;
    if (@$args) {
        if ($opt_quiet) {
            open STDOUT, '>', '/dev/null';
        }
        do_command(join(' ', @$args), $CONN);
        $exit = $ERR != 0;
    }
    else {
        $M6::ReadLine::IP_NETWORK =
            NetAddr::IP->new("$$STATUS{network}/$$STATUS{prefixlen}");

        init_readline() if $INTERACTIVE;

        # Don't add stuff to history list automatically.
        $TERM->MinLine(undef) if $TERM;
        # Keep track of last command in the history, so
        # we avoid adding duplicates.
        my ($prev_command) = $TERM ? reverse $TERM->GetHistory : ();
        $prev_command = 'quit' if !defined $prev_command;
        while (1) {
            my $input = $TERM ? $TERM->readline($PROMPT) : <>;
            last if !defined $input;

            next if $input =~ /^\s*(?:#.*)?$/; # Skip empty lines and comments.
            my $command = do_command($input, $CONN);
            if ($input ne $prev_command) {
                # Only add input to history if it's not a duplicate.
                $TERM->AddHistory($input) if $TERM;
                $prev_command = $input;
            }
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
                    $exit++;
                    print_error("** connection closed unexpectedly");
                }
                last;
            }
        }
        if (!$INTERACTIVE) {
            $exit ||= ($ERR != 0);
        }
    }
    $CONN && $CONN->close;
    exit $exit;
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
            $ERR++;
            return print_error(qq{@parsed: NOT IMPLEMENTED});
        }
        else {
            $ERR++ if ! $func->($conn, \@parsed, \%args);
            return "@parsed";
        }
    }
    else {
        $ERR++;
    }
    return "@parsed";
}

#############################################################################
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

#############################################################################
sub expand_ip_filter {
    my %args     = (name => 'ip', @_);
    my $arg_str  = $args{'arg'};
    my $name     = $args{'name'};
    my $silent   = $args{'silent'};
    my $have_mac = $args{'have_mac'};

    DEBUG "filter <$arg_str>";
    if (grep { lc $arg_str eq $_ } @IP_STATES) {
        my $state_table = get_state_table($CONN);
        my $state = uc $arg_str;
        my @list;
        if ($state eq 'ALL') {
            @list = sort { $a cmp $b } keys %$state_table;
        }
        else {
            while (my ($k, $v) = each %$state_table) {
                push @list, $k if $v eq $state;
            }
        }
        if ($have_mac || ($state eq 'ALL' && $state ne 'DEAD')) {
            # Make sure the addresses all have valid MACs.
            my ($opts, $reply, $arp_table, $tag_fmt) =
                shared_show_arp_ip($CONN, 'get_arp', [], {});
            my %mac = map { ($_->{'hex_ip'}, $_->{'mac'}) } @$arp_table;
            @list = grep { exists $mac{$_} && $mac{$_} ne $ETH_ADDR_NONE }
                         @list;

        }
        return [ map { [ hex($_), hex($_), hex2ip($_), hex2ip($_) ] } @list ];
    }
    elsif (defined last_error()) {
        return;
    }
    return expand_ip_range($arg_str, $name, $silent);
}

#############################################################################
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

#############################################################################
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

#############################################################################
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

#############################################################################
sub check_log_level {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_log_level $arg";
    if (defined $arg && length($arg)) {
        my $level = is_valid_log_level($arg, -err => \(my $err));
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

#############################################################################
sub check_log_mask {
    my ($spec, $arg, $silent) = @_;
    DEBUG "check_log_mask $arg";
    if (defined $arg && length($arg)) {
        my $err;
        my $mask = parse_event_mask($arg, -err => \$err);
        if (!defined $mask) {
            $silent or print_error($err);
            return;
        }
        return $mask;
    }
}

sub complete_log_mask {
    my $partial = shift @_;
    my @words   = split(/,/, $partial);
    if ($partial =~ /,$/) {
        $partial = '';
    }
    else {
        $partial = @words ? pop @words : '';
    }
    my $prefix  = join('', map { "$_," } @words);
    DEBUG "\ncomplete_log_mask partial:<$partial>; prefix:<$prefix>";

    my @names;
    for my $name (event_names()) {
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

#############################################################################
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


#############################################################################
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

sub do_ip_run {
    my $list    = shift;
    my $code    = shift;
    my $delay   = shift;

    my @reply;

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

sub expand_ip_run {
    my $arg_str = shift;
    my $list    = expand_ip_range($arg_str, 'ip') or return;

    return do_ip_run($list, @_);
}

sub Wrap_GetOptionsFromArray {
    my ($arg, $retval, @spec) = @_;

    if (!defined $arg) {
        return $retval;
    }
    elsif (reftype $arg eq 'ARRAY') {
        return GetOptionsFromArray($arg, @spec) ? $retval : undef;
    }
    else {
        return $arg;
    }
}

sub do_quit {
    my ($conn, $parsed, $args) = @_;
    Wrap_GetOptionsFromArray($$args{-options}, {}) or return;
    my $reply = check_send_command($conn, 'quit') or return;
    return print_output($reply);
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
    return print_output($out);
}

sub do_help {
    my ($conn, $parsed, $args) = @_;
    my $pod = 0;
    Wrap_GetOptionsFromArray($$args{-options}, {}, 'pod' => \$pod) or return;

    if ($pod) {
        return do_help_pod();
    }

    my $maxlen = term_width() - 4;
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
    return print_output($out);
}

sub do_ping {
    my ($conn, $parsed, $args) = @_;

    Wrap_GetOptionsFromArray($$args{-options}, {}) or return;

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
    return 1;
}

sub do_inform_about {
    my ($conn, $parsed, $args) = @_;

    my $opts = {};
    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'delay=f'  => \$opts->{'delay'},
            'rate=f'   => \$opts->{'rate'},
        ) or return;

    my $delay = $$opts{'delay'};
    my $rate  = $$opts{'rate'};

    my $dfl_probe_delay = $DFL_PROBE_DELAY / 10;
    my $dfl_probe_rate  = 1/$dfl_probe_delay;

    my $interrupt = 0;
    local ($::SIG{INT}) = sub { $interrupt++ };

    if (defined $delay) {
        if (defined $rate) {
            print_error("** warning: --rate ignored in favour of --delay");
        }
        if ($delay <= 0) {
            print_error("** warning: delay of $delay ignored;",
                        " using $dfl_probe_delay");
            $delay = $dfl_probe_delay;
        }
    }
    elsif (defined $rate) {
        if ($rate > $MAX_PROBE_RATE) {
            my $dfl_rate = sprintf("%0.2f", $dfl_probe_rate);
            print_error("** warning: rate of $rate ignored;",
                        " using $dfl_rate");
            $delay = $dfl_probe_delay;
        }
    }
    else {
        $delay = $dfl_probe_delay;
    }

    my $src_list = expand_ip_filter(arg => $$args{'src_ip'},
                                    name => 'source-ip') or return;

    my $dst_list = expand_ip_filter(arg => $$args{'dst_ip'},
                                    name => 'dest-ip',
                                    have_mac => 1) or return;

    my $pairs               = int(@$src_list) * int(@$dst_list);
    my $estimate_per_update = $delay ? $delay : 0.05;
    my $time_estimate       = $pairs * $estimate_per_update;

    my $count = 0;
    my $start = time;
    my $intlen = length($pairs);
    my $timelen = length(sprintf("%d", $time_estimate+0.5));
    my $fmt = "%${intlen}d/%${intlen}d updates,"
            . " %${timelen}d secs left"
            ;
    $fmt .= clr_to_eol() if $INTERACTIVE; # Padding.
    my $total_pairs = $pairs;

    if ($INTERACTIVE) {
        printf("$fmt\r", $count, $total_pairs, $time_estimate);
    }
    my $print_freq = int(0.5/$estimate_per_update);
    $print_freq |= 1; # Make it an odd number;

    if (get_arp_update_flags($conn) == 0) {
        return print_error(
            qq{** inform: arp_update_flags is set to "none",},
            qq{ so this is a NOP}
        );
    }

    # Lovely, nested anonymous subs...
    my $reply = do_ip_run($dst_list,
        sub {
            return undef if $interrupt;
            my $dst = shift;
            return do_ip_run($src_list,
                sub {
                    return undef if $interrupt;
                    if ($INTERACTIVE && $count % $print_freq == 0) {
                        $time_estimate = $pairs * $estimate_per_update + 0.5;
                        printf("$fmt\r", $count, $total_pairs, $time_estimate);
                    }
                    $pairs--;
                    $count++;
                    return '' if $dst eq $_[0];
                    send_single_inform($conn, $dst, $_[0]);
                    sleep($delay);
                    $estimate_per_update = (time-$start) / $count;
                    return '';
                },
            )
        }
    );

    if ($count > 1 || $INTERACTIVE) {
        $time_estimate = $pairs * $estimate_per_update + 0.5;
        print clr_to_eol() if $INTERACTIVE;
        my $fmt = "%${intlen}d/%${intlen}d updates in %${timelen}d secs";
        print_output(
            sprintf($fmt, $count, $total_pairs, time-$start)
        );
    }
    return 1;
}

sub send_single_inform {
    my ($conn, $dst, $src) = @_;

    my $raw = check_send_command($conn, 'inform', $dst, $src) or return '';

    return '';
    my ($opts, $reply, $output, $tag) = parse_server_reply($raw);
    my $info = $output->[0];
    if (defined $info && defined $info->{'tpa'}) {
        return print_output(sprintf(
                "update sent: [tpa=%s,tha=%s] [spa=%s,sha=%s]",
                $$info{'tpa'}, $$info{'tha'},
                $$info{'spa'}, $$info{'sha'},
            ));
    }
    else {
        return print_output($reply);
    }
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

    Wrap_GetOptionsFromArray($args->{-options}, {},
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
    return print_output($log);
}

# cmd: show version
sub do_show_version {
    my ($conn, $parsed, $args) = @_;
    Wrap_GetOptionsFromArray($$args{-options}, {}) or return;
    return print_output($STATUS->{'version'}."\n");
}

# cmd: show uptime
sub do_show_uptime {
    my ($conn, $parsed, $args) = @_;
    Wrap_GetOptionsFromArray($$args{-options}, {}) or return;

    if (($STATUS) = get_status($conn, {raw=>0, format=>1})) {
        print_output(
            sprintf("%s up %s (started: %s)\n",
                strftime("%H:%M:%S", localtime(time)),
                relative_time($STATUS->{'started'}, 0),
                format_time($STATUS->{'started'}),
            )
        );
    }
    return;
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

    my ($opts, $reply, $output, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_arp', $parsed, $args);

    defined $output or return;

    if (!$$opts{format}) {
        print_output($reply);
        my $count;
        $count++ while ($reply =~ /^ip=/gm);
        return $count;
    }

    my @output;
    if ($$opts{summary}) {
        if ($$opts{header}) {
            push @output, sprintf("%-17s %-17s %-11s %s",
                                  "# MAC", "IP", "Epoch", "Time");
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
    return int(@$output);
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

    my ($opts, $raw, $output, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_ip', $parsed, $args);

    defined $raw or return;

    my %count = (ALIVE=>0,DEAD=>0,PENDING=>0,TOTAL=>0);

    if (!$$opts{format}) {
        while ($raw =~ /^state=(\w+)/gm) {
            $count{$1}++;
            $count{TOTAL}++;
        }
        print_output($raw);
        return \%count;
    }

    my @output;
    if ($$opts{summary} && $$opts{header}) {
        push @output, sprintf("%-17s %-12s %7s %12s %7s",
                                "# IP", "State", "Queue",
                                "Rate (q/min)", "Updated");
    }

    for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$output) {
        if ($$info{state} =~ /^PENDING/) {
            $count{PENDING}++;
        } else {
            $count{$$info{state}}++;
        }
        $count{TOTAL}++;
        if (defined $filter_state) {
            if ($filter_state eq 'pending') {
                next if $$info{state} !~ /^PENDING/;
            }
            else {
                next if lc $$info{state} ne $filter_state;
            }
        }
        if ($$opts{summary}) {
            push @output,
                    sprintf("%-17s %-12s %7d %8.3f     %s",
                            $$info{ip}, $$info{state}, $$info{queue},
                            $$info{rate},
                            format_time($$info{state_changed}),
                    );
        }
        else {
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
    return \%count;
}

# ($opts, $raw, $records, $tag_fmt) =
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
#       $raw        the unformatted output as returned by the daemon
#       $output     a reference to an array of output records. Each
#                   record is a hash (ref) containing key=>value pairs.
#       $tag_fmt    printf format string for the largest "key" string,
#                   e.g. "%-20s".
#
sub shared_show_arp_ip {
    my ($conn, $command, $parsed, $args) = @_;
    my $opts = {
            'header'  => 1,
            'format'  => 1,
            'summary' => 1,
            'raw'     => 0,
        };

    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'header!'  => \$opts->{header},
            'raw!'     => \$opts->{raw},
            'format!'  => \$opts->{format},
            'long!'    => sub { $opts->{summary} = !$_[1] },
            'summary!' => sub { $opts->{summary} = $_[1] },
            'nf'       => sub { $opts->{format}  = 0  },
            'nh'       => sub { $opts->{header}  = 0  },
        ) or return;

    $opts->{format} &&= !$opts->{raw};

    my $reply = '';
    if ($args->{'ip'}) {
        my $arg_count = 0;
        $reply = expand_ip_run($args->{'ip'},
                    sub {
                        $arg_count++;
                        return check_send_command($conn, "$command $_[0]");
                    }
                );
        $opts->{summary} //= ($arg_count > 1);
    }
    else {
        $reply = check_send_command($conn, $command);
        $opts->{summary} //= 1;
    }

    return parse_server_reply($reply, $opts);
}

# ($opts, $reply, $records, $tag_fmt) = parse_server_reply($reply, \%opts, [, $key]);
#
#   Helper function for parsing replies from server.
#
#   Parameters:
#
#       $opts     - Hash ref with options:
#                        raw    : don't convert IP/MAC addresses (dfl. false).
#                        format : split up into records (dfl. 1).
#       $reply    - Raw reply from server.
#       $key      - Key to store records under. If not given, records will be
#                   stored in an array.
#
#   Returns:
#
#       $opts     - The input hash, but with default values filled in.
#       $reply    - The server reply (possibly with IP/MAC addresses
#                   translated).
#       $output   - A reference to an array of output records. Each
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
        $reply =~ s/\b(log_mask)=(\d+)\b
                   /"$1=".join(q{,}, event_mask_to_str($2))
                   /gxme;
    }

    my @output;
    my $taglen  = 0;
    for my $record (split(/\n\n/, $reply)) {
        my %info;
        for my $line (split("\n", $record)) {
            if ($line =~ /(.*?)=(.*)$/g) {
                $info{$1} = $2;
            }
        }

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

    return ($opts, $reply, \@output, $tag_fmt);
}

###############################################################################
# CLEAR commands
###############################################################################

# cmd: clear ip
sub do_clear_ip {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    Wrap_GetOptionsFromArray($args->{-options}, {}) or return;

    if ($ip eq 'all') {
        return check_send_command($conn, 'clear_ip_all');
    }

    return expand_ip_run($ip,
                  sub {
                      return check_send_command($conn, "clear_ip $_[0]");
                  }
                );
}

# cmd: clear arp
sub do_clear_arp {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    Wrap_GetOptionsFromArray($args->{-options}, {}) or return;

    return expand_ip_run($ip,
                  sub {
                      return check_send_command($conn, "clear_arp $_[0]");
                  }
                );
}

###############################################################################
# PROBE commands
###############################################################################

# cmd: probe
sub do_probe {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    my $opts = {};
    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'delay=f'  => \$opts->{'delay'},
            'rate=f'   => \$opts->{'rate'},
        ) or return;

    my $delay = $$opts{'delay'};
    my $rate  = $$opts{'rate'};

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
    else {
        $delay = $DFL_PROBE_DELAY;
    }

    my $start = time;
    my $n = 0;
    expand_ip_run($ip,
        sub {
            my $r = check_send_command($conn, "probe $_[0]") or return;
            my ($o, $reply, $out, $t) = parse_server_reply($r);
            print_output($reply);
            $n++;
        },
        $delay,
    );
    my $elapsed = time - $start;

    return print_output(sprintf("%d probe(s) sent in %0.2fs", $n, $elapsed));
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

    Wrap_GetOptionsFromArray($opts{-options}, {}) or return;

    my $raw = check_send_command($conn, $command, $arg) or return;

    DEBUG "do_set_generic: reply=<$raw>";

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    if ($type eq 'log-level') {
        $old = log_level_to_string($old);
        $new = log_level_to_string($new);
    }
    elsif ($type eq 'arp-update-flags') {
        $old = '('.join(',', update_flags_to_str($old)).')';
        $new = '('.join(',', update_flags_to_str($new)).')';
    }
    elsif ($type eq 'log-mask') {
        $old = '('.join(',', event_mask_to_str($old)).')';
        $new = '('.join(',', event_mask_to_str($new)).')';
    }
    elsif ($type eq 'boolean') {
        $old = $old ? 'yes' : 'no';
        $new = $new ? 'yes' : 'no';
        $type = '%s';
    }
    elsif ($type eq 'int') {
        $type = '%d';
    }
    elsif ($type eq 'float') {
        $fmt = '%0.2f';
    }
    return print_output(sprintf("%s changed from $fmt to $fmt%s",
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

# cmd: set log-mask
sub do_set_log_mask {
    my ($conn, $parsed, $args) = @_;

    event_mask( get_log_mask($conn) );

    do_set_generic(-conn    => $conn,
                   -name    => 'log_mask',
                   -val     => $args->{'mask'},
                   -options => $args->{-options},
                   -type    => 'log-mask');

    event_mask( get_log_mask($conn) );
}

# cmd: set max_pending
sub do_set_max_pending {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max_pending',
                   -val     => $args->{'num'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'integer');
}

# cmd: set max_rate
sub do_set_max_rate {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max_rate',
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

# cmd: set flood_protection
sub do_set_flood_protection {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'flood_protection',
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

# cmd: set sweep_skip_alive
sub do_set_sweep_skip_alive {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'sweep skip-alive',
                   -val     => $args->{'bool'},
                   -options => $args->{-options},
                   -type    => 'bool');
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

    Wrap_GetOptionsFromArray($opts{-options}, {}) or return;

    my @command_args = ($command, $ip);
    push(@command_args, $arg) if defined $arg;
    my $raw = check_send_command($conn, @command_args) or return;

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    if ($type eq 'boolean') {
        $old = $old ? 'yes' : 'no';
        $new = $new ? 'yes' : 'no';
        $type = '%s';
    }
    elsif ($type eq 'int') {
        $type = '%d';
    }
    elsif ($type eq 'float') {
        $fmt = '%0.2f';
    }
    return print_output(sprintf("%s: %s changed from $fmt to $fmt%s",
                                $output->[0]->{ip},
                                $name, $old, $new, $unit));
}

# cmd: set ip pending
sub do_set_ip_pending {
    my ($conn, $parsed, $args) = @_;

    DEBUG "set ip pending";
    return expand_ip_run($args->{'ip'},
        sub {
            do_set_ip_generic(-conn    => $conn,
                      -command => 'set_pending',
                      -name    => 'state',
                      -val     => $args->{'pending'} // 0,
                      -ip      => hex2ip($_[0]),
                      -options => $args->{-options},
                      -type    => 'string');
        }
    );
}

# cmd: set ip dead
sub do_set_ip_dead {
    my ($conn, $parsed, $args) = @_;

    return expand_ip_run($args->{'ip'},
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

    return expand_ip_run($args->{'ip'},
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

    my $opts = { raw => 0, format => 1 };

    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'raw!'     => \$opts->{raw},
            'format!'  => \$opts->{format},
            'nf'       => sub { $opts->{format} = 0 },
        ) or return;

    $opts->{format} &&= !$opts->{raw};

    my $raw = check_send_command($conn, 'get_status') or return;

    ($opts, my $reply, my $output, my $tag) = parse_server_reply($raw, $opts);

    if (!$opts->{format}) {
        return print_output($reply);
    }
    my $info = $output->[0];
    return print_output(
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
        sprintf("$tag%s", 'next sweep:', format_time($$info{next_sweep})),
        ($$info{next_sweep} ? 
            sprintf(" (in %d secs) [%d]",
                $$info{next_sweep}-$$info{date},
                $$info{next_sweep})
            : ''
        ),
        "\n",
    );
}

# $flags_integer = get_arp_update_flags();
sub get_arp_update_flags {
    my $conn = shift;
    my $raw = check_send_command($conn, 'get_param') or return;

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw, {raw=>1});
    return $output->[0]->{arp_update_flags};
}

# $log_mask_integer = get_log_mask();
sub get_log_mask {
    my $conn = shift;
    my $raw = check_send_command($conn, 'get_param') or return;

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw, {raw=>1});
    return $output->[0]->{log_mask};
}

sub do_param {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    my $opts = { raw => 0, format => 1 };

    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'raw!'     => \$opts->{raw},
            'format!'  => \$opts->{format},
            'nf'       => sub { $opts->{format} = 0 },
        ) or return;

    $opts->{format} &&= !$opts->{raw};

    my $raw = check_send_command($conn, 'get_param') or return;

    ($opts, my $reply, my $output, my $tag) = parse_server_reply($raw, $opts);

    if (!$opts->{format}) {
        return print_output($reply);
    }
    my $info = $output->[0];
    return print_output(
        sprintf("$tag= %d\n", 'queuedepth', $$info{queue_depth}),
        sprintf("$tag= %0.2f q/min\n", 'max_rate', $$info{max_rate}),
        sprintf("$tag= %0.2f q/sec\n", 'flood_protection',
            $$info{flood_protection}),
        sprintf("$tag= %d\n", 'max_pending', $$info{max_pending}),
        sprintf("$tag= %d secs\n", 'sweep_period', $$info{sweep_period}),
        sprintf("$tag= %d secs\n", 'sweep_age', $$info{sweep_age}),
        sprintf("$tag= %s\n", 'sweep_skip_alive',
            $$info{sweep_skip_alive}?'yes':'no'),
        sprintf("$tag= %d pkts/sec\n", 'proberate', $$info{proberate}),
        sprintf("$tag= %s\n", 'learning',
            $$info{learning}?"yes ($$info{learning} secs)":'no'),
        sprintf("$tag= %s\n", 'dummy', $$info{dummy}?'yes':'no'),
        sprintf("$tag= %s\n", 'arp_update_flags', $$info{arp_update_flags}),
        sprintf("$tag= %s\n", 'log_level', $$info{log_level}),
        sprintf("$tag= %s\n", 'log_mask', $$info{log_mask}),
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

    my %info = map { /(.*?)=(.*)/; ($1=>$2) } split("\n", $reply);
    my $taglen = 0;
    foreach (keys %info) {
        $taglen = length($_) if length($_) > $taglen;
    }
    $taglen++;
    return (\%info, "%-${taglen}s ");
}

# cmd: dump status [$file]
sub do_dump_status {
    my ($conn, $parsed, $args) = @_;

    if (my $fname = $args->{'file'}) {
        my $dummy;
        # Just pre-check options.
        my $opts = {
                'header'  => 1,
                'format'  => 1,
                'summary' => 1,
                'raw'     => 0,
            };

        $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
                'header!'  => \$opts->{header},
                'raw!'     => \$opts->{raw},
                'format!'  => \$opts->{format},
                'long!'    => sub { $opts->{summary} = !$_[1] },
                'summary!' => sub { $opts->{summary} = $_[1] },
                'nf'       => sub { $opts->{format}  = 0  },
                'nh'       => sub { $opts->{header}  = 0  },
            ) or return;

        $args->{-options} = $opts;

        my $out_fh = IO::File->new(">$fname")
                        or return print_error("cannot write to $fname: $!");

        my $io = IO::String->new();
        my $oldhandle = select $io;
        print_output("<STATUS>");
        do_show_status($conn, $parsed, $args);
        print_output("</STATUS>");
        print_output("\n<PARAM>");
        do_show_parameters($conn, $parsed, $args);
        print_output("</PARAM>");
        print_output("\n<STATE>");
        my $count = do_show_ip($conn, $parsed, $args);
        print_output("</STATE>");
        print_output("\n<ARP-TABLE>");
        my $arp_count = do_show_arp($conn, $parsed, $args);
        print_output("</ARP-TABLE>");
        print_output(
                "\nalive=$$count{ALIVE}",
                " dead=$$count{DEAD}",
                " pending=$$count{PENDING}",
                " ARP_entries=$arp_count",
        );
        select $out_fh;
        print_output(${$io->string_ref});
        select $oldhandle;
        $out_fh->autoflush(1);
        my $size = ($out_fh->stat)[7];
        if (-f $out_fh) {
            print_output("$size bytes written to $fname");
        }
        return $out_fh->close;
    }
    else {
        Wrap_GetOptionsFromArray($args->{-options}, {}) or return;
        ($STATUS) = get_status($conn, {raw=>0, format=>1});
        if (my $pid = $STATUS->{'pid'}) {
            verbose("sending USR1 signal to $pid: ");
            if (kill 'USR1', $STATUS->{'pid'}) {
                verbose("ok\n");
                return print_output("process $pid signalled");
            }
            else {
                verbose("ERROR\n");
                return print_error("** cannot signal $pid: $!");
            }
        }
    }
}

# helper: get state table
sub get_state_table {
    my $conn = shift;

    my %curr_state_table;
    my %curr_stats = (ALIVE=>0,STATIC=>0,DEAD=>0,PENDING=>0,TOTAL=>0);
    {
        my $raw = check_send_command($conn, 'get_ip');
        my ($d_opts, $reply, $output, $d_tag) = parse_server_reply($raw);
        for my $entry (@$output) {
            # Strip "(x)" from "PENDING(x)"
            my ($state) = $entry->{'state'} =~ /^(\w+)/;

            $curr_state_table{$entry->{'hex_ip'}} = $state;
            $curr_stats{TOTAL}++;
            $curr_stats{$state}++;
        }
    }
    return wantarray ? (\%curr_state_table, \%curr_stats) : \%curr_state_table;
}

# cmd: load status $file
sub do_load_status {
    my ($conn, $parsed, $args) = @_;

    my $opts = { force => 0 };

    $opts = Wrap_GetOptionsFromArray($args->{-options}, $opts,
            'force!'   => \$opts->{force},
        ) or return;

    my $fname = $args->{'file'};
    my $fh = IO::File->new("<$fname")
                or return print_error("cannot read $fname: $!");

    my $mtime = ($fh->stat)[9];

    if ($mtime + 60 < time) {
        print_error("** status file $fname\n",
                    "** timestamp [", format_time($mtime), "]",
                    " older than 60 seconds");

        my $load = 0;
        if ($opts->{force}) {
            $load++;
            verbose("--force specified\n");
        }
        elsif ($INTERACTIVE) {
            verbose("(contents are probably stale)\n");
            $load += yesno("load anyway", 'yN');
        }

        if ($load <= 0) {
            return print_error("** status loading aborted");
        }
        else {
            print_output("continue loading...");
        }
    }

    verbose("getting current state table...");

    my ($curr_state_table, $curr_stats) = get_state_table($conn);

    verbose(" ok\n");

    my $parse_state = 'none';
    my %state_table = ();
    my %arp_table   = ();

    verbose("reading state tables...");
    local($_);
    while ($_ = $fh->getline) {
        if (/^<STATE>$/)          { $parse_state = 'state' }
        elsif (/^<ARP-TABLE>$/)   { $parse_state = 'arp'   }
        elsif (/^<\/[\w-]+>$/)    { $parse_state = 'none'  }
        elsif ($parse_state eq 'state' &&
            /^([\d\.]+) \s+ ([A-Z]+) \s+ \d+ \s+ \d+\.\d+ \s+ \S+[\@\s]\S+$/x) {
            my $ip = ip2hex($1);
            $state_table{$ip} = $2;
        }

        elsif ($parse_state eq 'arp' &&
                /^([a-f\d\:]+) \s+ ([\d\.]+) \s+ \d+ \s+ \S+[\@\s]\S+$/x) {
            my ($mac, $ip) = (mac2hex($1), ip2hex($2));
            if (exists $state_table{$ip} && $state_table{$ip} eq 'ALIVE') {
                $arp_table{$ip} = $mac;
            }
        }
    }
    $fh->close;
    verbose(" ok\n");

    verbose("checking and setting states\n");

    my %ip_stats   = (ALIVE=>0, STATIC=>0, DEAD=>0,
                      TOTAL=>0, PENDING=>0, CHANGED=>0);
    for my $ip (sort { $a cmp $b } keys %state_table) {
        $ip_stats{'TOTAL'}++;
        $ip_stats{$state_table{$ip}}++;
        $$curr_state_table{$ip} //= 'DEAD';
        if ($$curr_state_table{$ip} eq $state_table{$ip}) {
            #verbose "no change ", hex2ip($ip), "\n";
            next;
        }
        foreach ($state_table{$ip}) {
            if ($_ eq 'ALIVE') {
                $ip_stats{'CHANGED'}++;
                do_set_ip_generic(
                    -conn    => $conn,
                    -command => 'set_alive',
                    -name    => 'state',
                    -val     => $arp_table{$ip},
                    -ip      => hex2ip($ip),
                    -options => [],
                )
            }
            elsif ($_ eq 'DEAD') {
                $ip_stats{'CHANGED'}++;
                check_send_command($conn, "clear_ip $ip");
            }
        }
    }
    verbose("done\n");

    return print_output(
            "old:",
                 " total=$$curr_stats{TOTAL}",
                 " static=$$curr_stats{STATIC}",
                 " alive=$$curr_stats{ALIVE}",
                 " dead=$$curr_stats{DEAD}",
                 " pending=$$curr_stats{PENDING}",
                 "\n",
            "new:",
                 " total=$ip_stats{TOTAL}",
                 " static=$ip_stats{STATIC}",
                 " alive=$ip_stats{ALIVE}",
                 " dead=$ip_stats{DEAD}",
                 " pending=$$curr_stats{PENDING}",
                 " changed=$ip_stats{CHANGED}",
        );
}

###############################################################################
# Initialisation
###############################################################################

sub initialise {
    my ($sockname, $interface);
    my $opt_c     = undef;

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
        'quiet'       => \$opt_quiet,
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
            my $err = "$0: cannot find sponge instance in $rundir\n";
            if ($opt_test) {
                warn "** WARN: $err";
            }
            else {
                die $err;
            }
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
    $M6::ReadLine::TYPES{'log-mask'} = {
            'verify'   => \&check_log_mask,
            'complete' => \&complete_log_mask,
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
[B<--quiet>]
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
X<--command>

Signals to the program that whatever follows the C<--command> option should be
considered as input to the program. This is useful if you want to specify
options to the program's commands. The following are sort of equivalent:

  asctl -c show status --no-format
  asctl -- show status --no-format
  asctl 'show status --no-format'

Note that you cannot specify C<--command> without at least one argument.

=item B<--debug>
X<--debug>

Print debugging information to F<stderr> while executing.

=item B<--interface>=I<ifname>
X<--interface>

Connect to the L<arpsponge> instance for interface I<ifname>.

=item B<--rundir>=I<dir>
X<--rundir>

Override the default top directory for the L<arpsponge> control files.
See also L<FILES|/FILES> below.

=item B<--socket>=I<sock>
X<--socket>

Explicitly specify the path of the control socket to connect to. Mutually
exclusive with L<--interface|/--interface>.

=item B<--test>
X<--test>

Do not connect to any daemon or send any commands. This is really only
used during development to check command parsing, etc.

=item B<--verbose>
X<--verbose>

The C<--verbose> flag causes the program to be a little more talkative.

=item B<--quiet>
X<--quiet>

Only has effect when executing commands from the command line.
Causes all non-error output to be suppressed.

=back

=head1 COMMANDS

In the list below, the following constructions are used:

    $ip        ::= valid IPv4 address
    $ip-range  ::= $ip[-$ip][,$ip-range]
    $ip-any    ::= {$ip-range|all}
    $ip-filter ::= {alive|dead|pending|none|$ip-any}

=over

=item B<clear arp> I<ip-range>
X<clear arp>

Clear ARP table for given IP(s)

=item B<clear ip> I<ip-range>
X<clear ip>

Clear state table for given IP(s)

=item B<dump status>
X<dump status>

=item B<dump status> [I<file>]

This command will actually do two very different things, depending on whether
the I<file> argument is given or not.

Without a I<file> argument, the I<asctl> process will send a C<USR1> signal to
the L<arpsponge|arpsponge> daemon, causing B<it> to dump its status to its
C<--dumpfile> argument which is fixed at daemon startup. See also
L<arpsponge|arpsponge>(8). This command can typically only be executed by
the owner of the daemon's process (typically C<root>).

With a I<file> argument, the I<asctl> process will query the daemon and write a
summary of the status to I<file>. The output file location should be writable
by the user running I<asctl>. This command can be executed by anybody with
sufficient rights to connect to the daemon's control socket. A file argument
of "F<->" will dump the status to the terminal.

The format of the I<asctl> generated file differs slightly from the daemon's
legacy format, but both can be used in a C<load status> command.

=item B<help>
X<help>

Show command summary

=item B<inform> I<dst_ip> B<about> I<src_ip>
X<inform>

Force I<dst_ip> to update its ARP entry for I<src_ip>. See also
"L<set arp_update_flags|/arp_update_flags>" below.

Both I<dst_ip> and I<src_ip> can be I<$ip-filter> arguments.

=item B<load status> [B<--force>] I<file>
X<load status>

Load IP/ARP state from I<file>. The I<file> should be a dump file previously
created by the daemon's dump facility (see also "L<dump status|/dump status>"
above).

By default, a dump file that's older than 60 seconds is ignored, since it is
likely to contain stale information, unless B<--force> is given.

The states in the dump file are interpreted as follows:

=over

=item B<ALIVE>

If we have:

  <STATE>
  # IP          State  Queue Rate (q/min) Updated
  91.200.17.2   ALIVE      0    0.000     2011-07-05@17:15:33
  </STATE>

  <ARP-TABLE>
  # MAC             IP          Epoch      Time
  00:0c:db:02:64:1c 91.200.17.2 1309878933 2011-07-05@17:15:33
  </ARP-TABLE>

Execute:

  set ip 91.200.17.2 alive 00:0c:db:02:64:1c

That is, the daemon is told set the address to C<ALIVE> and update the
corresponding MAC (if present in the dump file).

=item B<DEAD>

If we have:

  <STATE>
  # IP          State  Queue Rate (q/min) Updated
  91.200.17.3   DEAD       0    0.000     2011-07-05@17:15:45
  </STATE>

Execute:

  clear ip 91.200.17.3

That is, the daemon is told to clear the state information, so the next
ARP for that address will put it in a C<PENDING> state.

=back

The handling of C<DEAD> state information in the dump file allows us to load
relatively old data, without resulting in sponging of active addresses, while
still allowing quick discovery of the still-dead addresses.

=item B<ping> [[I<count> [I<delay>]]
X<ping>

Send I<count> "ping" probes to the daemon, waiting I<delay>
seconds between probes, display response RTT per probe and
a summary at the end. Can be stopped by an interrupt signal
(C<Ctrl-C>).

=item B<probe> [B<--delay>=I<sec> | B<--rate>=I<rate>] I<ip-range>
X<probe>

Send broadcast ARP queries (probes) for addresses in I<ip-range>.
By default, the request rate is 10 probes per second (delay is 0.1),
but this can be changed with the C<--delay> or C<--rate> options.

=item B<quit>
X<quit>

disconnect and quit

=item X<arp_update_flags>B<set> B<arp_update_flags> I<flag>[,I<flag>,...]
X<set arp_update_flags>

Set the methods (comma-separated list) by which the sponge is to update
its neighbors' ARP caches.

This value is used for manual C<inform> commands as well as automatic inform
actions (see L<--arp-update-methods|arpsponge/--arp-update-methods> in the
L<arpsponge>(1) manpage).

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
X<set dummy>

Enable/disable DUMMY mode; I<bool> can be any of:
C<yes>, C<true>, C<on>, C<1>,
C<no>, C<false>, C<off>, C<0>.

=item B<set ip> I<ip-range> B<alive> [I<mac>]
X<set ip alive>

Unsponge given IP(s) (associate them with I<mac>)

=item B<set ip> I<ip-range> B<dead>
X<set ip dead>

Sponge given IP(s)

=item B<set ip> I<ip-range> B<mac> I<mac>
X<set ip>

Statically store <ip> -> <mac> in the ARP table

=item B<set ip> I<ip-range> pending [I<pending>]
X<set ip pending>

Set given IP(s) to pending state I<pending> (default 0)

=item B<set learning> I<secs>
X<set learning>

Switch in to/out of learning mode

=item B<set log_level> I<level>
X<set log_level>

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

=item B<set log_mask> [B<!>|B<+>]I<event>,...

Specify which event types should be logged. Some events can occur
very often and it can be useful to filter them out to prevent filling
the logs. The default value is C<all>, meaning that all event classes
are logged by default.

The following event classes exist:

=over

=item C<io>

I/O related events (broken pipes, disconnections, read failures, etc.).

=item C<alien>

The "misplaced ARP" events. When multiple subnets are active on a single
LAN, it may be prudent to filter this one out.

=item C<spoof>

Messages about "spoofed" ARP packets, i.e. where the Ethernet source
is different than the ARP header's "source hardware address".

=item C<static>

Warnings about traffic coming from a statically sponged address.

=item C<sponge>

Sponge events (sponge/unsponge/pending/clear, etc.)

=item C<ctl>

Control socket events (connect/disconnect, commands).

=item C<state>

Daemon state.

=back

The classes can be specified as a comma-separated list, e.g.:

   io,alien,spoof

If a class starts with a C<+>, it is added to the current mask, if
it starts with a C<!>, it is subtracted from the current mask.

If the first class in the list does not start with either a C<+> or C<!>, then
the mask is reset to the class, i.e.:

   io,+alien

Will set the mask to C<io> and C<alien> only, while:

   +io,+alien

Will add C<io> and C<alien> to the current mask.

Default value is C<all>.

=item B<set> {B<max_pending>|B<queuedepth>} I<num>
X<set max_pending>
X<set queuedepth>

Set queue parameters

=item B<set> {B<max_rate>|B<flood_protection>|B<proberate>} I<rate>
X<set max_rate>
X<set flood_protection>
X<set proberate>

Set rate parameters

=item B<set sweep_age> I<secs>
X<set sweep_age>

=item B<set sweep_period> I<secs>
X<set sweep_period>

Set sweep/probe parameters

=item B<set sweep_skip_alive> I<bool>
X<set sweep_skip_alive>

Enable/disable skipping ALIVE addresses during sweeping; I<bool> can be any of:
C<yes>, C<true>, C<on>, C<1>,
C<no>, C<false>, C<off>, C<0>.

=item B<show arp> [I<ip-any>]
X<show arp>

Show ARP table for given IP(s)

=item B<show ip> [I<ip-filter>]
X<show ip>

Show state table for given IP(s)

=item B<show log> [I<nlines>]
X<show log>

Show daemon log (most recent <nlines>)

=item B<show> {B<parameters>|B<status>|B<uptime>|B<version>}
X<show parameters>
X<show status>
X<show uptime>
X<show version>

Show general information

=item B<sponge> I<ip-range>
X<sponge>

=item B<unsponge> I<ip-range>
X<unsponge>

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

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

