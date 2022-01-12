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

use 5.014;
use warnings;
use FindBin;
use Getopt::Long    qw( GetOptions GetOptionsFromArray );
use POSIX           qw( strftime floor );
use Pod::Usage;
use Pod::Text::Termcap;
use Time::HiRes     qw( time sleep );
use NetAddr::IP;
use Term::ReadLine;
use IO::File;
use Scalar::Util    qw( reftype );
use YAML::PP qw();
use JSON::PP qw();

use M6::ArpSponge::Control::Client;
use M6::ArpSponge::Event     qw( :standard );
use M6::ArpSponge::Log       qw( :standard :macros );
use M6::ArpSponge::Util      qw( :all );
use M6::ArpSponge::ReadLine  qw( :all );
use M6::ArpSponge::Const     qw( :all );
use M6::ArpSponge::NetPacket qw( :vars );

my $JSON_OBJ        = JSON::PP->new->pretty(1);
my $YAML_OBJ        = YAML::PP->new(
    yaml_version      => [qw( 1.2 1.1 )],
    schema            => ['+'],
    boolean           => 'JSON::PP',
    cyclic_refs       => 'fatal',
    duplicate_keys    => 0,
    indent            => 2,
    width             => 78,
    header            => 1,
    footer            => 0,
    version_directive => 1,
);

my $SPONGE_VAR      = '@SPONGE_VAR@';
my $CONN            = undef;
my $ERR             = 0;
my $STATUS          = {};

my $MAX_DUMP_AGE    = 60;

my $DFL_PROBE_DELAY = 0.1;
my $MIN_PROBE_DELAY = 0.001;
my $DFL_PROBE_RATE  = 1/$DFL_PROBE_DELAY;
my $MAX_PROBE_RATE  = 1/$MIN_PROBE_DELAY;

my %ATTR_TYPE = (
    ( map { $_ => $_    } qw( arp_update_flags log_level log_mask state ) ),
    ( map { $_ => 'ip'  } qw( ip tpa spa network ) ),
    ( map { $_ => 'mac' } qw( mac tha sha ) ),
    ( map { $_ => 'boolean' } qw(
        dummy passive static sweep_skip_alive
    ) ),
    ( map { $_ => 'int' } qw(
        learning max_pending pid prefixlen proberate
        queue queue_depth sweep_age sweep_period
        tm_date tm_last_queried tm_mac_changed
        tm_next_sweep tm_started tm_state_changed
        raw_arp_update_flags
        raw_log_level
        raw_log_mask
        raw_boolean
        raw_sweep_skip_alive
        raw_static
        raw_dummy
        raw_passive
    ) ),
    ( map { $_ => 'float' } qw(
        flood_protection max_rate rate
    ) ),
    ( map { $_ => 'date'  } qw(
        started date mac_changed state_changed last_queried
        next_sweep
    ) ),
);

my %TYPE_CONVERSION_MAP = (
    state => {
        fmt => '%s',
    },
    arp_update_flags => {
        convert => sub { join(',', update_flags_to_str($_[0])) },
        save_raw => 'raw_%s',
        convert_raw => sub { ($_[0] // 0) + 0 },
        fmt => '%s',
    },
    log_level => {
        convert => \&log_level_to_string,
        save_raw => 'raw_%s',
        convert_raw => sub { ($_[0] // 0) + 0 },
        fmt => '%s',
    },
    log_mask => {
        convert => sub { join(',', event_mask_to_str($_[0])) },
        save_raw => 'raw_%s',
        convert_raw => sub { ($_[0] // 0) + 0 },
        fmt => '%s',
    },
    boolean => {
        convert => \&int2bool,
        save_raw => 'raw_%s',
        convert_raw => sub { ($_[0] // 0) + 0 },
        fmt => '%s',
    },
    int => {
        convert => sub { $_[0] + 0 },
        fmt => '%d',
    },
    float => {
        convert => sub { $_[0] + 0 },
        fmt => '%0.2f',
    },
    ip => {
        convert  => \&hex2ip,
        save_raw => 'hex_%s',
        fmt => '%s',
    },
    mac => {
        convert => \&hex2mac,
        save_raw => 'hex_%s',
        fmt => '%s',
    },
    date => {
        convert  => \&format_time,
        fmt      => '%s',
        save_raw => 'tm_%s',
        convert_raw => sub { ($_[0] // 0) + 0 },
    },
);

my %VALID_OUTPUT_FORMAT = (
    map { $_ => $_ } qw( json yaml native raw )
);

# Values set on the Command Line.
my $opt_quiet     = 0;
my $opt_verbose   = 0;
my $opt_debug     = 0;
my $opt_test      = 0;
my $rundir        = $SPONGE_VAR;

my $INTERACTIVE   = 1;

my $VERSION    = '@RELEASE@';
my $app_header = <<EO_USAGE;

This is $FindBin::Script, v$VERSION

See "perldoc $FindBin::Script" for more information.
EO_USAGE

END {
    $CONN && $CONN->close;
}

sub verbose(@) { print @_ if $opt_verbose; }
sub DEBUG(@)   { print_error(@_) if $opt_debug; }

my @IP_STATES = qw(all alive dead pending static none);
my %Syntax = (
    'quit $-' => { '?'       => 'Disconnect and quit.', },
    'help $-' => { '?'       => 'Show command summary.',
        opts => [ 'pod|p' ]
    },
    'ping $count? $delay?' => {
        '?'       => '"ping" the daemon, display response RTT.',
        '$count'  => { type=>'int',   min=>1,    default=>1 },
        '$delay'  => { type=>'float', min=>0.01, default=>1 }, },
    'clear ip $- $ip'   => {
        '?'       => 'Clear state table for given IP(s).',
        '$ip'     => { type=>'ip-any'    } },
    'clear arp $- $ip'  => {
        '?'       => 'Clear ARP table for given IP(s).',
        '$ip'     => { type=>'ip-range'  } },
    'load status $- $file' => {
        '?'       => 'Load IP/ARP state from dump file.',
        '$file'   => { type=>'filename' },
        'opts'    => [ 'force|f' ], },
    'dump status $- $file?' => {
        '?'       => 'Either dump daemon status to <file>,'
                     .' or signal the daemon to dump to its'
                     .' "standard" location (user needs'
                     .' privileges to send signals to the'
                     .' daemon process).',
        '$file'   => { type=>'filename' },
        'opts'    => [
            'header|h!',
            'H',
            'extended|x!',
            mk_output_format_options_2(),
        ],
    },
    'probe $- $ip'   => {
        '?'       => 'Send ARP requests for given IP(s).',
        '$ip'     => { type=>'ip-range'  },
        'opts' => [ 'delay|d=f', 'rate|r=f', 'verbose|v' ],
    },
    'show ip $- $ip?'   => {
        '?'       => 'Show state table for given IP(s).',
        '$ip'     => { type=>'ip-filter' },
        'opts'    => [
            'header|h!', 'H',
            'extended|x!',
            mk_output_format_options_2()
        ],
    },
    'show arp $- $ip?'  => {
        '?'       => 'Show ARP table for given IP(s).',
        '$ip'     => { type=>'ip-any'    },
        'opts'    => [
            'header|h!', 'H',
            'extended|x!',
            mk_output_format_options_2()
        ],
    },
    'show parameters $-' => {
        '?'    => 'Show daemon parameters.',
        'opts' => [
            'extended|x!',
            mk_output_format_options_2()
        ],
    },
    'show status $-'  => {
        '?'    => 'Show daemon status.',
        'opts' => [
            'extended|x!',
            mk_output_format_options_2()
        ],
    },
    'show version $-' => { '?' => 'Show daemon version.'  },
    'show uptime $-'  => { '?' => 'Show daemon uptime.'   },
    'show log $- $nlines?' => {
        '?'       => 'Show daemon log (most recent <nlines>).',
        '$nlines' => { type=>'int', min=>1 },
        'opts'    => [
            'raw-timestamps|n',
            'reverse|r!', 'R',
        ],
    },
    'sponge $- $ip' => {
        '?'       => 'Sponge given IP(s); see also "set ip dead".',
        '$ip'     => { type=>'ip-range' } },
    'unsponge $- $ip' => {
        '?'       => 'Unsponge given IP(s); see also "set ip alive".',
        '$ip'     => { type=>'ip-range' } },
    'inform $- $dst_ip about $src_ip' => {
        '?'       => 'Force <dst_ip> to update its ARP entry for <src_ip>.',
        '$dst_ip' => { type=>'ip-filter' },
        '$src_ip' => { type=>'ip-filter' },
        'opts' => [ 'delay|d=f', 'rate|r=f', 'verbose|v' ],
    },
    'set arp_update_flags $flags' => {
        '?'       => q{Set the methods (comma-separated list) by which the}
                    .q{ sponge is to update its neighbors' ARP caches},
        '$flags'  => { type=>'arp-update-flags' },
        },
    'set ip $ip dead'   => {
        '?'       => 'Sponge given IP(s).',
        '$ip'      => { type=>'ip-range'  } },
    'set ip $ip static'   => {
        '?'        => 'Mark given IP(s) as statically sponged.',
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
    'set passive $bool' => {
        '?'        => 'Enable/disable PASSIVE mode.',
        '$bool'    => { type=>'bool' }, },
    'set static $bool' => {
        '?'        => 'Enable/disable STATIC mode.',
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
        $CONN = M6::ArpSponge::Control::Client->create_client($sockname)
                    or die "$sockname: ".M6::ArpSponge::Control::Client->error."\n";
    }
    ($STATUS) = get_status($CONN);
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
        $M6::ArpSponge::ReadLine::IP_NETWORK =
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

sub print_output_fh {
    my ($fh, @l) = @_;
    my $old_fh = select $fh;
    print_output(@l);
    select $old_fh;
}

sub do_command {
    my ($line, $conn) = @_;
    my %args = (-conn => $conn);
    my @parsed = ();

    if (parse_line($line, \@parsed, \%args)) {
        my $func_name = "cmd @parsed";
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
sub expand_ip_chunk {
    my ($name, $ip_s, $silent) = @_;

    my ($lo_s, $hi_s);

    if ($ip_s !~ m{/\d+$}) {
        ($lo_s, $hi_s) = split(/-/, $ip_s, 2);

        check_ip_address_arg({name=>$name}, $lo_s, $silent) or return;
        my $lo = ip2int($lo_s);
        DEBUG "lo: <$lo_s> $lo";
        my $hi = $lo;
        if ($hi_s) {
            check_ip_address_arg({name=>$name}, $hi_s, $silent) or return;
            $hi = ip2int($hi_s);
            DEBUG "hi: <$hi_s> $hi";
        }
        if ($hi < $lo) {
            $silent or print_error(
                        qq{$name: "$lo_s-$hi_s" is not a valid IP range});
            return;
        }
        return [$lo, $hi, $lo_s, $hi_s // $lo_s];
    }

    my $cidr = NetAddr::IP->new($ip_s);
    if (!$cidr) {
        $silent or print_error(
                qq{$name: "$ip_s" is not a valid IP range});
        return;
    }
    if (!$M6::ArpSponge::ReadLine::IP_NETWORK->contains($cidr)) {
        $silent or print_error(
                qq{$name: $ip_s is out of range }
                . $M6::ArpSponge::ReadLine::IP_NETWORK->cidr
        );
        return;
    }

    my ($cidr_first, $cidr_last, $net_first, $net_last) = (
        $cidr->first->addr, $cidr->last->addr,
        $M6::ArpSponge::ReadLine::IP_NETWORK->first->addr,
        $M6::ArpSponge::ReadLine::IP_NETWORK->last->addr,
    );
    $lo_s = $cidr_first eq $net_first
        ? $cidr_first
        : $cidr->network->addr;

    $hi_s = $cidr_last eq $net_last
        ? $cidr_last
        : $cidr->broadcast->addr;

    return [ip2int($lo_s), ip2int($hi_s), $lo_s, $hi_s];
}

#############################################################################
# Expand the $arg_str as an IP address range:
#
#   192.168.0.4, 192.168.0.5 .. 192.168.0.8
#   192.168.0.4 - 192.168.0.8
#   192.168.0.4 .. 192.168.0.8
#   192.168.0.4/30, 192.168.0.8
#
#############################################################################
sub expand_ip_range {
    my ($arg_str, $name, $silent) = @_;

    $arg_str =~ s/\s*(?:-|\.\.|to)\s*/-/g;
    $arg_str =~ s/\s*,\s*/ /g;

    my @args = split(' ', $arg_str);

    DEBUG "range: <$arg_str>:", map {" <$_>"} @args;

    my @list;
    for my $ip_s (@args) {
        my $chunk = expand_ip_chunk($name, $ip_s, $silent) or return;
        push @list, $chunk;
    }
    return \@list;
}

#############################################################################
sub check_output_format {
    my ($opts) = @_;

    my $fmt = $opts->{format};
    if ($fmt) {
        if (my $val = $VALID_OUTPUT_FORMAT{lc $fmt}) {
            return $val;
        }
        my @formats = sort keys %VALID_OUTPUT_FORMAT;
        my $last_fmt = pop @formats;

        my $fmt_list = join('', map { "'$_', " } @formats);
        $fmt_list .= "or " if length($fmt_list);
        $fmt_list .= $last_fmt;

        return print_error("invalid format '$fmt'; need $fmt_list");
    }

    for my $k (sort keys %VALID_OUTPUT_FORMAT) {
        return $VALID_OUTPUT_FORMAT{$k} if $opts->{$k};
    }
    return 'native';
}

sub mk_output_format_options {
    my ($opts, $key) = @_;

    return (
        'format|f=s'  => \$opts->{format},
        map {
            "$_|".substr($_, 0, 1) => sub { $opts->{format} = $_[0] }
        } keys %VALID_OUTPUT_FORMAT
    );
}

sub mk_output_format_options_2 {
    return (
        'format|f=s',
        map { "$_|".substr($_, 0, 1) } keys %VALID_OUTPUT_FORMAT
    );
}

#############################################################################
sub int2bool {
    my ($val) = @_;
    return $_[0] ? JSON::PP::true : JSON::PP::false;
}

sub bool2str {
    my ($val, $true_suffix, $false_suffix) = @_;
    if ($val) {
        return 'true'.($true_suffix // '');
    }
    return 'false'.($false_suffix // '');
}

#############################################################################
# ($val, $cv) = convert_attr_value($key, $val);
sub convert_attr_value {
    my ($key, $val) = @_;
    $key =~ tr/-/_/;

    my $type = $ATTR_TYPE{$key}
        or return ($val, { fmt => '%s' });

    my $cv = $TYPE_CONVERSION_MAP{$type}
        or return ($val, { fmt => '%s' });

    my %cv = (
        convert => sub { $_[0] },
        fmt => '%s',
        %$cv
    );
    my $new_v = $cv{convert}->($val);
    return ($cv{convert}->($val), \%cv);
}

#############################################################################
# $s = format_attr_value($key, $val);
sub format_attr_value {
    my ($k, $v) = @_;
    my ($val, $cv) = convert_attr_value($k, $v);

    return sprintf("$$cv{fmt}", $val);
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
                shared_show_arp_ip($CONN, 'get_arp');
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
    for my $name (keys %M6::ArpSponge::Const::STR_TO_UPDATE_FLAG) {
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

sub cmd_quit {
    my ($conn, $parsed, $args) = @_;
    my $reply = check_send_command($conn, 'quit') or return;
    return print_output($reply);
}


sub cmd_help {
    my ($conn, $parsed, $args) = @_;

    my %optinfo;
    while (my ($cmd, $info) = each %Syntax) {
        my $opts = $info->{opts} || next;
        for my $spec (@$opts) {
            $spec =~ s/[\!\+]//g;
            my ($name, $val) = split(/=/, $spec, 2);
            my @names = split(/\|/, $name);
            my $pod = length($names[0]) == 1 ? "B<-$names[0]>" : "B<--$names[0]>";
            $pod .= "=I<$val>" if $val;
            my $txt = "--$names[0]";
            $txt .= "=$val" if $val;
            push @{$optinfo{$cmd}{pod}}, "[$pod]";
            push @{$optinfo{$cmd}{txt}}, "[$txt]";
        }
    }

    my %help;
    for my $cmd (keys %Syntax) {
        my $text = $cmd;
        my $opts = $optinfo{$cmd}{pod} // [];
        my $opt_text = join(' ', @$opts);
        $text =~ s/(\s*)\$-(\s*)/length($opt_text) ? "$1$opt_text$2" : $2/ge;
        $text =~ s/(^|\s)([a-z][\w\-]*)/$1B<$2>/g;
        $text =~ s/\$(\S+)\?/[I<$1>]/g;
        $text =~ s/\$(\S+)/I<$1>/g;
        $text =~ s/(\S+)\|(\S+)/{B<$1>|B<$1>}/g;
        $help{$text} = $Syntax{$cmd}->{'?'};
    }

    my $maxlen = 72;
    my $pod = qq{=head1 COMMAND SUMMARY\n\n}
            . qq{=over 32\n}
            ;

    for my $cmd (sort keys %help) {
        $pod .= qq{\n=item $cmd\n\n}
              . fmt_text('', $help{$cmd}, $maxlen, 0)
              ;
    }
    $pod .= "\n=back\n";

    if ($args->{-options}->{pod}) {
        return print_output($pod);
    }

    my $output;
    my $pod_parser = Pod::Text::Termcap->new( width => (term_width() - 1) );
    $pod_parser->output_string(\$output);
    $pod_parser->parse_string_document($pod);

    return print_output($output);
}

sub cmd_ping {
    my ($conn, $parsed, $args) = @_;

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
            print_output([
                "%d bytes from #%d: time=%0.3f ms\n", length($reply),
                $$STATUS{pid}, $rtt
            ]);
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
        print_output(
            [ "--- %s ping statistics ---\n", $$STATUS{id}      ],
            [ "%d packets transmitted, %d received, ", $ns, $nr ],
            [ "%d%% packet loss, time %dms\n", $loss, $time     ],
            [ "rtt min/avg/max/mdev = %0.3f/%0.3f/%0.3f/%0.3f ms\n",
                $min_rtt, $avg_rtt, $max_rtt, $mdev_rtt ]
        );
    }
    return 1;
}

sub cmd_inform_about {
    my ($conn, $parsed, $args) = @_;

    my $delay = $args->{-options}{'delay'};
    my $rate  = $args->{-options}{'rate'};

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
                    send_single_inform($conn, $dst, $_[0], $args->{-options});
                    sleep($delay);
                    $estimate_per_update = (time-$start) / $count;
                    return '';
                },
            )
        }
    );

    if ($count > 1 || $INTERACTIVE) {
        $time_estimate = $pairs * $estimate_per_update + 0.5;
        print "\r".clr_to_eol() if $INTERACTIVE;
        my $fmt = "%${intlen}d/%${intlen}d updates in %${timelen}d secs";
        print_output([ $fmt, $count, $total_pairs, time-$start ]);
    }
    return 1;
}

sub send_single_inform {
    my ($conn, $dst, $src, $opts) = @_;

    $opts //= {};

    my $raw = check_send_command($conn, 'inform', $dst, $src) or return '';

    return '' if !$opts->{verbose};

    ($opts, my ($reply, $output, $tag)) = parse_server_reply($raw);
    my $info = $output->[0];
    if (defined $info && defined $info->{'tpa'}) {
        return print_output([
            "update sent: [tpa=%s,tha=%s] [spa=%s,sha=%s]",
            $$info{'tpa'}, $$info{'tha'},
            $$info{'spa'}, $$info{'sha'},
        ]);
    }
    else {
        return print_output($reply);
    }
}

###############################################################################
# SHOW commands
###############################################################################

# cmd: show status
sub cmd_show_status {
    my ($conn, $parsed, $args) = @_;
    return do_show_status($conn, $args);
}

# cmd: show status
sub cmd_show_parameters {
    my ($conn, $parsed, $args) = @_;
    return do_show_parameters($conn, $args);
}

# cmd: show log
sub cmd_show_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    my $opts = $args->{-options};
    my $notranslate = $opts->{'raw-timestamps'};
    my $reverse = ($opts->{reverse} // 1) && !$opts->{R};

    my @args = defined $args->{'nlines'} ? ($args->{'nlines'}) : ();
    my $log = check_send_command($conn, 'get_log', @args) or return;
    if (!$notranslate) {
        $log =~ s/^(\S+)\t(\d+)\t/format_time($1,' ')." [$2] "/gme;
    }
    if ($reverse) {
        $log = join("\n", reverse split(/\n/, $log));
    }
    return print_output($log);
}

# cmd: show version
sub cmd_show_version {
    my ($conn, $parsed, $args) = @_;
    return print_output($STATUS->{'version'}."\n");
}

# cmd: show uptime
sub cmd_show_uptime {
    my ($conn, $parsed, $args) = @_;

    if (($STATUS) = get_status($conn)) {
        print_output([
            "%s up %s (started: %s)\n" => (
                strftime("%H:%M:%S", localtime(time)),
                relative_time($STATUS->{'tm_started'}, 0),
                $STATUS->{'started'},
            )
        ]);
    }
    return;
}

# cmd: show arp
sub cmd_show_arp {
    my ($conn, $parsed, $args) = @_;
    do_show_arp($conn, $args);
}

sub do_show_arp {
    my ($conn, $args) = @_;

    my $filter_state;
    my $ip = $args->{'ip'};

    if (defined $ip) {
        if ($ip eq 'all') {
            delete $args->{'ip'};
        }
    }

    my ($opts, $reply, $result, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_arp', $args);

    defined $result or return;

    if ($opts->{format} ne 'native') {
        if ($opts->{format} eq 'raw') {
            print_output($reply);
        }

        my $arp_table = convert_arp_output_for_export($result, $opts);
        my $data = { 'arpsponge.arp-table' => $arp_table };

        if ($opts->{format} eq 'json') {
            print_output($JSON_OBJ->encode($data));
        }
        elsif ($opts->{format} eq 'yaml') {
            print_output($YAML_OBJ->dump_string($data));
        }

        my $count = () = $reply =~ /^ip=/gm;
        return $count;
    }

    my @output;
    if ($$opts{header} // 1 && !$$opts{H}) {
        push @output, [
            "%-17s %-17s %-11s %s\n", "# MAC", "IP", "Epoch", "Time"
        ];
    }
    for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$result) {
        push @output, [
            "%-17s %-17s %-11d %s\n",
                $$info{mac}, $$info{ip},
                $$info{tm_mac_changed},
                $$info{mac_changed},
        ];
    }
    print_output(@output);
    return int(@$result);
}

# cmd: show ip
sub cmd_show_ip {
    my ($conn, $parsed, $args) = @_;
    do_show_ip($conn, $args);
}

sub do_show_ip {
    my ($conn, $args) = @_;

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

    my ($opts, $raw, $result, $tag_fmt) =
        shared_show_arp_ip($conn, 'get_ip', $args);

    return if !defined $raw;

    my %count = (ALIVE=>0,DEAD=>0,PENDING=>0,TOTAL=>0);
    my @filtered;
    for my $info (sort { $$a{hex_ip} cmp $$b{hex_ip} } @$result) {
        my $state = $$info{state} =~ s/\(\d+\)$//r;
        $count{$state}++;
        $count{TOTAL}++;
        next if defined $filter_state && lc $state ne $filter_state;
        push @filtered, $info;
    }

    if ($opts->{format} eq 'raw') {
        print_output($raw);
        return \%count;
    }

    if ($opts->{format} ne 'native') {
        my $ip_table = convert_ip_output_for_export(\@filtered, $opts);

        my $data = { 'arpsponge.state-table' => $ip_table };

        if ($opts->{format} eq 'json') {
            print_output($JSON_OBJ->encode($data));
        }
        else {
            print_output($YAML_OBJ->dump_string($data));
        }
        return \%count;
    }

    my @output;
    if ($$opts{header} // 1 && !$$opts{H}) {
        push @output, [
            "%-17s %-12s %7s %12s %7s\n",
            "# IP", "State", "Queue", "Rate (q/min)", "Updated"
        ];
    }

    for my $info (@filtered) {
        push @output, [
            "%-17s %-12s %7d %8.3f     %s\n",
            $$info{ip}, $$info{state}, $$info{queue}, $$info{rate},
            $$info{state_changed},
        ];
    }
    print_output(@output);
    return \%count;
}

# ($opts, $raw, $records, $tag_fmt) =
#       shared_show_arp_ip($conn, $command, $args);
#
#   Executes the specified command and parses the result, translating
#   hex strings to ip and mac addresses where necessary.
#
#   Parameters:
#       $conn       connection handle
#       $command    base command to execute
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
    my ($conn, $command, $args) = @_;

    my $opts = $args->{-options};

    $opts->{format} = check_output_format($opts) or return;

    my $reply = '';
    if ($args->{'ip'}) {
        my $arg_count = 0;
        $reply = expand_ip_run($args->{'ip'},
                    sub {
                        $arg_count++;
                        return check_send_command($conn, "$command $_[0]");
                    }
                );
    }
    else {
        $reply = check_send_command($conn, $command);
    }

    return parse_server_reply($reply, $opts);
}

# ($opts, $reply, $records, $tag_fmt) = parse_server_reply($reply, \%opts, [, $key]);
#
#   Helper function for parsing replies from server.
#
#   Parameters:
#
#       $reply    - Raw reply from server.
#       $key      - Key to store records under. If not given, records will be
#                   stored in an array.
#
#   Returns:
#
#       $opts     - The input $opts hash, but with default values filled in.
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

    return if !defined $reply;

    my @output;
    my $taglen = 0;
    for my $record (split(/\n\n/, $reply)) {
        my %info;
        for my $line (split("\n", $record)) {
            $line =~ /(?<k>.*?)=(?<v>.*)$/ or next;
            my ($k, $v) = @+{qw( k v )};
            if (my $type = $ATTR_TYPE{$k}) {
                if (my $cv = $TYPE_CONVERSION_MAP{$type}) {
                    if ($cv->{convert}) {
                        if (my $save_k = $cv->{save_raw}) {
                            $v = $cv->{convert_raw}->($v) if $cv->{convert_raw};
                            $info{sprintf($save_k, $k)} = $v;
                        }
                        $v = $cv->{convert}->($v);
                    }
                }
            }
            $taglen = length($k) if length($k) > $taglen;
            $info{$k} = $v;
        }

        push @output, \%info;
    }

    $taglen++;
    return ($opts, $reply, \@output, "%-${taglen}s ");
}

###############################################################################
# CLEAR commands
###############################################################################

# cmd: clear ip
sub cmd_clear_ip {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

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
sub cmd_clear_arp {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

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
sub cmd_probe {
    my ($conn, $parsed, $args) = @_;

    my $ip = $args->{'ip'};

    my $opts = $args->{-options};

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

    my $raw = check_send_command($conn, $command, $arg) or return;

    DEBUG "do_set_generic: reply=<$raw>";

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    ($old, my $cv) = convert_attr_value($type, $old);
    ($new) = convert_attr_value($type, $new);

    $fmt = $cv->{fmt};

    return print_output(sprintf("%s changed from $fmt to $fmt%s",
                                $name, $old, $new, $unit));
}

# cmd: set queuedepth
sub cmd_set_queuedepth {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'queuedepth',
                   -val     => $args->{'num'},
                   -options => $args->{-options},
                   -type    => 'int');
}

# cmd: set arp-update-flags
sub cmd_set_arp_update_flags {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'arp_update_flags',
                   -val     => $args->{'flags'},
                   -options => $args->{-options},
                   -type    => 'arp-update-flags');
}

# cmd: set log-level
sub cmd_set_log_level {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'log_level',
                   -val     => $args->{'level'},
                   -options => $args->{-options},
                   -type    => 'log-level');
}

# cmd: set log-mask
sub cmd_set_log_mask {
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
sub cmd_set_max_pending {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max_pending',
                   -val     => $args->{'num'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'integer');
}

# cmd: set max_rate
sub cmd_set_max_rate {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'max_rate',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/min',
                   -type    => 'float');
}

# cmd: set learning
sub cmd_set_learning {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'learning',
                   -val     => $args->{'secs'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'int');
}

# cmd: set flood_protection
sub cmd_set_flood_protection {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'flood_protection',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/sec',
                   -type    => 'float');
}

# cmd: set proberate
sub cmd_set_proberate {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'proberate',
                   -val     => $args->{'rate'},
                   -options => $args->{-options},
                   -unit    => ' q/sec',
                   -type    => 'float');
}

# cmd: set dummy
sub cmd_set_dummy {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'dummy',
                   -val     => $args->{'bool'},
                   -options => $args->{-options},
                   -type    => 'bool');
}

# cmd: set passive
sub cmd_set_passive {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'passive',
                   -command => 'set_passive_mode',
                   -val     => $args->{'bool'},
                   -options => $args->{-options},
                   -type    => 'bool');
}

# cmd: set static
sub cmd_set_static {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'static',
                   -command => 'set_static_mode',
                   -val     => $args->{'bool'},
                   -options => $args->{-options},
                   -type    => 'bool');
}

# cmd: set sweep period
sub cmd_set_sweep_period {
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
sub cmd_set_sweep_age {
    my ($conn, $parsed, $args) = @_;

    do_set_generic(-conn    => $conn,
                   -name    => 'sweep age',
                   -val     => $args->{'secs'},
                   -options => $args->{-options},
                   -unit    => ' secs',
                   -type    => 'int');
}

# cmd: set sweep_skip_alive
sub cmd_set_sweep_skip_alive {
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

    my @command_args = ($command, $ip);
    push(@command_args, $arg) if defined $arg;
    my $raw = check_send_command($conn, @command_args) or return;

    my ($opts, $reply, $output, $tag) = parse_server_reply($raw);
    my $old = $output->[0]->{old};
    my $new = $output->[0]->{new};

    my $fmt = '%s';
    if ($type eq 'boolean') {
        $old = bool2str($old);
        $new = bool2str($new);
    }
    elsif ($type eq 'int') {
        $fmt = '%d';
    }
    elsif ($type eq 'float') {
        $fmt = '%0.2f';
    }
    return print_output(sprintf("%s: %s changed from $fmt to $fmt%s",
                                $output->[0]->{ip},
                                $name, $old, $new, $unit));
}

# cmd: set ip pending
sub cmd_set_ip_pending {
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
sub cmd_set_ip_dead {
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

# cmd: set ip static
sub cmd_set_ip_static {
    my ($conn, $parsed, $args) = @_;

    return expand_ip_run($args->{'ip'},
        sub {
            do_set_ip_generic(-conn    => $conn,
                      -command => 'set_static',
                      -name    => 'state',
                      -ip      => hex2ip($_[0]),
                      -options => $args->{-options});
        }
    );
}

# cmd: sponge
sub cmd_sponge { &cmd_set_ip_dead }

# cmd: unsponge
sub cmd_unsponge { &cmd_set_ip_alive }

# cmd: set ip alive
sub cmd_set_ip_alive {
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
sub cmd_set_ip_mac {
    my ($conn, $parsed, $args) = @_;

    DEBUG "set ip $$args{ip} mac $$args{mac}\n";
    return cmd_set_ip_alive($conn, $parsed, $args);
}

###############################################################################
# STATUS command
###############################################################################

sub do_show_status {
    my ($conn, $args) = @_;

    my $opts = $args->{-options};
    $opts->{format} = check_output_format($opts) or return;

    my ($info, $reply, $tag) = get_status($conn, $opts);
    return if ! defined $info;

    if ($opts->{format} eq 'raw') {
        return print_output($reply);
    }

    if ($opts->{format} ne 'native') {
        delete @{$info}{grep { /^(?:hex|raw)_/ } keys %$info};
        delete @{$info}{grep { /^tm_/ } keys %$info} if !$opts->{extended};

        my $data = { 'arpsponge.status' => $info };
        return print_output(
            $opts->{format} eq 'json'
                ? $JSON_OBJ->encode($data)
                : $YAML_OBJ->dump_string($data)
        );
    }

    return print_output(
        [ "$tag%s\n", 'id:', $$info{id} ],
        [ "$tag%d\n", 'pid:', $$info{pid} ],
        [ "$tag%s\n", 'version:', $$info{version} ],
        [ "$tag%s [%d]\n", 'date:', $$info{date}, $$info{tm_date} ],
        [ "$tag%s [%d]\n", 'started:', $$info{started}, $$info{tm_started} ],
        [ "$tag%s/%d\n", 'network:', $$info{network}, $$info{prefixlen} ],
        [ "$tag%s\n", 'interface:', $$info{interface} ],
        [ "$tag%s\n", 'IP:', $$info{ip} ],
        [ "$tag%s\n", 'MAC:', $$info{mac} ],
        [ "$tag%s", 'next sweep:', $$info{next_sweep} ],
        ($$info{tm_next_sweep} ?
            sprintf(" (in %d secs) [%d]",
                $$info{tm_next_sweep}-$$info{tm_date},
                $$info{tm_next_sweep})
            : ''
        ),
        "\n",
    );
}

# $bool = get_static_mode();
sub get_static_mode {
    my $conn = shift;
    my ($opts, $reply, $output, $tag) = get_param($conn);
    return $output->{raw_static};
}

# $flags_integer = get_arp_update_flags();
sub get_arp_update_flags {
    my $conn = shift;
    my ($opts, $reply, $output, $tag) = get_param($conn);
    return $output->{raw_arp_update_flags};
}

# $log_mask_integer = get_log_mask();
sub get_log_mask {
    my $conn = shift;
    my ($opts, $reply, $output, $tag) = get_param($conn);
    return $output->{raw_log_mask};
}

sub do_show_parameters {
    my ($conn, $args) = @_;
    my $format = 1;

    my $opts = $args->{-options};
    $opts->{format} = check_output_format($opts) or return;

    ($opts, my $reply, my $info, my $tag) = get_param($conn, $opts);

    if ($opts->{format} eq 'raw') {
        return print_output($reply);
    }

    if ($opts->{format} ne 'native') {
        delete @{$info}{grep { /^(?:hex|raw)_/ } keys %$info};
        delete @{$info}{grep { /^tm_/ } keys %$info} if !$opts->{extended};

        my $data = { 'arpsponge.parameters' => $info };
        return print_output(
            $opts->{format} eq 'json'
                ? $JSON_OBJ->encode($data)
                : $YAML_OBJ->dump_string($data)
        );
    }

    return print_output(
        [ "$tag= %d\n"          => 'queuedepth',    $$info{queue_depth} ],
        [ "$tag= %0.2f q/min\n" => 'max_rate',      $$info{max_rate} ],
        [ "$tag= %0.2f q/sec\n" => 'flood_protection',
            $$info{flood_protection} ],
        [ "$tag= %d\n"          => 'max_pending',   $$info{max_pending} ],
        [ "$tag= %d secs\n"     => 'sweep_period',  $$info{sweep_period} ],
        [ "$tag= %d secs\n"     => 'sweep_age',     $$info{sweep_age} ],
        [ "$tag= %s\n"          => 'sweep_skip_alive',
            bool2str($$info{sweep_skip_alive}) ],
        [ "$tag= %d pkts/sec\n" => 'proberate',     $$info{proberate} ],
        [ "$tag= %s\n"          => 'learning',
            bool2str($$info{learning}, " ($$info{learning} secs)") ],
        [ "$tag= %s\n"          => 'dummy',         bool2str($$info{dummy}) ],
        [ "$tag= %s\n"          => 'passive',       bool2str($$info{passive}) ],
        [ "$tag= %s\n"          => 'static',        bool2str($$info{static}) ],
        [ "$tag= %s\n"          => 'arp_update_flags',
            $$info{arp_update_flags} ],
        [ "$tag= %s\n"          => 'log_level',     $$info{log_level} ],
        [ "$tag= %s\n"          => 'log_mask',      $$info{log_mask} ],
    );
}

# ($opts, $reply, $output, $tag_fmt) = get_param($conn, \%opts);
#
#   Helper function for status. Combines check_send_command with
#   parse_server_reply.
#
sub get_param {
    my ($conn, $opts) = @_;

    return if !$conn;

    my $raw = check_send_command($conn, 'get_param') or return;

    ($opts, my $reply, my $output, my $tag) = parse_server_reply($raw, $opts);

    return ($opts, $reply, $output->[0], $tag);
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

    my ($records, $tag_fmt);
    ($opts, $reply, $records, $tag_fmt) = parse_server_reply($reply, $opts);
    return if ! defined $records;
    return ($records->[0], $reply, $tag_fmt);
}

# cmd: dump status [$file]
sub cmd_dump_status {
    my ($conn, $parsed, $args) = @_;

    my $fname = $args->{'file'};

    if (!defined $fname) {
        my ($status, $raw_status) = get_status($conn);
        return if !defined $status;

        if (keys %{$args->{-options}}) {
            return print_error("dump status without file name accepts no options");
        }

        # Old-style dumping (by sending a signal to the daemon).
        my $pid = $status->{'pid'};
        if (!$pid) {
            verbose("ERROR\n");
            return print_error("** no running daemon found");
        }
        verbose("sending USR1 signal to $pid: ");
        if (kill 'USR1', $status->{'pid'}) {
            verbose("ok\n");
            return print_output("process $pid signalled");
        }
        verbose("ERROR\n");
        return print_error("** cannot signal $pid: $!");
    }

    # Dump to a file.
    $args->{-options}{format} = check_output_format($args->{-options}) or return;

    my $output_str = prepare_dump_status_output($conn, $args);
    return if !defined $output_str;

    my $out_fh;
    if ($fname eq '-') {
        open $out_fh, '>&', *STDOUT
            or return print_error("cannot DUP stdout: $!");
    }
    else {
        open $out_fh, '>', $fname
            or return print_error("cannot write to $fname: $!");
    }

    print_output_fh($out_fh, $output_str);
    $out_fh->autoflush(1);

    if (-f $out_fh) {
        my $size = ($out_fh->stat)[7];
        print_output("$size bytes written to $fname");
    }
    return $out_fh->close;
}

sub prepare_dump_status_output {
    my ($conn, $args) = @_;

    my $opts = $args->{-options};

    if ($opts->{format} eq 'native') {
         return format_native_status($conn, $args);
    }

    my ($status, $raw_status) = get_status($conn, $opts);
    return if !defined $status;

    (undef, my $raw_param, my $param, undef) = get_param($conn, $opts);
    return if !defined $param;

    my (undef, $raw_ip_state, $ip_output, undef) =
        shared_show_arp_ip($conn, 'get_ip');
    return if !defined $ip_output;

    my (undef, $raw_arp_state, $arp_output, undef) =
        shared_show_arp_ip($conn, 'get_arp');
    return if !defined $arp_output;

    if ($opts->{format} eq 'raw') {
        return "$raw_status\n$raw_param\n$raw_ip_state\n$raw_arp_state";
    }

    for my $hash ($status, $param) {
        delete @{$hash}{grep { /^(?:hex|raw)_/ } keys %$hash};
        delete @{$hash}{grep { /^tm_/ } keys %$hash} if !$opts->{extended};
    }

    my $ip_table = convert_ip_output_for_export($ip_output, $opts);
    my $arp_table = convert_arp_output_for_export($arp_output, $opts);

    my $data = {
        'arpsponge.status' => $status,
        'arpsponge.parameters' => $param,
        'arpsponge.state-table' => $ip_table,
        'arpsponge.arp-table' => $arp_table,
    };

    if ($opts->{format} eq 'json') {
        return $JSON_OBJ->encode($data);
    }

    return $YAML_OBJ->dump_string($data);
}

sub convert_ip_output_for_export {
    my ($ip_output, $opts) = @_;
    my %ip_table;

    for my $entry (@$ip_output) {
        my $ip = delete $entry->{ip};
        delete @{$entry}{grep { /^(?:hex|raw)_/ } keys %$entry};
        delete @{$entry}{grep { /^tm_/ } keys %$entry} if !$opts->{extended};
        $ip_table{$ip} = $entry;
    }
    return \%ip_table;
}

sub convert_arp_output_for_export {
    my ($arp_output, $opts) = @_;
    my %arp_table;
    for my $entry (@$arp_output) {
        my $ip = delete $entry->{ip};
        delete @{$entry}{grep { /^(?:hex|raw)_/ } keys %$entry};
        delete @{$entry}{grep { /^tm_/ } keys %$entry} if !$opts->{extended};
        $arp_table{$ip} = $entry;
    }
    return \%arp_table;
}

sub format_native_status {
    my ($conn, $args) = @_;

    my $out_buf = '';
    open my $out_buf_fh, '>', \$out_buf;
    my $oldhandle = select $out_buf_fh;
    {
        print_output("<STATUS>");
        do_show_status($conn, $args);
        print_output("</STATUS>");
        print_output("\n<PARAM>");
        do_show_parameters($conn, $args);
        print_output("</PARAM>");
        print_output("\n<STATE>");
        my $count = do_show_ip($conn, $args);
        print_output("</STATE>");
        print_output("\n<ARP-TABLE>");
        my $arp_count = do_show_arp($conn, $args);
        print_output("</ARP-TABLE>");
        print_output(
                "\nalive=$$count{ALIVE}",
                " dead=$$count{DEAD}",
                " pending=$$count{PENDING}",
                " ARP_entries=$arp_count",
        );
    }
    select $oldhandle;
    return $out_buf;
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
sub cmd_load_status {
    my ($conn, $parsed, $args) = @_;

    my $opts = $args->{-options};

    my $fname = $args->{'file'};

    open my $fh, '<', $fname
        or return print_error("cannot read $fname: $!");

    my $mtime = ($fh->stat)[9];

    if ($mtime + $MAX_DUMP_AGE < time) {
        print_error("** status file $fname\n",
                    "** timestamp [", format_time($mtime), "]",
                    " older than $MAX_DUMP_AGE seconds");

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

    verbose("getting current state table...\n");

    my ($curr_state_table, $curr_stats) = get_state_table($conn);
    return if !$curr_state_table;

    verbose("reading state table(s) from $fname...\n");
    my ($state_table, $arp_table) = read_state_table_from_file($fname, $fh);
    return if !$state_table;


    verbose("checking and setting states\n");

    my $is_static_mode = get_static_mode($conn);

    my %ip_stats   = (ALIVE=>0, STATIC=>0, DEAD=>0,
                      TOTAL=>0, PENDING=>0, CHANGED=>0);

    for my $ip (sort { $a cmp $b } keys %$state_table) {
        $ip_stats{'TOTAL'}++;
        $ip_stats{$$state_table{$ip}}++;
        $$curr_state_table{$ip} //= 'NONE';
        if ($$curr_state_table{$ip} eq $$state_table{$ip}) {
            #verbose "no change ", hex2ip($ip), "\n";
            next;
        }
        foreach ($$state_table{$ip}) {
            if ($_ eq 'ALIVE') {
                $ip_stats{'CHANGED'}++;
                do_set_ip_generic(
                    -conn    => $conn,
                    -command => 'set_alive',
                    -name    => 'state',
                    -val     => $$arp_table{$ip},
                    -ip      => hex2ip($ip),
                    -options => [],
                )
            }
            elsif ($_ eq 'STATIC') {
                $ip_stats{'CHANGED'}++;
                check_send_command($conn, "set_static $ip");
            }
            elsif ($_ eq 'DEAD') {
                $ip_stats{'CHANGED'}++;
                if ($is_static_mode) {
                    check_send_command($conn, "set_dead $ip");
                }
                else {
                    check_send_command($conn, "clear_ip $ip");
                }
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

sub read_state_table_from_file {
    my ($fname, $fh) = @_;

    if (!$fh) {
        open $fh, '<', $fname or return print_error("cannot read $fname: $!");
    }

    my $input = do {
        local($/) = undef;
        $fh->getline;
    };

    if ($input =~ /^\s*<STATUS>\s*\n/s) {
        return parse_classic_status($input);
    }
    if ($input =~ /^\s*\{/s) {
        return parse_json_status($input, $fname);
    }
    if ($input =~ /^(\s*(?:#[^\n]*)?\n)*---\n/) {
        return parse_yaml_status($input, $fname);
    }

    return print_error("$fname: unknown format");
}

sub parse_json_status {
    my ($input, $fname) = @_;

    my $data = eval { $JSON_OBJ->decode($input) };

    if (my $err = $@) {
        chomp($err);
        $err =~ s/(, at character offset \d+.*?) at .*? line \d+\.$/$1/;
        my ($off) = $err =~ /, at character offset (\d+)/;
        my $good_input = substr($input, 0, $off);
        my $newlines = $good_input =~ tr/\n//;
        my $lineno = $newlines + 1;
        my $col = $off - length($good_input) + 1;
        $err =~ s/, at character offset \d+/, at line $lineno, column $col/;
        $err .= "\n   Line: $lineno\n   Column: $col";
        return print_error("JSON Error: $err\n\n** cannot load '$fname'");
    }

    return (
        expand_state_table(
            $data->{"arpsponge.state-table"},
            "$fname/arpsponge.state-table",
        ),
        expand_state_table(
            $data->{"arpsponge.arp-table"},
            "$fname/arpsponge.arp-table",
        ),
    );
}

sub parse_yaml_status {
    my ($input, $fname) = @_;

    my $data = eval { $YAML_OBJ->load_string($input) };

    if (my $err = $@) {
        $err =~ s/at \S+ line \d+\.$//;
        $err =~ s/\n+$//;
        return print_error("$err\n\n** cannot load '$fname'\n");
    }
    return (
        expand_state_table(
            $data->{"arpsponge.state-table"},
            "$fname/arpsponge.state-table"
        ),
        expand_state_table(
            $data->{"arpsponge.arp-table"},
            "$fname/arpsponge.state-table"
        ),
    );
}

sub expand_state_table {
    my ($table, $varname) = @_;

    return {} if !$table;

    # The keys in the state table can be IP addresses or IP ranges.
    # We should sort by least specific -> most specific first.
    my @chunks_by_size;
    while (my ($key, $val) = each %$table) {
        my $ip_list = expand_ip_range($key, $varname) or return;

        if (ref $val) {
            if (reftype $val ne 'HASH') {
                return print_error(
                    "$varname: '$key' should map to a HASH or a SCALAR\n"
                );
            }
            $val = $val->{state} // $val->{mac};
        }

        for my $chunk (@$ip_list) {
            my $chunk_size = $chunk->[1] - $chunk->[0] + 1;
            push @$chunk, $val;
            push @{$chunks_by_size[$chunk_size]}, $chunk;
        }
    }
    my %new_table;
    for my $chunk_list (reverse grep { defined } @chunks_by_size) {
        for my $chunk (@$chunk_list) {
            my ($lo, $hi, $lo_s, $hi_s, $val) = @$chunk;
            for (my $ip_i = $lo; $ip_i <= $hi; $ip_i++) {
                $new_table{sprintf("%08x", $ip_i)} = $val;
            }
        }
    }
    return \%new_table;
}

sub parse_classic_status {
    my ($input) = @_;
    local($_);

    my $parse_state = 'none';
    my %state_table = ();
    my %arp_table   = ();

    foreach (split(/\n/, $input)) {
        if (/^<\/[\w-]+>$/) {
            $parse_state = 'none';
            next;
        }
        if (/^<STATE>$/) {
            $parse_state = 'state';
            next;
        }
        if (/^<ARP-TABLE>$/) {
            $parse_state = 'arp';
            next;
        }

        if ($parse_state eq 'state' &&
            /^([\d\.]+) \s+ ([A-Z]+) \s+ \d+ \s+ \d+\.\d+ \s+ \S+[\@\s]\S+$/x) {
            my $ip = ip2hex($1);
            $state_table{$ip} = $2;
            next;
        }

        if ($parse_state eq 'arp' &&
                /^([a-f\d\:]+) \s+ ([\d\.]+) \s+ \d+ \s+ \S+[\@\s]\S+$/x) {
            my ($mac, $ip) = (mac2hex($1), ip2hex($2));
            if (exists $state_table{$ip} && $state_table{$ip} eq 'ALIVE') {
                $arp_table{$ip} = $mac;
            }
            next;
        }
    }
    return (\%state_table, \%arp_table);
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
            die "$FindBin::Script: ",
                "--socket and --interface are mutually exclusive\n";
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
            my $err = "$FindBin::Script: "
                    . "cannot find sponge instance in $rundir\n";
            if ($opt_test) {
                warn "** WARN: $err";
            }
            else {
                die $err;
            }
        }

    }

    $M6::ArpSponge::ReadLine::TYPES{'ip-range'} = {
            'verify'   => \&check_ip_range_arg,
            'complete' => \&complete_ip_range,
        };
    $M6::ArpSponge::ReadLine::TYPES{'ip-filter'} = {
            'verify'   => \&check_ip_filter_arg,
            'complete' => \&complete_ip_filter,
        };
    $M6::ArpSponge::ReadLine::TYPES{'ip-any'} = {
            'verify'   => \&check_ip_any_arg,
            'complete' => \&complete_ip_any,
        };
    $M6::ArpSponge::ReadLine::TYPES{'arp-update-flags'} = {
            'verify'   => \&check_arp_update_flags,
            'complete' => \&complete_arp_update_flags,
        };
    $M6::ArpSponge::ReadLine::TYPES{'log-level'} = {
            'verify'   => \&check_log_level,
            'complete' => \&complete_log_level,
        };
    $M6::ArpSponge::ReadLine::TYPES{'log-mask'} = {
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

  asctl -c show status --json
  asctl -- show status --json
  asctl 'show status --json'

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

Load IP/ARP state from I<file>. The I<file> should be in one of three formats:

=over

=item * B<arpsponge dump format>

A dump file previously created by the daemon's dump facility
(see also "L<dump status|/dump status>" above).

=item * B<YAML>

A YAML file with the following structure:

    ---
    arpsponge.state-table:
        IP1: STATE
        IP2:
            state: STATE
            ...
        ...

    arpsponge.arp-table:
        IP: MAC
        IP:
            mac: MAC
            ...
        ...

=item * B<JSON>

A JSON file with the following structure:

    {
        "arpsponge.state-table" : {
            "IP1" : "STATE",
            "IP2" : {
                "state" : "STATE",
                ...
            }
            ...
        },
        "arpsponge.arp-table" : {
            "IP1" : "MAC",
            "IP2" : {
                "mac" : "MAC",
                ...
            }
            ...
        }
    }

=back

Note that the table entries can either map an IP key to a single
(I<STATE> or I<MAC>) string or to a hash with a C<state> or C<mac>
key. The former format is more convenient for manually maintained
files, the latter maintains full compatibility with the B<asctl>
generated dump files.

For the YAML and JSON formats, I<IP> can be a single IP address
or a range. Examples:

    # Single address:
        192.168.0.1

    # CIDR notation:
        192.168.0.0/24

    # Range notation:
        192.168.0.0-192.168.0.255

The I<STATE> is one of C<STATIC>, C<DEAD>, C<ALIVE>, C<PENDING(N)>,
where I<N> is a non-negative integer.

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

=over

=item *

In static mode, execute:

  set ip 91.200.17.3 dead

=item *

In non-static mode, execute:

  clear ip 91.200.17.3

That is, the daemon is told to clear the state information, so the next
ARP for that address will put it in a C<PENDING(0)> state.

=back

The handling of C<DEAD> state information in the dump file allows us to load
relatively old data, without resulting in sponging of active addresses, while
still allowing quick discovery of the still-dead addresses.

=item B<STATIC>

Execute:

  set ip 91.200.17.3 static


=item B<PENDING>(I<N>)

Ignored.

=back

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

=item B<--format>={B<native>|I<raw>|I<json>|I<yaml>}

Select the output format:

=over

=item C<native>

Produce human-readable output (typically in table format).
This is the default.

=item C<raw>

Print the raw response from the L<arpsponge> daemon.

=item C<json>, C<yaml>

JSON and YAML formats, resp.

Date values are presented as ISO-8601 date strings.

Example:

  {
    "arpsponge.status" : {
      "id"              : "arpsponge",
      "pid"             : 30396,
      "version"         : "3.22~1.gbp512f74",
      "date"            : "2021-04-06T15:16:14+0200",
      "started"         : "2021-03-30T16:47:25+0200",
      "network"         : "192.168.122.0",
      "interface"       : "enp1s0",
      "ip"              : "192.168.122.234",
      "prefixlen"       : 24,
      "mac"             : "52:54:00:1e:a5:c2",
      "next_sweep"      : "never",
    }
  }

  ---
  arpsponge.status:
    id            : arpsponge
    pid           : 30396
    version       : 3.22~1.gbp512f74
    date          : 2021-04-06T15: 18:35+0200
    started       : 2021-03-30T16:47:25+0200
    network       : 192.168.122.0
    interface     : enp1s0
    ip            : 192.168.122.234
    prefixlen     : 24
    mac           : 52:54:00:1e:a5:c2
    next_sweep    : never

If C<--extended> is specified as well, the "epoch" values (seconds
since midnight 1 January 1970), are included as well, with a C<tm_>
prefix:

  {
    "arpsponge.status" : {
      ...
      "tm_date"         : 1617714974,
      "tm_started"      : 1617115645,
      "tm_next_sweep"   : 0
    }
  }

  ---
  arpsponge.status:
    ...
    tm_date       : 1617715115
    tm_started    : 1617115645
    tm_next_sweep : 0

=back

=item B<--raw>, B<--json>, B<--yaml>
X<--raw>X<--json>X<--yaml>

Shortcuts for C<--format=X>.

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

Copyright 2011-2021, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
