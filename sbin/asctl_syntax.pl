#!/usr/bin/perl

use 5.014;
use warnings;
use Term::CLI;
use Term::CLI::L10N;
use NetAddr::IP;
use Data::Dumper;

use M6::ArpSponge::Util qw( ip2int );
use M6::ArpSponge::Asctl::Arg_IP_Range;
use M6::ArpSponge::Asctl::Arg_IP_Filter;

my $IP_NETWORK = NetAddr::IP->new( '127.0.0.0/24' );
my $TERM;

my $opt_verbose = 0;
my $opt_debug   = 1;

sub verbose(@) { print @_ if $opt_verbose; }
sub DEBUG(@)   { print_error(@_) if $opt_debug; }

sub print_error_cond {
    my ($cond, @args) = @_;
    my $out = join('', @args);
    chomp($out);
    if ($cond) {
        say STDERR $out;
        $TERM && $TERM->term->on_new_line();
    }
    return;
}

sub print_error {
    return print_error_cond(1, @_);
}

#############################################################################

#############################################################################

$TERM = Term::CLI->new(
    name => 'asctl',
    prompt => 'asctl> ',
    skip => qr/^\s*(?:#.*)$/,
);

$TERM->term->Attribs->{sort_completion_matches} = 0;

#
# Callback: noop
#
sub command_noop {
    my ($cmd, %args) = @_;
    return %args if $args{status} < 0;
    my @cmd_path = @{$args{command_path}};
    my $app = (shift @cmd_path)->name;
    my $cmd_name = join(' ', map { $_->name } @cmd_path);
    say "($app) $cmd_name", map { " <$_>" } @{$args{arguments}};
    return %args;
}

my @commands;

#
# Command: quit
#
push @commands, Term::CLI::Command->new(
    name => 'quit',
    summary => 'disconnect and quit',
    description => 'Disconnect and quit.',
    callback  => \&command_quit,
);

push @commands, Term::CLI::Command->new(
    name => 'exit',
    summary => 'alias for C<quit>',
    description => 'Disconnect and quit.',
    callback  => \&command_quit,
);

#
# Command: ping
#
push @commands, Term::CLI::Command->new(
    name => 'ping',
    summary => '"ping" the daemon',
    description => 'Ping the daemon, display response RTT.',
    callback  => \&command_ping,
    arguments => [
        Term::CLI::Argument::Number::Int->new(
            name => 'count',
            min => 1,
            min_occur => 0,
        ),
        Term::CLI::Argument::Number::Float->new(
            name => 'delay',
            min => 0.01,
            min_occur => 0,
        ),
    ],
);


#
# Command: clear
#
push @commands, Term::CLI::Command->new(
    name => 'clear',
    summary => 'clear IP state and ARP entries',
    description => 'Clear IP state and ARP entries from their respective tables.',
    commands => [
        Term::CLI::Command->new( name => 'ip',
            summary => 'clear state table for given IP address(es)',
            description => 'Clear state table for given IP address(es).',
            callback => \&command_clear_ip,
            arguments => [
                M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                    name => 'IP',
                    max_occur => 0,
                    network_prefix => $IP_NETWORK,
                ),
            ],
        ),
        Term::CLI::Command->new( name => 'arp',
            summary => 'clear ARP table for given IP address(es)',
            description => 'Clear ARP table for given IP address(es).',
            callback => \&command_clear_arp,
            arguments => [
                M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                    name => 'IP',
                    max_occur => 0,
                    network_prefix => $IP_NETWORK,
                ),
            ],
        ),
    ],
);


#
# command: load status
#
push @commands, Term::CLI::Command->new(
    name => 'load',
    summary => 'load IP/ARP state from file',
    description => 'Load IP/ARP state from a dump file.',
    commands => [
        Term::CLI::Command->new( name => 'status',
            summary => 'load IP/ARP state from file',
            description => 'Load IP/ARP state from a dump file.',
            callback => \&command_load_status,
            arguments => [
                Term::CLI::Argument::Filename->new(
                    name => 'file',
                    occur => 1,
                ),
            ],
        ),
    ],
);

#
# command: dump status
#
{
    my $summary = 'dump IP/ARP state to file';
    my $description =
        'Either dump IP/ARP state to I<file>, or signal the daemon to'
        .' dump to its "standard" location (user needs sufficient'
        .' privileges to send signals to the damon process).'
        ;

    push @commands, Term::CLI::Command->new(
        name => 'dump',
        summary => $summary,
        description => $description,
        commands => [
            Term::CLI::Command->new( name => 'status',
                summary => $summary,
                description => $description,
                callback => \&command_dump_status,
                arguments => [
                    Term::CLI::Argument::Filename->new(
                        name => 'file',
                        min_occur => 0,
                    ),
                ],
            ),
        ],
    );
}

#
# command: probe
#
{
    my $summary = 'send ARP requests for given IP address(es)';
    my $description =
        qq{Send ARP broadcast requests for the given IP address(es).\n}
        .qq{This only sends the requests, it doesn't wait for any replies:\n}
        .qq{these will be caught by the regular sponge operation.}
        ;

    push @commands, Term::CLI::Command->new(
        name => 'probe',
        summary => $summary,
        description => $description,
        callback => \&command_probe,
        options => [ 'delay|d=f', 'count|c=i' ],
        arguments => [
            M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                name => 'IP',
                max_occur => 0,
                network_prefix => $IP_NETWORK,
            ),
        ],
    );
}

#
# command: show
#
{
    my @show_sub_commands;

    {
        my $summary = 'show ARP table for given IP address(es)';
        my $description =
            qq{Show ARP table entries for the given IP address(es).\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'arp',
            summary => $summary,
            description => $description,
            callback => \&command_show_arp,
            arguments => [
                M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                    name => 'IP',
                    occur => 0,
                    network_prefix => $IP_NETWORK,
                ),
            ],
        );
    }

    {
        my $summary = 'show state table for given IP address(es)';
        my $description =
            qq{Show state table for the given IP address(es).\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'ip',
            summary => $summary,
            description => $description,
            callback => \&command_show_ip,
            arguments => [
                M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                    name => 'IP',
                    occur => 0,
                    network_prefix => $IP_NETWORK,
                ),
            ],
        );
    }

    {
        my $summary = 'show arpsponge daemon parameters';
        my $description =
            qq{Show configuration parameters of the running arpsponge daemon.\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'parameters',
            summary => $summary,
            description => $description,
            callback => \&command_show_parameters,
        );
    }

    {
        my $summary = 'show version information';
        my $description =
            qq{Show B<asctl> version information.\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'version',
            summary => $summary,
            description => $description,
            callback => \&command_show_version,
        );
    }

    {
        my $summary = 'show arpsponge status summary';
        my $description =
            qq{Show a summary of the status of the running arpsponge daemon.\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'status',
            summary => $summary,
            description => $description,
            callback => \&command_show_status,
        );
    }

    {
        my $summary = 'show uptime';
        my $description =
            qq{Show B<arpsponge> uptime.\n};
            ;

        push @show_sub_commands, Term::CLI::Command->new(
            name => 'uptime',
            summary => $summary,
            description => $description,
            callback => \&command_show_version,
        );
    }

    push @commands, Term::CLI::Command->new(
        name => 'show',
        usage => 'B<show> I<item>',
        summary => 'show various information',
        description => 'Show IP/ARP state, log, and operational parameters.',
        commands => \@show_sub_commands,
    );
}

#
# command: sponge
#
{
    my $summary = 'sponge given IP address(es)';
    my $description =
        qq{Sponge the given IP address(es); see also C<set ip dead>.}
        ;

    push @commands, Term::CLI::Command->new(
        name        => 'sponge',
        summary     => $summary,
        description => $description,
        callback    => \&command_sponge,
        arguments   => [
            M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                name => 'IP',
                max_occur => 0,
                network_prefix => $IP_NETWORK,
            ),
        ],
    );
}

#
# command: unsponge
#
{
    my $summary = 'unsponge given IP address(es)';
    my $description =
        qq{Unsponge the given IP address(es); see also C<set ip alive>.}
        ;

    push @commands, Term::CLI::Command->new(
        name        => 'unsponge',
        summary     => $summary,
        description => $description,
        callback    => \&command_unsponge,
        arguments   => [
            M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                name => 'IP',
                max_occur => 0,
                network_prefix => $IP_NETWORK,
            ),
        ],
    );
}

#
# command: inform X about Y
#
{
    my $summary = 'update ARP entry for I<src_list> at I<dst_list>';
    my $description = q{}
        .qq{Tell the devices at I<dst_list> to update their ARP cache\n}
        .qq{entries for I<src_list> with the MAC addresses that are in\n}
        .qq{the arpsponge's own table.\n}
        .qq{\n}
        .qq{The method by which the I<dst_list> entities are informed is\n}
        .qq{determined by the value of the C<arp_update_flags> configuration\n}
        .qq{setting.\n}
        .qq{\n}
        .qq{The B<asctl> program will expand the I<src_list> and I<dst_list>\n}
        .qq{arguments and send update packets for each I<src> and I<dst>\n}
        .qq{pair. This implies a quadratic complexity; that is, if you have\n}
        .qq{200 "alive" IP addresses in your table then B<asctl> will\n}
        .qq{the arpsponge to send S<200 x 199 = 39,800 updates.>\n}
        .qq{If C<arp_update_flags> is also set to C<all> (i.e.\n}
        .qq{C<reply,request,gratuitous>, then the arpsponge will end up\n}
        .qq{sending S<39,800 x 3 = 119,400 packets.>\n}
        .qq{\n}
        .qq{B<Options:>\n\n}
        .qq{=over\n\n}
        .qq{=item B<--delay>=I<secs>\n\n}
        .qq{Delay I<secs> seconds between subsequent "inform" steps. I<secs>\n}
        .qq{can be a fractional number (e.g. C<0.1>.\n}
        .qq{\n}
        .qq{Especially on large ranges of IP addresses, the delay can be\n}
        .qq{useful to avoid locking the arpsponge with many "inform" requests\n}
        .qq{as well as to avoid flooding connected stations with lots of\n}
        .qq{ARP traffic.\n}
        .qq{\n}
        .qq{=back\n\n}
        ;

    push @commands, Term::CLI::Command->new(
        name        => 'inform',
        summary     => $summary,
        description => $description,
        options     => [ 'delay|d=f' ],
        arguments   => [
            M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                name => 'dst_ip',
                occur => 1,
                network_prefix => $IP_NETWORK,
            ),
        ],
        commands    => [
            Term::CLI::Command->new(
                name        => 'about',
                summary     => $summary,
                description => $description,
                callback    => \&command_inform,
                arguments   => [
                    M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                        name => 'src_ip',
                        occur => 1,
                        network_prefix => $IP_NETWORK,
                    ),
                ],
            )
        ]
    );
}

#
# Command: help
#
push @commands, Term::CLI::Command::Help->new();

#
# REPL
#
$TERM->add_command(@commands);

while (defined (my $line = $TERM->readline)) {
    $TERM->execute($line);
}

print "\n";
execute_exit(0);

##############################################################################
# Command execution routines.
##############################################################################

sub command_quit {
    my ($cmd, %args) = @_;
    return %args if $args{status} < 0;
    execute_exit(0);
}

sub execute_exit {
    exit @_;
}


sub command_ping {
    my ($cmd, %args) = @_;
    return %args if $args{status} < 0;
    my ($count, $delay) = @{$args{arguments}};
    $count //= 1;
    $delay //= 1;
    say "ping count=$count delay=$delay";
    return %args;
}

sub command_clear_ip {
    my ($cmd, %args) = @_;

    return %args if $args{status} < 0;

    my @cmd_path = @{$args{command_path}};

    my $app = (shift @cmd_path)->name;

    my $cmd_name = join(' ', map { $_->name } @cmd_path);

    say "($app) $cmd_name";

    print Dumper($args{arguments});

    return %args;
}

sub command_clear_arp {
    return command_noop(@_);
}

sub command_load_status {
    return command_noop(@_);
}

sub command_dump_status {
    return command_noop(@_);
}

sub command_probe {
    return command_noop(@_);
}

sub command_show_arp {
    return command_noop(@_);
}

sub command_show_ip {
    return command_noop(@_);
}

sub command_show_parameters {
    return command_noop(@_);
}

sub command_show_status {
    return command_noop(@_);
}

sub command_show_uptime {
    return command_noop(@_);
}

sub command_show_version {
    return command_noop(@_);
}

sub command_sponge {
    return command_noop(@_);
}

sub command_unsponge {
    return command_noop(@_);
}

sub command_inform {
    return command_noop(@_);
}

__END__

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
