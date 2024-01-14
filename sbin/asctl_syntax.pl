#!/usr/bin/perl
#
use Modern::Perl;
use Term::CLI;
use Term::CLI::L10N;

package Arg::IP::Filter {
    use Moo;
    use Term::CLI::Util qw( is_prefix_str find_text_matches );

    extends 'Term::CLI::Argument';

    my @States = sort qw( all dead alive pending );

    sub complete {
        my ($self, $text, $state) = @_;

        if (!length $text) {
            return ('IP-ADDRESS', 'IP-RANGE', @States);
        }

        return find_text_matches( $text, \@States );
    }
}

my $term = Term::CLI->new(
    name => 'asctl',
    prompt => 'asctl> ',
    skip => qr/^\s*(?:#.*)$/,
);

$term->term->Attribs->{sort_completion_matches} = 0;

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
    callback  => \&command_exit,
);

sub command_exit {
    my ($cmd, %args) = @_;
    return %args if $args{status} < 0;
    execute_exit(0);
}

sub execute_exit {
    say "-- exit";
    exit @_;
}


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

sub command_ping {
    my ($cmd, %args) = @_;
    return %args if $args{status} < 0;
    my ($count, $delay) = @{$args{arguments}};
    $count //= 1;
    $delay //= 1;
    say "ping count=$count delay=$delay";
    return %args;
}


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
                #Term::CLI::Argument::String->new(
                Arg::IP::Filter->new(
                    name => 'IP',
                    max_occur => 0,
                ),
            ],
        ),
        Term::CLI::Command->new( name => 'arp',
            summary => 'clear ARP table for given IP address(es)',
            description => 'Clear ARP table for given IP address(es).',
            callback => \&command_clear_arp,
            arguments => [
                Term::CLI::Argument::String->new(
                    name => 'IP',
                    max_occur => 0,
                ),
            ],
        ),
    ],
);

sub command_clear_ip {
    return command_noop(@_);
}

sub command_clear_arp {
    return command_noop(@_);
}


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

sub command_load_status {
    return command_noop(@_);
}

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

sub command_dump_status {
    return command_noop(@_);
}

#
# command: probe
#
{
    my $summary = 'send ARP requests for given IP address(es)';
    my $description =
        qq{Send ARP broadcast requests for the given IP address(es).\n}
        .qq{This only sends the requests, it doesn't wait for any replies;\n}
        .qq{any replies will be caught by the regular sponge operation.}
        ;

    push @commands, Term::CLI::Command->new(
        name => 'probe',
        summary => $summary,
        description => $description,
        callback => \&command_probe,
        arguments => [
            Term::CLI::Argument::String->new(
                name => 'IP',
                max_occur => 0,
            ),
        ],
    );
}

sub command_probe {
    return command_noop(@_);
}


#
# command: show
#
{
    my @show_sub_commands;

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
                Term::CLI::Argument::String->new(
                    name => 'IP',
                    occur => 0,
                ),
            ],
        );
    }

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
                Term::CLI::Argument::String->new(
                    name => 'IP',
                    occur => 0,
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

    push @commands, Term::CLI::Command->new(
        name => 'show',
        summary => 'show various information',
        description => 'Show IP/ARP state, log, and operational parameters.',
        commands => \@show_sub_commands,
    );
}

sub command_show_ip {
    return command_noop(@_);
}

sub command_show_arp {
    return command_noop(@_);
}

sub command_show_parameters {
    return command_noop(@_);
}

sub command_show_status {
    return command_noop(@_);
}


#
# Command: help
#
push @commands, Term::CLI::Command::Help->new();

#
# REPL
#
$term->add_command(@commands);

while (defined (my $line = $term->readline)) {
    $term->execute($line);
}

print "\n";
execute_exit(0);

__END__

    'show ip $ip?'   => {
        '?'       => 'Show state table for given IP(s).',
        '$ip'     => { type=>'ip-filter' } },
    'show arp $ip?'  => {
        '?'       => 'Show ARP table for given IP(s).',
        '$ip'     => { type=>'ip-any'    } },
    'show parameters' => { '?' => 'Show daemon parameters.'   },

    'show status'  => { '?' => 'Show daemon status.'   },
    ###
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
