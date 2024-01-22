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
my %DATA_SECTION;

# Get documentation information from the __DATA__ section.
{
    my $data_text = do { local($/) = undef; <DATA> };
    close DATA;
    $data_text =~ s{ ^ \@\@ \h+ \# .* $ }{}gmx; # remove comment lines.
    while ($data_text =~
        m{
            ^ \@\@ \h+ (\S+) \h* \n (.*?) \n
            (?= \@\@)
        }gmsx)
    {
        say "=== section $1:\n---$2---";
        $DATA_SECTION{$1} = $2;
    }
}

sub make_command {
    my %arg = @_;

    my $data_key = $arg{data_key} // $arg{name};
    delete $arg{data_key};

    my $usage       = $DATA_SECTION{"$data_key:usage"};
    my $summary     = $DATA_SECTION{"$data_key:summary"};
    my $description = $DATA_SECTION{"$data_key:description"};

    return Term::CLI::Command->new(
        ( defined $usage       ? (usage       => $usage)       : () ),
        ( defined $summary     ? (summary     => $summary)     : () ),
        ( defined $description ? (description => $description) : () ),
        %arg
    );
};

    
#############################################################################

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
push @commands, make_command(
    name        => 'quit',
    callback    => \&command_quit,
);

push @commands, make_command(
    name      => 'exit',
    callback  => \&command_quit,
);

#
# Command: ping
#
push @commands, make_command(
    name        => 'ping',
    callback    => \&command_ping,
    options     => [
        'count|c=i', 'delay|d=f'
    ],
);


#
# Command: clear
#
push @commands, make_command(
    name => 'clear',
    commands => [
        make_command(
            data_key  => 'clear_ip',
            name      => 'ip',
            callback  => \&command_clear_ip,
            arguments => [
                M6::ArpSponge::Asctl::Arg_IP_Filter->new(
                    name => 'IP',
                    max_occur => 0,
                    network_prefix => $IP_NETWORK,
                ),
            ],
        ),
        make_command(
            data_key    => 'clear_arp',
            name        => 'arp',
            callback    => \&command_clear_arp,
            arguments   => [
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
push @commands, make_command(
    name     => 'load',
    data_key => 'load_status',
    commands => [
        make_command(
            name        => 'status',
            data_key    => 'load_status',
            callback    => \&command_load_status,
            arguments   => [
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
push @commands, Term::CLI::Command->new(
    name        => 'dump',
    data_key    => 'dump_status',
    commands    => [
        Term::CLI::Command->new(
            name        => 'status',
            data_key    => 'dump_status',
            callback    => \&command_dump_status,
            arguments   => [
                Term::CLI::Argument::Filename->new(
                    name => 'file',
                    min_occur => 0,
                ),
            ],
        ),
    ],
);

#
# command: probe
#
push @commands, make_command(
    name => 'probe',
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
push @commands, make_command(
    name        => 'inform',
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
            data_key    => 'inform',
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

#
# Command: help
#
push @commands, Term::CLI::Command::Help->new();

#
# REPL
#

$TERM = Term::CLI->new(
    name => 'asctl',
    prompt => 'asctl> ',
    skip => qr{^ \s* (?:\#.*)? $}x,
    commands => \@commands
);

$TERM->term->Attribs->{sort_completion_matches} = 0;

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

__DATA__
@@ ######################################################################
@@ clear:summary
clear IP state and ARP entries
@@ clear:description
Clear IP state and ARP entries from their respective tables. See the
sub-commands for more information.

@@ clear_arp:summary
clear ARP table for given IP address(es)
@@ clear_arp:description
Clear the arpsponge's ARP table for the given IP address(es).
Each I<IP> argument can be a comma-separated list of IP addresses,
a CIDR prefix, or a state filter (C<dead>, C<alive>, C<pending>, C<all>).

Examples:

    # Equivalent:
    clear arp 192.0.2.128/31 192.0.2.130
    clear arp 192.0.2.128-192.0.2.130
    clear arp 192.0.2.128,192.0.2.129,192.0.2.130
    clear arp 192.0.2.128 192.0.2.129 192.0.2.130

    # Tread carefully!
    clear arp alive
    clear arp all

@@ clear_ip:summary
clear state table for given IP address(es)
@@ clear_ip:description
Clear state table for the given IP address(es).
Each I<IP> argument can be a comma-separated list of IP addresses,
a CIDR prefix, or a state filter (C<dead>, C<alive>, C<pending>, C<all>).

Examples:

    # Equivalent:
    clear ip 192.0.2.128/31 192.0.2.130
    clear ip 192.0.2.128-192.0.2.130
    clear ip 192.0.2.128,192.0.2.129,192.0.2.130
    clear ip 192.0.2.128 192.0.2.129 192.0.2.130

    # Tread carefully!
    clear ip dead
    clear ip alive
    clear ip pending
    clear ip all

@@ ######################################################################
@@ dump_status:summary
dump IP/ARP state to file
@@ dump_status:description
Either dump IP/ARP state to I<file>, or signal the daemon to dump to its
"standard" location (user needs sufficient privileges to send signals
to the damon process).

@@ ######################################################################
@@ exit:summary
disconnect and exit
@@ exit:description
Alias for B<quit>.

Disconnect from the arpsponge daemon and exit from B<asctl>.

@@ ######################################################################
@@ inform:summary
update ARP entry for I<src_list> at I<dst_list>
@@ inform:description
Tell the devices at I<dst_list> to update their ARP cache
entries for I<src_list> with the MAC addresses that are in
the arpsponge's own table.

The method by which the I<dst_list> entities are informed is
determined by the value of the C<arp_update_flags> configuration
setting.

The B<asctl> program will expand the I<src_list> and I<dst_list>
arguments and instruct the arpsponge to send update packets for
each I<src> and I<dst> pair. This implies a square complexity.
For large I<dst_list> and/or I<src_list> ranges, it is therefore
highly recommended to insert a delay with L<--delay|/inform_delay>
(see below).

=over

=item B<Example:>

Suppose the arpsponge has 200 "alive" IP addresses in its table and
the following command is issued:

    inform alive alive

This will result in the arpsponge being instructed to send
S<200 x 199 = 39,800 updates.>

Furthermore, if C<arp_update_flags> is set to C<all> (i.e.
C<reply,request,gratuitous>, then the arpsponge will end up
sending S<39,800 x 3 = 119,400 packets.>

In this particular case, the use of L<--delay|/inform_delay>
should be considered.

=item B<Options:>

=over

=item B<--delay>=I<secs>
X<inform_delay>

Delay I<secs> seconds between subsequent "inform" steps. I<secs>
can be a fractional number (e.g. C<0.1>).

Especially on large ranges of IP addresses, the delay can be
useful to avoid locking the arpsponge with many "inform" requests
as well as to avoid flooding connected stations with lots of
ARP traffic.

=back

=back

@@ ######################################################################
@@ load_status:summary
load IP/ARP state from file
@@ load_status:description
Load IP/ARP state from a dump file.

@@ ######################################################################
@@ ping:summary
"ping" the arpsponge daemon
@@ ping:description
Ping the arpsponge daemon, display response RTT.

=over

=item B<Options:>

=over

=item B<--count>=I<n>

Send I<n> pings to the arpsponge daemon; I<n> is an integer greater than
zero (0). Default is one (1).

=item B<--delay>=I<secs>

Delay I<secs> between subsequent ping requests to the daemon; I<secs> is
a decimal number greater than or equal to 0.01. The default is 0.01.

=back

=back

@@ ######################################################################
@@ probe:summary
send ARP requests for given IP address(es)
@@ probe:description
Send ARP broadcast requests for the given IP address(es).

Note that B<asctl> only tells the arpsponge to send the requests, i.e.,
it doesn't wait for any replies; these will be caught by the regular
sponge operation.

=over

=item B<Options:>

=over

=item B<--count>=I<n>, B<-c> I<n>

Send I<n> probes to the given IP address(es). The I<n> argument is
an integer greater than zero (0). The default is one (1).

=item B<--delay>=I<secs>, B<-d> I<secs>

Wait for I<secs> between subsequent probe messages. The I<secs> argument
is a decimal number greater than 0.01. The default is 0.01.

=back

=back

@@ ######################################################################
@@ quit:summary
disconnect and exit
@@ quit:description
Alias for B<exit>.

Disconnect from the arpsponge daemon and exit from B<asctl>.

@@ ######################################################################
@@ END

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
