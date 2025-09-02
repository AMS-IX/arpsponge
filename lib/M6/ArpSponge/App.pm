###############################################################################
#
# ARP sponge
#
# (c) Copyright AMS-IX B.V. 2003-2010; all rights reserved.
#
# See the LICENSE file that came with this package.
#
# A.Vijn,   2003-2004;
# S.Bakker, 2004-;
#
# Yes, this file is BIG. There's a POD at the end.
#
###############################################################################
package M6::ArpSponge::App;

use 5.014;
use warnings;

use Moo;
use Types::Standard qw( Int Str Num Bool );

use Getopt::Long qw( GetOptionsFromArray :config bundling );
use Pod::Usage;
use Pod::Find qw( pod_where );
use FindBin;
use Data::Dump qw( dump );

use Net::Pcap qw(
    pcap_dispatch pcap_get_selectable_fd
    pcap_open_live pcap_setnonblock
);

use NetAddr::IP         qw( :lower );
use Time::HiRes         qw( time sleep );
use Time::Piece;
use POSIX               qw( :signal_h :errno_h );
use File::Path          qw( mkpath );

use IO::Select;
use IO::Socket;

use M6::ArpSponge::Control::Server;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Event        qw( :const :func );
use M6::ArpSponge::UpdateFlags  qw( :const :func );
use M6::ArpSponge::Log          qw( :macros :func !log_level );
use M6::ArpSponge::NetPacket    qw( :all );
use M6::ArpSponge::Sponge;
use M6::ArpSponge::State        qw( :const :func );
use M6::ArpSponge::UpdateFlags  qw( :const );
use M6::ArpSponge::Util         qw( :all );

###############################################################################

use constant SYSLOG_IDENT => M6::ArpSponge::Defaults->NAME;

my $PROG                 = $FindBin::Script;
my $VERSION              = M6::ArpSponge::Defaults->VERSION;
my $RUN_DIR              = M6::ArpSponge::Defaults->RUN_DIR;

# Max. number of packets to handle in a pcap_dispatch() cycle.
# This should be large enough to allow for some efficiency,
# but low enough so other events (on other FDs) get handled.
#
# Assuming:
#
#   * A 100Mb/s interface
#   * 64-byte frames/packets
#   => 195 packets/sec
#
# So, if we cycle 100 packets, that would cost us about 0.5 seconds
# on a saturated interface, leaving enough interactive response...
#
my $MAX_PKT_PER_CYCLE   = 100;
my $PCAP_TIMEOUT        = 5;

my $USAGE_MSG = "Try '$PROG --help' for more information.\n";

###############################################################################

my $Wrote_Pid      = 0;
my $Pid_File       = undef;
my $Control_Socket = undef;
my $Block_Sigset   = POSIX::SigSet->new(SIGUSR1, SIGHUP, SIGALRM);
my $Timer_Cycle    = 1.0;

# Keep track of how many errors we've seen and when we logged the
# last error. This is used to suppress too much logging.
my $Last_Select_Error_Time  = 0;
my $Last_Select_Error       = 0;
my $Select_Error_Count      = 0;

#############################################################################
# Attributes
#############################################################################
has device => (
    is => 'ro',
    required => 1,
    isa => Str,
);

has network => (
    is => 'ro',
    required => 1,
    isa => Str->where(sub { /^[\da-z]{8}$/ }),
);

has prefixlen => (
    is => 'ro',
    required => 1,
    isa => Int->where(sub { $_ > 0 && $_ <= 32 }),
);

has control_socket => (
    is      => 'lazy',
    isa     => Str,
    builder => sub { $_[0]->run_dir . '/control' },
);

has daemon_mode => (
    is => 'ro',
    isa => Bool,
    default => sub { 0 },
);

has flood_protection => (
    is      => 'rw',
    isa     => Num->where(sub { $_ > 0 }),
    default => \&M6::ArpSponge::Defaults::FLOOD_PROTECTION,
);

has learn_time => (
    is      => 'rw',
    isa     => Int->where(sub { $_ >= 0 }),
    default => \&M6::ArpSponge::Defaults::LEARN_TIME,
);

has log_level => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    trigger => sub { M6::ArpSponge::Log::log_level($_[1]) }
);

has log_mask => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    trigger => sub { event_mask($_[1]) },
);

has max_arp_age => (
    is      => 'rw',
    isa     => Int->where(sub { $_ >= 0 }),
    default => \&M6::ArpSponge::Defaults::MAX_ARP_AGE,
);

has max_arp_rate => (
    is      => 'rw',
    isa     => Int->where(sub { $_ >= 0 }),
    default => \&M6::ArpSponge::Defaults::MAX_ARP_RATE,
);

has max_pending => (
    is      => 'rw',
    isa     => Int->where(sub { $_ > 0 }),
    default => \&M6::ArpSponge::Defaults::MAX_PENDING
);

has passive_mode => (
    is      => 'rw',
    isa     => Bool,
    default => sub { 0 },
);

has pid_file => (
    is      => 'lazy',
    isa     => Str,
    builder => sub { $_[0]->run_dir . '/pid' },
);

has probe_rate => (
    is  => 'rw',
    isa => Num->where(sub { $_ > 0 }),
    default => \&M6::ArpSponge::Defaults::PROBE_RATE,
);

has run_dir => (
    is  => 'rw',
    isa => Str,
    default => \&M6::ArpSponge::Defaults::PROBE_RATE,
);

has status_file => (
    is      => 'lazy',
    isa     => Str,
    builder => sub { $_[0]->run_dir . '/status' },
);

# Some attributes are handled by the "state"
# object.
my @STATE_ATTR = qw(
    arp_update_flags
    dummy_mode
    gratuitous
    init_state
    sponge_network
    pcap_handle
    queue_depth
);

has state => (
    is => 'lazy',
    builder => sub {
        my ($self) = @_;
        return M6::ArpSponge::Sponge->new(
            device    => $self->device,
            network   => $self->network,
            prefixlen => $self->prefixlen,
        );
    },
    handles => \@STATE_ATTR,
);

has socket_uid => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    default => sub { 0 },
);

has socket_gid => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    default => sub { 0 },
);

has socket_mode => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    default => sub { 0660 },
);

for my $attr (qw( static_mode sweep_at_start sweep_skip_alive )) {
    has $attr => (
        is  => 'rw',
        isa => Bool,
        default => sub { 0 },
    );
}

has verbose => (
    is  => 'rw',
    isa => Int->where(sub { $_ >= 0 }),
    default => sub { 0 },
);

sub BUILD {
    my ($self, $args) = @_;

    # Transfer some of the constructor arguments to the
    # 'state' object (M6::ArpSponge::Sponge).
    my $state = $self->state;
    for my $attr (@STATE_ATTR) {
        next if !exists $args->{$attr};
        $state->$attr($args->{$attr}) 
    }
}

# $val = _check_num_opt($name, $value, $cmp_op, $cmp_arg);
#
#   Check option ("--$name") value ($value) against a boundary
#   ($cmp_arg) using $cmp_op as the comparison. Emit a fatal
#   error if the comparison fails.
#
#   Example:
#
#       $opt_pending = _check_num_opt('max-pending', $opt_pending, '>', 0);
#
#   Returns 1 if $opt_pending is 1, but exits with a fatal error
#   if it is 0 or lower: "invalid --max-pending argument '0': must be > 0."
#
sub _check_num_opt {
    my ($name, $val, $cmp_op, $cmp_arg) = @_;
    if (eval "\$val $cmp_op \$cmp_arg") {
        return $val;
    }
    log_fatal "invalid --%s argument '%s': must be %s %s.",
            $name, $val, $cmp_op, $cmp_arg;
}

sub _fetch_opt {
    my ($opt, $key) = @_;
    my $opt_name = $key =~ s/_/-/gr;
    return ($key, $opt_name, $opt->{$opt_name});
}

sub default_options {
    return (
        'max-arp-age'         => M6::ArpSponge::Defaults->MAX_ARP_AGE,
        'arp-update-flags'    => 'all',
        'control-socket'      => undef,
        'daemon-mode'         => 0,
        'device'              => undef,
        'dummy-mode'          => 0,
        'passive-mode'        => 0,
        'static-mode'         => 0,
        'flood-protection'    => M6::ArpSponge::Defaults->FLOOD_PROTECTION,
        'gratuitous'          => 0,
        'init-state'          => M6::ArpSponge::Defaults->INIT_STATE,
        'learn-time'          => M6::ArpSponge::Defaults->LEARN_TIME,
        'log-level'           => M6::ArpSponge::Defaults->LOG_LEVEL,
        'log-mask'            => M6::ArpSponge::Defaults->LOG_EVENT_MASK,
        'network'             => undef,
        'max-pending'         => M6::ArpSponge::Defaults->MAX_PENDING,
        'pid-file'            => undef,
        'probe-rate'          => M6::ArpSponge::Defaults->PROBE_RATE,
        'queue-depth'         => M6::ArpSponge::Defaults->QUEUE_DEPTH,
        'max-arp-rate'        => M6::ArpSponge::Defaults->MAX_ARP_RATE,
        'run-dir'             => undef,
        'socket-permissions'  => M6::ArpSponge::Defaults->SOCK_PERMS,
        'sponge-network'      => 0,
        'status-file'         => undef,
        'sweep'               => undef,
        'sweep-at-start'      => 0,
        'sweep-skip-alive'    => 0,
        'verbose'             => 0,
    );
}

sub parse_command_line {
    my ($class, $args) = @_;

    init_log(SYSLOG_IDENT);

    $args //= \@ARGV;

    my %opt = $class->default_options;

    GetOptionsFromArray($args, \%opt,
        'max-arp-age|age=i',
        'arp-update-flags|arp-update-methods=s',
        'control-socket=s',
        'daemon-mode!',
        'device=s',
        'dummy-mode!',
        'passive-mode!',
        'static-mode!',
        'flood-protection=f',
        'gratuitous!',
        'init-state=s',
        'learn-time|learning=i',
        'loglevel=s',
        'logmask=s',
        'network=s',
        'max-pending|pending=i',
        'socket-permissions|permissions=s',
        'pid-file|pidfile=s',
        'probe-rate|proberate=f',
        'queue-depth|queuedepth=i',
        'max-arp-rate|rate=f',
        'run-dir|rundir=s',
        'sponge-network',
        'status-file|statusfile=s',
        'sweep=s',
        'sweep-at-start!',
        'sweep-skip-alive',
        'verbose|v+',

        'version|V' => sub {
            print "$PROG $VERSION\n";
            exit 0;
        },
        'help|h|?' => sub {
            pod2usage(
                -exitstatus => 0,
                -verbose => 0,
                -input => pod_where({-inc => 1}, __PACKAGE__) 
            );
        },
        'manual' => sub {
            pod2usage(
                -exitstatus => 0,
                -verbose => 2,
                -input => pod_where({-inc => 1}, __PACKAGE__) 
            );
        },
    ) or die($USAGE_MSG);

    my %param;

    # First the mandatory things...
    #
    # We need --network=cidr  OR first command line argument.
    # We need --device=ifname OR "dev <ifname>" command line arguments.
    #
    # Device is needed for auto values of run_dir.
    #
    my ($network, $device);
    NETWORK_AND_DEVICE: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'network');
        my $argname = "--$opt_name";
        my $opt_network = $opt_val;
        if (!$opt_network) {
            log_fatal("Not enough parameters.\n$USAGE_MSG") if @${args} < 1;
            $opt_network = shift @{$args};
            $argname = $opt_name;
        }
        if (!is_valid_ip($opt_network)) {
            log_fatal "invalid $argname argument '%s'.", $opt_network;
        }
        $network = NetAddr::IP->new($opt_network)
            or log_fatal "invalid $argname argument '%s'.", $opt_network;

        $param{network}   = ip2hex($network->addr);
        $param{prefixlen} = $network->masklen;

        if (defined $opt{device}) {
            $device = $opt{device};
        }
        else {
            log_fatal("not enough parameters.\n$USAGE_MSG") if @${args} < 2;

            my $arg = lc shift @{$args};
            if ($args ne 'dev') {
                log_fatal(
                    "invalid parameter: expected 'dev' instead of '%s'.",
                    $arg
                );
            }
            $device = shift @{$args};
        }
        $param{device} = $device;
        log_fatal("too many parameters.\n$$USAGE_MSG")  if @${args} > 0;
    }

    BOOLEANS: {
        my @boolean_keys = qw(
            daemon_mode dummy_mode gratuitous passive_mode
            sponge_network static_mode sweep_at_start
            sweep_skip_alive verbose
        );
        for my $k (@boolean_keys) {
            my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, $k);
            $param{$key} = $opt_val;
        }
    }

    ARP_UPDATE_FLAGS: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'arp_update_flags');
        my $val = parse_update_flags(
                $opt_val,
                -err => \(my $err)
        );
        if (defined $err) {
            log_fatal("invalid --%s argument '%s' (%s).",
                    $opt_name, $opt_val, $err);
        }
        $param{$key} = $val;
    }

    INIT_STATE: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'init_state');
        my $val = is_valid_state($opt_val);
        if (!defined $val) {
            log_fatal "invalid --%s argument '%s'.", $opt_name, $opt_val;
        }
        $param{$key} = $val;
    }

    LOG_LEVEL: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'log_level');
        my $val = is_valid_log_level($opt_val);
        if (!defined $val) {
            log_fatal "invalid --%s argument '%s'.", $opt_name, $opt_val;
        }
        $param{$key} = $val;
    }

    EVENT_MASK: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'log_mask');
        my $val = parse_event_mask($opt{log_mask}, -err => \(my $err));
        if (!defined $val) {
            log_fatal "invalid --%s argument '%s' (%s).",
                $opt_name, $opt_val, $err;
        }
        $param{$key} = $val;
    }

    PERMISSIONS: {
        my ($key, $opt_name, $opt_val)
            = _fetch_opt(\%opt, 'socket_permissions');

        my @dfl_perms  = split(':', M6::ArpSponge::Defaults->SOCK_PERMS);
        my @perms      = split(':', $opt_val);
        if (@perms > 3) {
            log_fatal "invalid --%s argument '%s'.", $opt_name, $opt_val;
        }
        my $sock_owner = $perms[0] // $dfl_perms[0];
        my $sock_group = $perms[1] // $dfl_perms[1];
        my $sock_mode  = oct($perms[2] // $dfl_perms[2]);

        $param{socket_uid} = getpwnam($sock_owner)
            // log_fatal(
                    "--socket-permissions: unknown user name '%s'.",
                    $sock_owner,
                );

        $param{socket_gid} = getgrnam($sock_group)
            // log_fatal(
                    "--socket-permissions: unknown group name '%s'.",
                    $sock_group,
                );

        $param{socket_mode} = $sock_mode;
    }

    # Numerical, must be > 0.
    for my $var (qw(
        max_pending
        flood_protection
        probe_rate
        queue_depth 
    )) {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, $var);
        $param{$key} = _check_num_opt($opt_name, $opt_val, '>', 0);
    }

    # Numerical, must be >= 0.
    for my $var (qw(
        learn_time
        max_arp_age
        max_arp_rate
    )) {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, $var);
        $param{$key} = _check_num_opt($opt_name, $opt_val, '>=', 0);
    }

    SWEEP: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'sweep');
        if (!defined $opt_val || !length($opt_val)) {
            last SWEEP;
        }

        my ($sweep_sec, $sweep_threshold) = $opt_val =~ m|^(\d+)/(\d+)$|
            or log_fatal "invalid --%s argument '%s'.", $opt_name, $opt_val;

        $param{sweep_sec} = $sweep_sec;
        $param{sweep_threshold} = $sweep_threshold;
    }

    RUNDIR_CONTROL_PIDFILE_STATUSFILE: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'run_dir');
        my $run_dir = $opt_val // "$RUN_DIR/$device";
        $param{run_dir}         = $run_dir;
        $param{control_socket}  = $opt{'control-socket'} // "$run_dir/control";
        $param{pid_file}        = $opt{'pid-file'}       // "$run_dir/pid";
        $param{status_file}     = $opt{'status-file'}    // "$run_dir/status";
    }

    say "Opt:\n", dump(\%opt), "\n";
    say "Program parameters:\n", dump(\%param);
    return %param;
}

sub new_with_args {
    my ($class, $args) = @_;

    my %param = $class->parse_command_line($args);
    return $class->new(%param);
}


1;

__END__

=pod

=head1 NAME

arpsponge - automatically "sponge" ARP requests for dead IP addresses

=head1 SYNOPSIS

B<arpsponge> [I<options>] I<NETPREFIX/LEN> B<dev> I<DEV>

I<Options>:

    --age=secs
    --arp-update-method={all|none|request|reply|gratuitous}*
    --control=socket
    --[no]daemon
    --dummy
    --flood-protection=r
    --[no]gratuitous
    --init={ALIVE|DEAD|PENDING|NONE}
    --learning=secs
    --loglevel=level
    --logmask=mask
    --pending=n
    --permissions=owner:group:mode
    --pidfile=pidfile
    --proberate=r
    --queuedepth=n
    --rate=r
    --rundir=path
    --[no-]passive
    --[no-]static
    --sponge-network
    --statusfile=file
    --sweep=interval/threshold
    --sweep-at-start
    --sweep-skip-alive
    --verbose

B</etc/init.d/arpsponge> {B<start>|B<stop>|B<restart>|B<status>}

=head1 DESCRIPTION

The C<arpsponge> program "sponges" ARP queries from an Ethernet interface.

=head2 Sponging

The program monitors ARP queries for addresses in the I<NETPREFIX/LEN>
network and starts spoofing replies for them when the queries reach a
threshold (default unanswered queries with an average
rate of 50 or more per minute).

=head2 Unsponging

Sponging stops in one of three cases:

=over 4

=item 1.

The sponge receives a gratuitous ARP ("ARP WHO-HAS I<xx> TELL I<xx>") for
the sponged IP address.

Many systems (mostly routers) will send a gratuitous ARP request when they
bring up their interfaces, advertising their presence and seeding ARP caches.

=item 2.

The sponge receives an arbitrary IP or ARP packet from the sponged IP address.

Some systems do not send gratuitous ARP request packets when bringing up interfaces.
However, they typically start ARPing for peers on the LAN when attempting
to set up connections, so that is a good trigger as well.

=item 3.

The sponge receives an ARP query for a sponged IP address that seems to
come from IP 0.0.0.0 ("ARP WHO-HAS I<xx> TELL B<0.0.0.0>"). This is used
by many DHCP client implementations to detect duplicate addresses before
accepting an address from the DHCP server (See also RFC 2131, section 4.4.1).
Should not appear on an IXP peering LAN, but then, you never know.

=back

=head2 Rationale

The idea here is that when on a busy BGP peering LAN a router with many
peerings goes down, the resulting ARP storm is mitigated by the sponge.
Similarly, when a peer on the LAN goes away permanently, the sponge will
make sure that no excessive ARPing is done for the now defunct IP address
by parties that did not clean up their BGP configurations.

=head2 Features

=head3 Learning State

By default, the sponge spends @DFL_LEARN@ seconds in "learning mode"
at startup. During this time it records IP and MAC addresses, but
does not sponge addresses or send queries.

=head3 Gratuitous ARP

The program can send out a gratuitous ARP request when it starts to sponge
an address. This should bring down the ARP rate on the LAN further, since
ideally all devices update their ARP cache immediately.

=head3 Pending State

If the query rate for an IP address exceeds the queue depth and rate
threshold, the sponge can put the IP address in a "pending" state:
it will send out a query for the IP address every second for the next
@DFL_PENDING@ seconds.
If there is still no sign of life from the target, the target's state moves
from "pending" to "dead" and will be sponged. See also the
L<--pending|/--pending>
option below.

=head3 Sweeping

Not all devices send a gratuitous ARP request when they come up, so it may
be necessary to periodically sweep the IP range for dead or very quiet
addresses. This also helps to clear the status for very quiet
hosts.

=head3 Logging

The program writes sponge/unsponge events to L<B<syslog>(3)|syslog.3> with
priority C<info>.

It can also write more detailed event to clients on the control socket
and when the B<--statusfile> argument is given, it will write a summary
of its current state upon receiving a C<HUP> or C<USR1> signal.

=head2 Passive Mode

The program can run in so-called "passive mode", where it will I<never> send
ARP queries using its own IP address. This effectively disables
L<sweeping|/Sweeping> and turns the L<pending state|/Pending State> into
a passive timer.

If the sponge's network interface does not have an IPv4 address assigned to
it, passive mode is automatically turned on, but warnings will be generated
periodically. To get rid of these, restart the daemon with
L<--passive|/--passive>.

Note that this only disables active probing by the program; sponging and
unsponging will still happen automatically.

=head2 Static Mode

When running in "static mode", the program will learn IP/MAC address mappings,
and periodically sweep, but it will I<never> automatically sponge or unsponge.

Instead, sponging and unsponging will have to be done manually (through
L<asctl|/asctl>).

In static mode, if any events occur that would normally result in I<unsponging>
an IP address, a warning will be logged instead.

=head1 OPTIONS

=over

=item B<--age>=I<secs>
X<--age>

Time until we consider an ARP entry "stale" (default @DFL_ARP_AGE@).
This really controls how often we refresh the entries in our internal
ARP cache.

=item B<--arp-update-method>=[B<!>]I<method>,...
X<--arp-update-method>

Some routers do not update their ARP cache when an IP gets unsponged.
We detect this by looking for traffic destined for our MAC, with a
destination IP that is I<not> ours. If the destination IP is in our local
LAN, we should attempt to update the packet source's ARP cache.

This can be done in three ways:

=over

=item C<reply>

Send an unsollicited unicast reply to I<IP-B>:

  ARP <IP-A> IS AT <MAC-A>

Where I<IP-A> and I<MAC-A> are of the router targeted by the stray packet,
and I<IP-B> is the IP address of the neighbour whose cache needs to be
updated.

=item C<request>

Send an unicast request by proxy (i.e. fake the requestor):

  ARP WHO HAS <IP-B> TELL <IP-A>@<MAC-A>

Where I<IP-B> is the IP address of the neighbour whose cache needs to be
updated.

=item C<gratuitous>

Send a unicast gratuitous ARP request on behalf of I<IP-A> to I<IP-B>:

  ARP WHO HAS <IP-A> TELL <IP-A>@<MAC-A>

Where I<IP-B> is the IP address of the neighbour whose cache needs to be
updated.

=item C<all>, C<none>

All or none of the above, resp.

=back

The methods can be specified as a comma-separated list, e.g.:

   request,reply

Each element can be prefixed by C<!> to negate it, so the following are
equivalent:

   request,reply

   all,!gratuitous

Default value is C<all>.

This value is also used by the L<inform|asctl/inform> command of
L<B<asctl>(1)|asctl.1>.

=item B<--control>=I<socket>
X<--control>

Location of the UNIX control socket. Default is
"I<rundir>/B<control>". See also L<--permissions|/--permissions> below.

=item B<--daemon>
X<--daemon>

=item B<--no-daemon>
X<--no-daemon>

Run (don't run) as a daemon process in the background.

If run as a daemon, leave the process identification (PID) in
I<pidfile> (see L<--pidfile|/--pidfile>).

If I<pidfile> already exists and the value in the file is that of a
running sponge process, the program will exit with an appropriate
error diagnostic. Otherwise, it forks into the background, closes
the standard input, output and error file descriptors and writes its
PID to I<pidfile>.

This option turns off C<--verbose> and enables logging to
L<B<syslog>(3)|syslog.3>.

=item B<--passive>
X<--passive>

=item B<--no-passive>
X<--no-passive>

Run (don't run) in passive mode. When passive mode is activated, the
sponge will I<never> send ARP queries from its own IP address.

See L<Passive Mode|/Passive Mode> above.

=item B<--static>
X<--static>

=item B<--no-static>
X<--no-static>

Run (don't run) in static mode. When static mode is activated,
sponging and unsponging will I<never> happen automatically. Instead,
sponging and unsponging will have to be done manually (through L<asctl|/asctl>).

See L<Static Mode|/Static Mode> above.

=item B<--dummy>
X<--dummy>

Dummy operation (simulate sponging). Does send ARP queries, but no ARP
(sponge) replies.

=item B<--flood-protection>=I<r>
X<--flood-protection>

ARP threshold rate in queries/sec (default 3) above
which we ignore ARP queries from a particular source.

If there is a ARP broadcast storm on the platform (e.g. loops or DoS),
it's possible that one or more IP addresses originate large amounts
of (bogus) ARP queries.

As an example, suppose we set flood protection to "3", and I<SRC_IP>
sends over 100 ARP queries/sec for I<DST_IP>. Rather than putting
I<DST_IP> in pending mode after a few second of this, we would check
the ARP rate of I<SRC_IP> and see that it exceeds 3 and immediately
reduce the queue back to 1.

=item B<--[no]gratuitous>
X<--gratuitous>X<--nogratuitous>

Do (not) send gratuitous ARP queries when sponging an address.

=item B<--init>={B<ALIVE>|B<DEAD>|B<PENDING>|B<NONE>}
X<--init>

How to initialise the sponge's state table:

=over 4

=item B<ALIVE> (default)

All addresses are considered to be alive at startup. This is the least
disruptive initialisation mode. Addresses will only get sponged after
their ARP queue fills up AND the rate exceeds the threshold AND they
don't answer ARP queries.

=item B<DEAD>

All addresses are considered to be dead at startup.

WARNING: This can potentially bring down all or most of the services
on your LAN!

This option is really only useful if the sponge is (one of) the first
active entities on a large LAN and all the other stations will join through
something like DHCP (and send 0.0.0.0 sourced ARP queries for themselves).

=item B<PENDING>

All addresses are set to PENDING state. Once the sponge goes out of learning
mode, it will periodically sweep the PENDING addresses, and the dead ones
will quickly get sponged.

For a small network segment (/24 or larger prefix) this is the preferred
method. It quickly finds the dead addresses, without flooding the network
with massive numbers of broadcast queries.

=item B<NONE>

No states are set. This emulates the ALIVE state with a full queue.
No queries are sent, but the first ARP query for an address with an
undefined state will result in a PENDING state for that address, at
which point querying for that address will commence.

For a large network, this can be a real bonus. It still quickly catches
dead addresses, but doesn't incur the overhead of large ARP sweeps.

=back

=item B<--learning>=I<secs>
X<--learning>

Spend I<secs> seconds on LEARNING mode. During the learning mode, we only
listen to network traffic, we don't send ARP queries or sponged answers. This
parameter is especially useful in conjunction with init states I<DEAD>,
I<PENDING> and I<NONE> as it will clear the table for live IP addresses.

A value of zero (0) disables the initial learning state.

=item B<--loglevel>=I<level>
X<--loglevel>

Logging level for
L<B<syslog>(3)|syslog.3>
logging. Default is C<info>.

=item B<--logmask>=[B<!>|B<+>]I<event>,...
X<--logmask>

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

Note that ARP queries for the network base address and broadcast address
are also considered "alien" and will be logged as such.

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

=item B<--pending>=I<n>
X<--pending>

Number of ARP queries the sponge itself sends before sponging an IP address
(default: 5).

The L<pending state|/Pending State> (see L<above|/Pending State>)
serves as an extra check before sponging: if it gets a response from
the target IP, then that address is obviously not dead yet.

Choosing the I<pending> parameter wisely (larger than one, but not much
larger than 5) will prevent unjustified sponging (e.g. when
a Black Hat sends streams of ARP queries in the hopes of getting the
target sponged).

B<Tip>: Increasing the value pending parameter by one adds one second
of delay before the sponge kicks in. If you increase this value significantly,
you should consider decreasing the L<--queuedepth|/--queuedepth> parameter
as well.

=item B<--permissions>=[I<owner>]:[I<group>]:[I<mode>]
X<--permissions>

Set the permissions on the L<control socket|/--control>. Default is
system-dependent (C<root:adm:0660> on Linux, C<root:wheel:0660> on BSD).

=item B<--pidfile>=I<pidfile>
X<--pidfile>

Write daemon PID to I<pidfile> instead of the default
(I<rundir>/pid).

=item B<--proberate>=I<n>
X<--proberate>

The rate at which we send our ARP queries. Used when sweeping
and querying pending addresses.

Default is 100, but check the rate your network can
comfortably handle.

Generally speaking, the following formula gives an upper bound for
the time spent in a probing sweep:


            IP_SIZE
  Tmax =   ---------
           PROBERATE

So a sweep over 100 addresses with a query rate of 50 takes about 2 seconds.

The CPU can usually throw ICMP packets at an interface much faster than
the actual wire speed, so many do not make it onto the wire.
Furthermore, since ARP queries are broadcast and thus typically CPU-bound at
the receiver, they may get rate-limited by the L2 infrastructure or at the
receiving stations.

Furthermore,
having the sponge itself be a source of periodic broadcast storms
defeats its own purpose,
so the probe rate should be set to something "sensible".

=over 7

=item NOTE:

Due to the way the C<proberate> delays are implemented, it's possible
that you will not be able to go higher than 100 and possibly even get stuck
at 50 or so.  See also L</BUGS AND LIMITATIONS> below.

=back

=item B<--queuedepth>=I<n>
X<--queuedepth>

Number of ARP queries over which to calculate average rate (default
1000).
Sponging is not triggered until at least this number of ARP queries are seen.

=item B<--rate>=I<r>
X<--rate>

ARP threshold rate in queries/min (default @DFL_RATE@). If the ARP queue
(see above) is full, and the average rate of incoming queries per second
exceeds I<r>, we move the target IP to I<PENDING> state (but see also
L<--flood-protection|/--flood-protection>.

=item B<--rundir>=I<path>
X<--rundir>

Base directory for run-time files. Default is system dependent, but
typically one of "F</run/arpsponge>/I<interface>" or 
"F</var/run/arpsponge>/I<interface>".

=item B<--sponge-network>
X<--sponge-network>

Statically sponge the network base address as well as the broadcast address.
L<Section 4.2.3 of RFC-1812|https://tools.ietf.org/html/rfc1812#section-4.2.3>
specifies that the "all one" and "all zero" host addresses are not valid node
addresses (see also section
L<3.2.1.3 of RFC-1122|https://tools.ietf.org/html/rfc1122#section-3.2.1.3>).

Hence, you should never see ARP requests for these addresses; if you do,
the cause is most probably a misconfigured network address or mask at the
sender's end.

By specifying C<--sponge-network>, the sponge will answer queries for both
the network base address and the broadcast address. Note that it will neither
query for them itself, nor send any unsollicited ARP for them.

ARP queries for either the network base address or the broadcast address
will be logged as C<alien> events (see L<--logmask|/--logmask>).

=item B<--statusfile>=I<file>
X<--statusfile>

Write status to I<file> when receiving the C<HUP> or C<USR1> signal.
Default is "I<rundir>/B<status>".

Note that the daemon has no way of reloading this data, other than through the
L<B<asctl>(1)|asctl> utility.

=item B<--sweep>=I<interval>/I<threshold>
X<--sweep>

Every I<interval> seconds, sweep the IP range for IP addresses who we
haven't heard from or queried in the last I<threshold> seconds. This
sweeps over all IP addresses, both sponged and quietly alive.

Example: C<--sweep=900/3600>. This will cause the program to sweep every
15 minutes, looking for the IP addresses it hasn't heard anything from
or sent anything to in the last hour. This does not mean that it queries
a silent address every 15 minutes, it just checks whether it should and
sends out no more than one query per hour for that address.

If the I<interval> vs. I<threshold> thing is confusing, just remember the
following:

=over 4

=item *

A shorter I<interval> generally results in a better spread of
sweep ARP queries at the cost of more processing spent in sweeping.

=item *

A shorter I<threshold> results in a quicker rediscovery of a sponged
address that has come back, but has been quiet for some reason, at the
cost of more ARP queries from the daemon's host.

=back

=item B<--sweep-at-start>, B<--no-sweep-at-start>
X<--sweep-at-start>X<--no-sweep-at-start>

Perform a sweep at the start of the program, I<after> the initial learning
phase. All "sweep" related settings apart from I<interval> apply to this
round, including I<--sweep-skip-alive>.

=item B<--sweep-skip-alive>
X<--sweep-skip-alive>

Do not sweep IP addresses with sponge state of ALIVE. Note that this only
counts for IP addresses that have an ARP entry: IP addresses in ALIVE state,
but without an ARP entry are queried anyway.

=item B<--verbose>[=I<n>]
X<--verbose>

Be verbose; print information on F<STDOUT>;
This options turns off logging to
L<B<syslog>(3)|syslog.3>
and causes the information to be printed to F<STDOUT> instead.
The higher the level I<n> (default is 1 if not given), the
more detailed information is printed.  Not recommended for
production use.

Has no effect when L<--daemon|/--daemon> is specified.

=back

=head1 EXAMPLES

To start the program on C<eth0> for the C<91.200.17.0/26> network,
simply use:

   arpsponge 91.200.17.0/26 dev eth0

=head2 Status Dumping

To use the status dumping functionality, do:

   arpsponge --daemon --statusfile=/tmp/sponge.out \
        91.200.17.0/26 dev eth0

Then send a C<USR1> signal to the process:

   pkill -USR1 arpsponge

Now F</tmp/sponge.out> should contain something like:

  id:               arpsponge
  pid:              27482
  version:          3.25.0
  date:             2011-04-22@15:30:26 [1303479026]
  started:          2011-04-22@11:25:53 [1303464353]
  network:          91.200.17.0/26
  interface:        eth0
  ip/mac:           91.200.17.40 [fe:00:00:96:00:0a]
  queue depth:      200
  max rate:         30.00
  flood protection: 5.00
  max pending:      10
  sweep period:     900 sec
  sweep age:        3600 sec
  proberate:        100 sec
  next sweep in:    627 sec
  learning:         no
  dummy:            yes

  <STATE>
  # IP              State          Queue Rate (q/min) Updated
  91.200.17.0       STATIC             0    0.000     2011-04-22@11:29:38
  91.200.17.1       ALIVE              0    0.000     2011-04-22@15:30:09
  91.200.17.2       ALIVE              0    0.000     2011-04-22@14:37:14
  91.200.17.3       DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.4       ALIVE              0    0.000     2011-04-22@15:30:09
  91.200.17.19      DEAD               1    0.000     2011-04-22@15:10:53
  91.200.17.22      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.26      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.27      DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.28      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.31      DEAD               1    0.000     2011-04-22@15:23:27
  91.200.17.32      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.33      DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.37      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.38      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.39      ALIVE              0    0.000     2011-04-22@15:30:10
  91.200.17.51      DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.52      DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.53      DEAD               1    0.000     2011-04-22@15:25:53
  91.200.17.61      DEAD               1    0.000     2011-04-22@15:10:53
  </STATE>

  <ARP-TABLE>
  # MAC             IP                Epoch       Time
  00:07:eb:46:48:e1 91.200.17.1       1303479009  2011-04-22@15:30:09
  00:0c:db:02:64:1c 91.200.17.2       1303475834  2011-04-22@14:37:14
  00:06:d7:3f:64:c0 91.200.17.4       1303479009  2011-04-22@15:30:09
  00:1b:ed:03:c2:00 91.200.17.22      1303479010  2011-04-22@15:30:10
  00:05:dc:66:10:06 91.200.17.26      1303479010  2011-04-22@15:30:10
  fe:00:00:64:00:0a 91.200.17.28      1303479010  2011-04-22@15:30:10
  fe:00:01:72:00:0a 91.200.17.29      1303479010  2011-04-22@15:30:10
  00:1b:ed:03:c2:00 91.200.17.32      1303479010  2011-04-22@15:30:10
  fe:00:01:5e:00:0a 91.200.17.37      1303479010  2011-04-22@15:30:10
  fe:00:01:69:00:0a 91.200.17.38      1303479010  2011-04-22@15:30:10
  fe:00:01:68:00:0a 91.200.17.39      1303479010  2011-04-22@15:30:10
  </ARP-TABLE>

  alive=24 dead=37 pending=0 ARP_entries=25

=head1 SYSTEM INIT SCRIPT

The sponge can be started by an
L<B<init>(1)|init>
script,
F</etc/init.d/arpsponge>.
This script looks for the following files:

=over 4

=item F<@ETC_DEFAULT@/arpsponge/defaults>

Contains default options for every sponge instance. The options are
specified as
L<B<sh>(1)|sh.1>
shell variables.

=item F<@ETC_DEFAULT@/arpsponge/interfaces.d/if_name>

Contains a network definition for the sponge on I<if_name>.

=item F<@ETC_DEFAULT@/arpsponge/ethX> (LEGACY)

Contains a network definition for the sponge on I<ethX>. This is a
legacy option, because it forces a name format on interfaces. If
both F<interfaces.d/> and F<ethX> file(s) exist, a warning will be
emitted, and the contents of F<interfaces.d/> will be used instead.

To migrate from this legacy situation, simply do the following:

    cd @ETC_DEFAULT@
    mkdir interfaces.d
    mv eth* interfaces.d

=back

Note that there are two possible locations for interface configuration files.
The files in the F<interfaces.d> sub-directory are the preferred way to go,
since it allows any kind of device name: any non-hidden regular file will
be seen as an interface configuration file.

For every interface configuration file the script finds, it starts a sponge
daemon on the corresponding interface. The sponge daemon will write its
status file to F<$RUN_DIR/if_name/status> and create a control socket in
F<$RUN_DIR/if_name/control>, where I<if_name> corresponds to the
interface name.

=head2 Init Variables

For boolean variables, "true", "yes", "on" and positive integers evaluate
to "true", other values are "false".

=head3 Global variables

=over 4

=item I<AGE> (integer)

The argument to C<--age>.

=item I<DISABLED> (boolean)

Whether the arpsponge is disabled. Can be set globally or per
interface. Note that if it is set globally, the individual interface
files can still explicitly override this value.

=item I<DUMMY_MODE> (boolean)

Use C<--dummy> on the sponge. Note that L<B<asctl>(1)|asctl> clients can
(re-)set this value on the fly.

=item I<GRATUITOUS> (boolean)

Whether or not to send gratuitous ARPs (C<--gratuitous>).

=item I<INIT_MODE>

Specify the C<--init> state.

=item I<LOGMASK> (string)

The value for L<--logmask|/--logmask>. Note that negations
(starting with "!") should be escaped to prevent history
expansion in shells.

=item I<LEARNING> (integer)

How many seconds to spend in learning mode.

=item I<PENDING>

The argument to C<--pending>.

=item I<PASSIVE_MODE> (boolean)

Whether or not to turn on the L<--passive|/--passive> flag.

=item I<PERMISSIONS>

The argument to C<--permissions>.

=item I<QUEUE_DEPTH> (integer)

The argument to C<--queuedepth>.

=item I<RATE> (integer)

The argument to C<--rate>.

=item I<SPONGE_NETWORK> (boolean)

Use C<--sponge-network>

=item I<SPONGE_VAR> (default: F</run/arpsponge>)

Directory root that holds state information for the various sponge
instances. The script will create the directory if it doesn't exist yet.
Together with the interface (I<$INTERFACE>) this is used to specify the
I<rundir> to the sponge ("B<--rundir>=I<$SPONGE_VAR>/I<$INTERFACE>").

=item I<STATIC_MODE> (boolean)

Whether or not to turn on the L<--static|/--static> flag.

=item I<SWEEP>

The argument to C<--sweep>.

=item I<SWEEP_AT_START> (boolean)

Use C<--sweep-at-start>

=item I<SWEEP_SKIP_ALIVE> (boolean)

Use C<--sweep-skip-alive>

=back

=head3 Per-interface variables

The per-interface configuration files can override each of the above and
can also specify:

=over 4

=item I<NETWORK> (mandatory)

This specifies the network for which to sponge.

Note that this variable must be set in the interface-specific configuration
file (setting it in the global defaults file will have no effect, other than
a warning).

=item I<DEVICE> (optional)

By default, the init script will use the configuration file's name
as the device name, but this can be overridden with the I<DEVICE>
variable.

Note that this variable must be set in the interface-specific configuration
file (setting it in the global defaults file will have no effect, other than
a warning).

=item I<STATIC_STATE_FILE> (string)

If I<STATIC_MODE> is true, this variable can be used to specify
a file with a status dump to load on (re)start of the ARP sponge.

See L<asctl's "load status" command|"asctl/load status"> for more
information.

Note that this variable must be set in the interface-specific configuration
file (setting it in the global defaults file will have no effect, other than
a warning).

=back

=head1 FILES

=over 4

=item F</etc/init.d/arpsponge>

Init script for the arpsponge.

=item F</etc/defaults/arpsponge/defaults>

Contains default options for the sponge's
L<B<init>(1)|init> script.

=item F</etc/defaults/arpsponge/interfaces.d/if_name>

Contains interface specific options for the sponge on I<ethX>.
This I<must> define the C<NETWORK> variable.

This is used by the sponge's
L<B<init>(1)|init> script,
see also L<SYSTEM INIT SCRIPT|/SYSTEM INIT SCRIPT>.

=item F</etc/defaults/arpsponge/ethX> (LEGACY)

Contains (I<LEGACY>) interface specific options for the sponge on I<ethX>.
This I<must> define the C<NETWORK> variable.

This is used by the sponge's
L<B<init>(1)|init> script,
see also L<SYSTEM INIT SCRIPT|/SYSTEM INIT SCRIPT>.

=item F</run/arpsponge/if_name/status>

Status file for the sponge daemon that runs on interface I<if_name>.
This is set up by the sponge's
L<B<init>(1)|init> script.

=item F</run/arpsponge/if_name/control>

Control socket for L<B<asctl>(8)|asctl>.
This is set up by the sponge's
L<B<init>(1)|init> script.

=item F</run/arpsponge/if_name/pid>

PID file for the sponge daemon that runs on interface I<if_name>.
This is set up by the sponge's
L<B<init>(1)|init> script.

=back

=head1 SEE ALSO

L<B<arp>(8)|arp.8>,
L<B<asctl>(1)|asctl.1>,
L<B<aslogtail>(1)|aslogtail.1>,
L<B<init>(1)|init.1>,
L<B<sh>(1)|sh.1>.

=over

=item Ethernet Adress Resolution Protocol (ARP):

L<RFC 826|https://tools.ietf.org/html/rfc826>

=item IP Address Conflict Detection:

L<RFC 2131, p38, bottom|https://tools.ietf.org/html/rfc2131#page-38>

L<RFC 5227|https://tools.ietf.org/html/rfc5227>

=item IPv4 host addressing:

L<Section 4.2.3 of RFC-1812|https://tools.ietf.org/html/rfc1812#section-4.2.3>

L<Section 3.2.1.3 of RFC-1122|https://tools.ietf.org/html/rfc1122#section-3.2.1.3>

=back

=head1 BUGS AND LIMITATIONS

=over 3

=item *

Nothing prevents multiple sponge instances for the same interface/network
from being run if they specify different PID files.

=item *

You can specify only one network prefix to listen to per interface.
If you want to monitor multiple prefixes, you will have to find a common
prefix and monitor that.

=item *

The C<--proberate> is implemented by using a C<select> loop on the
network interface and control socket. Therefore, a fixed, system-dependent
overhead delay is introduced between packets, and, in case traffic is coming
in, further overhead in handling that traffic.

As a result of this, the parameter should be seen as an upper limit,
not an exact figure.

=back

=head1 AUTHORS

Arien Vijn at AMS-IX (arien.vijn@ams-ix.net) created the original
version in 2003.

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net) has been extending and
maintaining this since 2004.

=head1 COPYRIGHT

Copyright 2003-2021, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
