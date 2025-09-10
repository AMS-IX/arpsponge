###############################################################################
#
# ARP sponge
#
# (c) Copyright AMS-IX B.V. 2003-2025; all rights reserved.
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
use Types::Standard        qw( Bool InstanceOf Int Maybe Num Str );
use Types::Common::String  qw( NonEmptyStr );
use Types::Common::Numeric qw(
    IntRange PositiveInt PositiveOrZeroInt PositiveOrZeroNum
);

use Getopt::Long qw( GetOptionsFromArray :config bundling );
use Pod::Usage;
use Pod::Find qw( pod_where );
use FindBin;
use Data::Dump qw( dump );

use Net::Pcap qw(
    pcap_dispatch pcap_get_selectable_fd
    pcap_open_live pcap_setnonblock
    pcap_sendpacket
);

use constant FALSE  => !1;

use NetAddr::IP         qw( :lower );
use Time::HiRes         qw( time sleep );
use Time::Piece         qw( localtime );
use POSIX               qw( :signal_h :errno_h _exit setsid );
use File::Path          qw( mkpath );

use IO::Select;

use M6::ArpSponge::App::Settings;
use M6::ArpSponge::App::HostInfo;

use M6::ArpSponge::ArpTable;
use M6::ArpSponge::Control::Server;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Event        qw( :const :func );
use M6::ArpSponge::Log          qw( :macros :func !log_level );
use M6::ArpSponge::NetPacket    qw( :all );
use M6::ArpSponge::Queue;
use M6::ArpSponge::State        qw( :const :func );
use M6::ArpSponge::StateTable;
use M6::ArpSponge::UpdateFlags  qw( :const :func );
use M6::ArpSponge::Util         qw( :all );

###############################################################################

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
my $PCAP_TIMEOUT_MS     = 5;

# Seconds between periodic task checks.
use constant    TIMER_CYCLE => 1.0;

###############################################################################

my $Block_Sigset   = POSIX::SigSet->new(SIGUSR1, SIGHUP, SIGALRM);

# Keep track of how many errors we've seen and when we logged the
# last error. This is used to suppress too much logging.
my $Last_Select_Error_Time  = 0;
my $Last_Select_Error       = 0;
my $Select_Error_Count      = 0;

#############################################################################
# Attributes & Constructor Arguments
#############################################################################

# Required
has device    => ( is => 'ro', required => 1, isa => NonEmptyStr );
has network   => ( is => 'ro', required => 1, isa => HexIpType );
has prefixlen => ( is => 'ro', required => 1, isa => IntRange[1, 32] );

# Optional
has arp_update_flags => (
    is => 'rw',
    isa => PositiveOrZeroInt,
    default => \&ARP_UPDATE_ALL
);

has gratuitous => ( is => 'rw', isa => Bool, default => \&FALSE );

has control_socket => (
    is      => 'lazy',
    isa     => Str,
    builder => sub { $_[0]->run_dir . '/control' },
);

has daemon_mode => ( is => 'ro', isa => Bool, default => \&FALSE );
has dummy_mode  => ( is => 'rw', isa => Bool, default => \&FALSE );

has flood_protection => (
    is      => 'rw',
    isa     => PositiveInt,
    default => \&M6::ArpSponge::Defaults::FLOOD_PROTECTION,
);

has init_state  => (
    is => 'rw',
    isa => IntRange[STATE_MIN],
    default => NONE,
);

has learn_time => (
    is      => 'rw',
    isa     => PositiveOrZeroInt,
    default => \&M6::ArpSponge::Defaults::LEARN_TIME,
);

has log_level => (
    is  => 'rw',
    isa => PositiveOrZeroInt,
    trigger => sub { M6::ArpSponge::Log::log_level($_[1]) }
);

has log_mask => (
    is  => 'rw',
    isa => PositiveOrZeroInt,
    trigger => sub { event_mask($_[1]) },
);

has max_arp_age => (
    is      => 'rw',
    isa     => PositiveOrZeroInt,
    default => \&M6::ArpSponge::Defaults::MAX_ARP_AGE,
);

has max_arp_rate => (
    is      => 'rw',
    isa     => PositiveOrZeroInt,
    default => \&M6::ArpSponge::Defaults::MAX_ARP_RATE,
);

has max_pending => (
    is      => 'rw',
    isa     => PositiveInt,
    default => \&M6::ArpSponge::Defaults::MAX_PENDING
);

has passive_mode => ( is => 'rw', isa => Bool, default => \&FALSE );

has pid_file => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub { $_[0]->run_dir . '/pid' },
);

has probe_rate => (
    is      => 'rw',
    isa     => PositiveInt,
    default => \&M6::ArpSponge::Defaults::PROBE_RATE,
    trigger => sub { $_[0]->_set_probe_sleep(1.0/$_[1]) },
);

has run_dir => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub {
        M6::ArpSponge::Defaults->RUN_DIR . '/' . $_[0]->device
    }
);

has sponge_network => ( is => 'rw', isa => Bool, default => \&FALSE );

has status_file => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub { $_[0]->run_dir . '/status' },
);


for my $attr (qw( socket_uid socket_gid socket_mode )) {
    has $attr => (
        is  => 'ro',
        isa => Int->where(sub { $_ >= 0 }),
        default => sub { 0 },
    );
}

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
    trigger => sub {
        my ($self, $level) = @_;
        log_is_verbose($level);
    },
);

#############################################################################
# Read-only, Automatic, Internal Attributes.
#############################################################################

has control_fh => ( is => 'rwp', init_arg => undef );

my @RO_INTERNAL   = ( is => 'ro',   init_arg => undef );
my @RWP_INTERNAL  = ( is => 'rwp',  init_arg => undef );
my @LAZY_INTERNAL = ( is => 'lazy', init_arg => undef );

has forced_passive_mode => (
    @RWP_INTERNAL,
    isa      => Bool,
    default  => \&FALSE,
);

has io_select => (
    @RWP_INTERNAL,
    isa => InstanceOf['IO::Select'],
    default => sub { IO::Select->new() },
);

has next_sweep_at => (
    @RWP_INTERNAL,
    isa => Num,
    default => sub { 0 },
);

has pcap_handle => (
    @RWP_INTERNAL,
    trigger => sub {
        my ($self, $pcap_h) = @_;

        my ($pcap_fh, $pcap_fd);
        if ($pcap_h) {
            $pcap_fd = pcap_get_selectable_fd($pcap_h);
            if ($pcap_fd < 0) {
                log_fatal("cannot get selectable fd for %s", $self->device);
            }
            $pcap_fh = IO::Handle->new();
            if (!$pcap_fh->fdopen($pcap_fd, 'r')) {
                log_fatal("fdopen(%d, 'r') for '%s' failed: %s",
                            $pcap_fd, $self->device, $!);
            }
        }
        $self->_set_pcap_fh($pcap_fh);
    },
);

has pcap_fh => (@RWP_INTERNAL);

has probe_sleep => (
    @RWP_INTERNAL,
    lazy => 1,
    isa => PositiveOrZeroNum,
    builder => sub { 1.0/$_[0]->probe_rate },
);

has select_error_count => (
    @RWP_INTERNAL,
    default => sub { 0 },
);

has select_error_last_time => (
    @RWP_INTERNAL,
    default => sub { 0 },
);

has select_error => (
    @RWP_INTERNAL,
    default => sub { !1 },
);

has start_time => (
    @RWP_INTERNAL,
    isa => Num->where(sub { $_ >= 0 }),
    default => sub { 0 },
);

sub version {
    return $M6::ArpSponge::VERSION;
}

# Keep track of whether we wrote a PID file.
has wrote_pid => (
    @RWP_INTERNAL,
    isa => Bool,
    default => sub { 0 },
);

# Keep track of the "main" daemon PID, i.e. the one
# that should perform all the cleanup.
has main_pid => (
    @RWP_INTERNAL,
    isa => Int,
    default => sub { $$ },
);

has host_info => (
    @LAZY_INTERNAL,
    builder  => sub {
        M6::ArpSponge::App::HostInfo->new(device => $_[0]->device);
    },
    handles  => [qw(
        my_ip  my_ip_s my_ip_all
        my_mac my_mac_s
        is_my_ip is_my_ip_s
    )],
);

has arp_table => (
    @RO_INTERNAL,
    isa      => InstanceOf['M6::ArpSponge::ArpTable'],
    default  => sub { M6::ArpSponge::ArpTable->new },
);

has queue => (
    @RO_INTERNAL,
    isa      => InstanceOf['M6::ArpSponge::Queue'],
    default  => sub { M6::ArpSponge::Queue->new() },
    handles  => { queue_depth => 'max_depth' },
);

has state_table => (
    @RO_INTERNAL,
    isa      => InstanceOf['M6::ArpSponge::StateTable'],
    default  => sub { M6::ArpSponge::StateTable->new },
    handles => {
        get_state_atime => 'get_atime',
        set_state_atime => 'set_atime',
        get_state_mtime => 'get_mtime',
        set_state_mtime => 'set_mtime',
        get_state       => 'get_state',
        get_state_info  => 'get_state_info',
        get_all_pending => 'get_all_pending',
    },
);

has phys_device => (
    @LAZY_INTERNAL,
    builder  => sub { (split(/:/, $_[0]->device))[0] },
);

has broadcast => (
    @LAZY_INTERNAL,
    builder => sub { ip2hex($_[0]->_network_obj->broadcast->addr) },
);

has broadcast_s => (
    @LAZY_INTERNAL,
    builder => sub { hex2ip($_[0]->broadcast) },
);

has network_lo_i => (
    @LAZY_INTERNAL,
    builder => sub { $_[0]->_network_obj->first->numeric },
);

has network_hi_i => (
    @LAZY_INTERNAL,
    builder => sub { $_[0]->_network_obj->last->numeric },
);

has network_s => (
    @LAZY_INTERNAL,
    builder => sub { hex2ip($_[0]->network) },
);

has _network_obj => (
    @LAZY_INTERNAL,
    builder => sub {
        my ($self) = @_;
        NetAddr::IP->new(hex2ip($self->network)."/".$self->prefixlen);
    }
);

sub BUILD {
    my ($self, $args) = @_;

    if (exists $args->{queue_depth}) {
        $self->queue->max_depth($args->{queue_depth});
    }
}


sub DEMOLISH {
    my ($self, $in_global_destruction) = @_;

    return if $$ != $self->main_pid;

    event_info(EVENT_STATE, "cleaning up");

    if ($self->wrote_pid) {
        my $pid_file = $self->pid_file;
        event_info(EVENT_STATE,
            "unlinking PID file '%s'", $pid_file);
        unlink($pid_file);
    }

    if (defined $self->control_fh) {
        my $socket_file = $self->control_socket;
        if (defined $socket_file && -e $socket_file) {
            event_info(EVENT_STATE,
                "unlinking control socket '%s'", $socket_file);
            unlink($socket_file);
        }
    }
}

sub state_name      { return state_to_string($_[1]) }

sub new_from_cli {
    my ($class, %arg) = @_;

    init_log() if !log_is_active();

    my $settings = M6::ArpSponge::App::Settings->new();

    $settings->parse_command_line(%arg);
    if ($settings->error) {
        die $settings->prog_name, ": ", $settings->error,
            "\n", $settings->usage_msg;
    }

    return $class->new(%{$settings->hash});
}


sub setup {
    my ($self) = @_;

    init_log() if !log_is_active();

    event_notice(EVENT_STATE, "initialising [device=%s, ip=%s, mac=%s]",
                $self->device, $self->my_ip_s, $self->my_mac_s);

    $self->_set_start_time(time);

    # Create the run directory for the sponge.
    my $run_dir = $self->run_dir;
    mkpath($run_dir, { mode => 0775, error => \my $err });
    if (@$err) {
        my $msg = LOG_IDENT.": errors creating '$run_dir'\n";
        for my $diag (@$err) {
            my ($file, $str) = %$diag;
            $msg .= LOG_IDENT.": mkdir '$file': " if length $file;
            $msg .= "$str\n";
        }
        log_fatal($msg);
    }

    if ($self->my_ip eq IPV4_ADDR_NONE) {
        if (!$self->passive_mode) {
            event_alert(EVENT_STATE,
                "%s has no IP address; forcing passive-mode", $self->device);
            $self->passive_mode(1);
            $self->_set_forced_passive_mode(1);
        }
    }

    $self->open_capture();
    $self->create_control_socket();

    log_sverbose(1, "%-7s %s (%s)\n", "Device", $self->device, $self->phys_device);
    log_sverbose(1, "%-7s %s\n", "MAC", $self->my_mac_s);
    log_sverbose(1, "%-7s %s\n", "IP", $self->my_ip_s);
}


sub run {
    my ($self) = @_;

    # If we have to run in daemon mode, do so.
    if ($self->daemon_mode) {
        $self->start_daemon();
    }

    event_notice(EVENT_STATE, "running [device=%s, ip=%s, mac=%s]",
                $self->device, $self->my_ip_s, $self->my_mac_s);

    $self->init_all_state($self->init_state);

    $self->setup_signal_handlers(1);

    $self->packet_capture_loop();

    $self->setup_signal_handlers(0);

    event_notice(EVENT_STATE, "stopping [device=%s, ip=%s, mac=%s]",
                $self->device, $self->my_ip_s, $self->my_mac_s);
}


###############################################################################
# $bool = $sponge->is_my_network($hex_ip)
# $bool = $sponge->is_my_network_s($ip_str)
#
#   Returns whether or not the argument is in the monitored
#   network range(s).
#
###############################################################################
sub is_my_network {
    my ($self, $ip) = @_;
    return hex_addr_in_net($ip, $self->network, $self->prefixlen);
}

sub is_my_network_s {
    my ($self, $ip) = @_;
    return $self->is_my_network(ip2hex($ip));
}

###############################################################################
# $sponge->init_all_state($init_state);
#
#   Wipe all state info from the sponge. This includes all IP state info,
#   all queue info, all timings, all ARP info.
#
#   The only info left in the tables is the sponge's own address.
#
###############################################################################
sub init_all_state {
    my ($self, $init_state) = @_;

    $self->arp_table->purge();
    $self->state_table->clear_all();
    $self->queue->clear_all();

    # Build up a bit of state again...

    if (defined $init_state && $init_state != NONE) {
        my $lo = $self->network_lo_i;
        my $hi = $self->network_hi_i;
        for (my $num = $lo; $num <= $hi; $num++) {
            my $ip = sprintf("%08x", $num);
            $self->state_table->set_state($ip, $init_state, 0);
        }
    }

    if ($self->sponge_network) {
        # Statically sponge network and broadcast addresses.
        $self->state_table->set_state($self->network, STATIC);
        $self->state_table->set_state($self->broadcast, STATIC);
    }

    for my $ip ($self->my_ip_all) {
        $self->set_alive($ip, $self->my_mac);
    }

    return;
}


###############################################################################
# $sponge->set_alive($ip, $target_mac);
#
#   Unsponge the $ip, which is now seen from $target_mac.
#   Update ARP cache and print appropriate notifications.
#
###############################################################################
sub set_alive {
    my ($self, $ip, $mac) = @_;

    return if ! $self->is_my_network($ip);

    my @old_arp = $self->arp_table->lookup_ip($ip);
    my $old_state = $self->get_state($ip);

    $mac //= $old_arp[0] // ETH_ADDR_NONE;

    if (log_is_verbose) {
        if (!@old_arp) {
            log_sverbose(1, "learned: ip=%s mac=%s old=none\n",
                               hex2ip($ip), hex2mac($mac));
        }
        elsif ($old_arp[0] ne $mac) {
            log_sverbose(1, "learned: ip=%s mac=%s old=%s\n",
                              hex2ip($ip), hex2mac($mac), hex2mac($old_arp[0]));
        }
        log_sverbose(1,
            "clearing: ip=%s mac=%s\n", hex2ip($ip), hex2mac($mac));
    }

    $self->queue->clear($ip);
    $self->state_table->set_state($ip, ALIVE);
    $self->arp_table->add($ip, $mac, time);

    if (defined $old_state && $old_state == DEAD) {
        event_info(EVENT_SPONGE,
            "unsponging: ip=%s mac=%s", hex2ip($ip), hex2mac($mac));
        return;
    }

    event_info(EVENT_SPONGE,
        "clearing: ip=%s mac=%s", hex2ip($ip), hex2mac($mac));
    return;
}


###############################################################################
# $state = $sponge->set_pending($ip, $n);
#
#   Set $ip's state to PENDING "$n". Returns new state.
#
###############################################################################
sub set_pending {
    my ($self, $ip, $n) = @_;
    my $state = $self->state_table->set_state($ip, PENDING($n));
    event_notice(EVENT_SPONGE, "pending: ip=%s state=%d", hex2ip($ip), $n);
    return $state;
}

###############################################################################
# $state = $sponge->incr_pending($ip);
#
#   Increment $ip's PENDING state. Returns new state.
#
###############################################################################
sub incr_pending {
    my ($self, $ip) = @_;
    my $pending = $self->get_state($ip) - PENDING(0);
    return $self->set_pending($ip, $pending+1);
}


###############################################################################
# $sponge->set_dead($ip);
#
#    Set $ip's state to DEAD (i.e. "sponged").
#
###############################################################################
sub set_dead {
    my ($self, $ip) = @_;
    my $rate = $self->queue->rate($ip) // 0.0;

    event_notice(EVENT_SPONGE,
        "sponging: ip=%s rate=%0.1f", hex2ip($ip), $rate);

    $self->send_gratuitous_arp($ip) if $self->gratuitous;
    $self->state_table->set_state($ip, DEAD);
}

###############################################################################
# $sponge->set_static($ip);
#
#    Set $ip's state to STATIC (i.e. "permanently sponged").
#
###############################################################################
sub set_static {
    my ($self, $ip) = @_;
    my $rate = $self->queue->rate($ip) // 0.0;

    event_notice(EVENT_SPONGE,
        "static sponging: ip=%s rate=%0.1f", hex2ip($ip), $rate);

    $self->send_gratuitous_arp($ip) if $self->gratuitous;
    $self->state_table->set_state($ip, STATIC);
}

###############################################################################
# $sponge->send_arp_who_has($ip);
#
#   Send a ARP "WHO HAS $ip" query. This prevents us from
#   erroneously sponging when there's a cretin sending ARP floods.
#
###############################################################################
sub send_arp_who_has {
    my ($self, $ip) = @_;

    if (log_is_verbose >=2) {
        log_sverbose(2,
            "Querying [dev=%s]: %s\n", $self->phys_device, hex2ip($ip)
        );
    }

    $self->set_state_atime($ip, time);

    $self->send_arp_pkt(
        tha => ETH_ADDR_BROADCAST,
        tpa => $ip,
        opcode => ARP_OPCODE_REQUEST
    );
    return;
}

###############################################################################
# $sponge->send_gratuitous_arp($ip);
#
#   Send a (sponge) ARP WHO HAS $ip TELL $ip".
#
###############################################################################
sub send_gratuitous_arp {
    my ($self, $ip) = @_;

    if (log_is_verbose) {
        log_sverbose(1, "%sgratuitous ARP [dev=%s]: %s\n",
                ($self->dummy_mode ? '[DUMMY] ' : ''),
                $self->phys_device, hex2ip($ip));
    }

    $self->set_state_atime($ip, time);

    return if $self->dummy_mode;

    my $ip_s = hex2ip($ip);
    $self->send_arp_pkt(
        spa => $ip,
        tha => ETH_ADDR_BROADCAST,
        tpa => $ip,
        opcode => ARP_OPCODE_REQUEST );
}

###############################################################################
# $sponge->send_arp_pkt($opcode, $sha, $spa, $tha, $tpa);
#
#   Send an ARP packet.
#
###############################################################################
sub send_arp_pkt {
    my ($self, %args) = @_;

    my $pcap_h = $self->pcap_handle or return;

    $args{spa}      //= $self->my_ip;
    $args{sha}      //= $self->my_mac;
    $args{src_mac}  //= $self->my_mac;
    $args{dest_mac} //= $args{tha};
    $args{opcode}   //= ARP_OPCODE_REQUEST;

    my $pkt = encode_ethernet({
        dest_mac => $args{tha},
        src_mac  => $args{src_mac},
        type     => ETH_TYPE_ARP,
        data     => encode_arp({
            sha => $args{sha},
            spa => $args{spa},
            tha => $args{tha},
            tpa => $args{tpa},
            opcode => $args{opcode},
        })
    });

    if (pcap_sendpacket($pcap_h, $pkt) < 0) {
        event_err(EVENT_IO, "ERROR sending ARP packet: %s", $!);
    }
    return;
}

###############################################################################
# $sponge->send_arp_update(%args);
#
#   Try to update TPA@THA that SPA is now at SHA.
#   Use a variety of methods for this.
#
###############################################################################
sub send_arp_update {
    my ($self, %args) = @_;

    my $pcap_h = $self->pcap_handle;

    if (!$pcap_h || log_is_verbose) {
        my $tha = hex2mac($args{tha});
        my $tpa = hex2ip($args{tpa});
        my $sha = hex2mac($args{sha});
        my $spa = hex2ip($args{spa});
        my $tag = $args{tag} // '';
        log_sverbose(1, "%s%sarp inform %s\@%s about %s\@%s\n",
            $tag,
            (!$pcap_h || $self->dummy_mode ? '[DUMMY] ' : ''),
            $tpa, $tha,
            $spa, $sha,
        );
    }
    return if (!$pcap_h || $self->dummy_mode);

    my $update_flags = $self->arp_update_flags;

    # Try various ways of updating the neighbour's cache...
    #
    # The goal is to inform <TPA>@<THA> about <SPA>@<SHA>.
    #
    if ($update_flags & ARP_UPDATE_REPLY) {
        # Unsollicited ARP reply:
        #
        #   Send to <THA>:
        #       ARP <SPA> IS-AT <SHA>
        #
        $self->send_arp_pkt(
            sha => $args{sha},
            spa => $args{spa},
            tha => $args{tha},
            tpa => $args{tpa},
            opcode => ARP_OPCODE_REPLY );
    }

    if ($update_flags & ARP_UPDATE_REQUEST) {
        # Request <TPA> on behalf of <SPA>; send to <THA> as unicast.
        #
        # The idea is that <TPA> responds with a "IS-AT" to <SPA>@<SHA>,
        # updating its own ARP cache for <SPA>.
        #
        #   Send to <THA>:
        #       ARP WHO-HAS <TPA> TELL <SPA>@<SHA>
        #
        $self->send_arp_pkt(
            sha => $args{sha},
            spa => $args{spa},
            tha => $args{tha},
            tpa => $args{tpa},
            opcode => ARP_OPCODE_REQUEST );
    }

    if ($update_flags & ARP_UPDATE_GRATUITOUS) {
        # Fake a gratuitous ARP, sent as a unicast message:
        # "gratuitous unicast proxy ARP request" :-)
        #
        #   Send to <THA>:
        #       ARP WHO-HAS <SPA> TELL <SPA>@<SHA>
        #
        # The idea is that <THA> updates its own ARP cache for <SPA>.
        #
        $self->send_arp_pkt(
            sha => $args{sha},
            spa => $args{spa},
            tha => $args{tha},
            tpa => $args{spa},
            opcode => ARP_OPCODE_REQUEST );
    }
    return;
}

###############################################################################
# $sponge->send_sponge_reply($src_ip, $arp_obj);
#
#   Send a (sponge) ARP "$src_ip IS AT" in reply to the $arp_obj request.
#
###############################################################################
sub send_sponge_reply {
    my ($self, $src_ip, $arp_obj) = @_;

    $self->set_state_atime($src_ip, time);

    my $pcap_h = $self->pcap_handle;

    if (!$pcap_h || $self->dummy_mode) {
        my $dst_mac_s = hex2mac($arp_obj->{sha});
        my $dst_ip_s  = hex2ip($arp_obj->{spa});
        my $src_ip_s  = hex2ip($src_ip);
        log_sverbose(1, "%s: DUMMY sponge reply to %s\@%s\n",
                           $src_ip_s, $dst_ip_s, $dst_mac_s);
        return;
    }

    if (log_is_verbose) {
        my $dst_mac_s = hex2mac($arp_obj->{sha});
        my $dst_ip_s  = hex2ip($arp_obj->{spa});
        my $src_ip_s  = hex2ip($src_ip);
        log_sverbose(1, "%s: sponge reply to %s\@%s\n",
                           $src_ip_s, $dst_ip_s, $dst_mac_s);
    }

    $self->send_arp_pkt(
        spa => $src_ip,
        tha => $arp_obj->{sha},
        tpa => $arp_obj->{spa},
        opcode => ARP_OPCODE_REPLY );

    return;
}


###############################################################################
###############################################################################
###############################################################################

sub packet_capture_loop {
    my ($self) = @_;

    $self->io_select->add($self->control_fh);
    $self->io_select->add($self->pcap_fh);

    event_info(EVENT_STATE, "entering packet capture loop");
    my $next_alarm = $self->reset_timer(time);

    while (1) {
        $self->handle_input($next_alarm);
        $self->handle_timer();
        $next_alarm = $self->reset_timer($next_alarm);
    }
    event_info(EVENT_STATE, "exiting packet capture loop");
}


sub exit_on_signal {
    my ($self, $sig_name) = @_;

    event_notice(EVENT_STATE, "received %s signal", $sig_name);
    exit(0);
}


sub write_status {
    my ($self, $sig_name) = @_;
    event_notice(EVENT_STATE, "received %s signal", $sig_name);
    event_notice(EVENT_STATE, "TBD: write_status()");
}


sub setup_signal_handlers {
    my ($self, $activate) = @_;

    if ($activate) {
        event_info(EVENT_STATE, "adding signal handlers");
        $::SIG{INT} = $::SIG{QUIT} = $::SIG{TERM}
            = sub { $self->exit_on_signal($_[0]) };

        $::SIG{'HUP'} = $::SIG{'USR1'}
            = sub { $self->write_status($_[0]) };
    }
    else {
        event_info(EVENT_STATE, "removing signal handlers");
        delete @::SIG{qw(INT QUIT TERM)};
        delete @::SIG{qw(HUP USR1)};
    }
}


###############################################################################
# $next_alarm = $self->reset_timer($prev_alarm)
#
#    Calculate when we need to run our timer trigger again.
#    Normally, this is $prev_alarm + TIMER_CYCLE, but if that
#    has already passed (which can happen if the timer trigger
#    is slow), we need to adjust our cycle.
#
###############################################################################
sub reset_timer {
    my ($self, $next_alarm) = @_;

    my $now = time;

    # Keep the intervals as steady as possible by keying off
    # of the previous alarm time if possible.
    $next_alarm += TIMER_CYCLE;

    if ($next_alarm > $now) {
        return $next_alarm;
    }

    # We've been dragging our feet. Rather than setting a new alarm time
    # that's already _now_ or in the past, adjust the next alarm to offset
    # from the current time.
    # This is not elegant, but it's better than running timer triggers in
    # tight loops.
    my $caller = (caller(1))[3];
    my $adjusted = $now + TIMER_CYCLE;
    event_warning(EVENT_STATE,
        "$caller - timer event LAG: %s; %s",
        localtime($next_alarm)->strftime("planned=%T"),
        localtime($adjusted)->strftime("adjusted=%T"),
    );
    return $adjusted;
}


###############################################################################
# handle_input
#
#    Handle input (packets, etc.) for a specific amount of time.
#
###############################################################################
sub handle_input {
    my ($self, $next_alarm) = @_;

    my $pcap_h     = $self->pcap_handle;
    my $pcap_fh    = $self->pcap_fh;
    my $control_fh = $self->control_fh;
    my $control_fd = $control_fh->fileno;

    my $io_select = $self->io_select;

    # [1] We keep track of the alarms ourselves rather than setting timers
    #     with alarm(), since the ALRM signal handler may be delayed, which
    #     would cause subsequent alarm() settings to be delayed as well.
    #
    # [2] Rather than just waiting for the select() to time out, we check
    #     the remaining timeout just before going into the select() call.
    #
    # [3] We rely on select() with a max. timeout of (next_alarm - now).
    #
    # [4] If packets come in before the timer expires, we process them and
    #     adjust the timeout in the next round.

    while (1) {
        my $now = time;
        if ($now >= $next_alarm) {  # [2]
            # We've overrun our timeout during the previous iteration,
            # so let's return now.
            return;
        }

        # [3] Wait for something to happen (timeout, signal or packet).
        $! = 0;
        my @ready = $io_select->can_read($next_alarm - $now);

        $now = time; # Update time.

        if (@ready == 0) {
            # Ignore timeout and EINTR errors; they are expected.
            next if $! == 0 || $! == EINTR;

            # A signal or another error.
            my $err = $!;

            $self->record_select_error($now, $err);
            next;
        }

        $self->flush_select_error($now);

        for my $ready_fh (@ready) {
            if ($ready_fh eq $pcap_fh) { # [4]
                sigprocmask(SIG_BLOCK, $Block_Sigset);
                pcap_dispatch(
                    $pcap_h, $MAX_PKT_PER_CYCLE, \&process_pkt, $self);
                sigprocmask(SIG_UNBLOCK, $Block_Sigset);
                next;
            }
            if ($ready_fh eq $control_fh) {
                if (my $client = $control_fh->accept()) {
                    $io_select->add($client);
                    add_notify($client);
                    event_info(EVENT_CTL,
                        "[client %d] connected", $client->fileno);
                    next;
                }
                log_fatal(
                    "cannot accept control connection: %s",
                    $control_fh->error
                );
            }
            if (!$ready_fh->handle_command($self)) {
                $io_select->remove($ready_fh);
                remove_notify($ready_fh);
                event_info(EVENT_CTL,
                    "[client %d] disconnected", $ready_fh->fileno);
                $ready_fh->close;
                next;
            }
        }
    }
}


sub flush_select_error {
    my ($self, $now) = @_;

    my $count = $self->select_error_count;
    return if $count <= 1;

    my $last_ts = $self->select_error_last_time;

    return if $now && $now < $last_ts + 15;

    # We've seen multiple select errors in the last 15 seconds.
    # Only the first was logged. Log the number of repetitions.
    event_err(EVENT_IO,
            "previous select error repeated %d time(s): %s",
            $count-1, $self->select_error);

    $self->_set_select_error_last_time(0);
    $self->_set_select_error_count(0);
    $self->_set_select_error(!1);
    return;
}

sub record_select_error {
    my ($self, $now, $err) = @_;

    if ($self->select_error != $err) {
        $self->flush_select_error(0);
        $self->_set_select_error($err);
        event_err(EVENT_IO, "error in select(): %s", $!);
        $self->_set_select_error_count(1);
    }

    $self->_set_select_error_last_time($now);
    $self->_set_select_error_count($self->select_error_count+1);
    $self->flush_select_error($now);
    return;
}


###############################################################################
# $self->process_pkt($hdr, $pkt);
#
#    Called by pcap_dispatch() as:
#
#        process_pkt($self, $hdr, $pkt);
#
#    Process sniffed packets. The "$self" parameter is what was passed
#    as the "user data" parameter to the pcap_dispatch() call. In our
#    case, that is the M6::ArpSponge::App instance, a.k.a. "$self".
#
###############################################################################
sub process_pkt {
    my ($self, $hdr, $pkt) = @_;
    my $eth_obj = decode_ethernet($pkt);
    my $src_mac = $eth_obj->{src_mac};

    # Self-generated packets are not relevant.
    return if $src_mac eq $self->my_mac;

    # Always "unsponge" the source IP address on any IP packet.
    if ($eth_obj->{type} == ETH_TYPE_IP) {
        my $ip_obj  = decode_ipv4($eth_obj->{data});
        my $src_ip  = $ip_obj->{src_ip};

        # Nothing to do if the source IP is not on our local network.
        return if ! $self->is_my_network($src_ip);

        # Update state for the source IP address.
        $self->update_state($src_ip, $src_mac);

        # Now, there are cases where a BGP peer A does not update
        # its neighbor cache after we unsponge peer B. This may
        # result in peer A sending traffic for B over us. For normal
        # BGP peerings this never happens (since A and B must communicate
        # directly over BGP), but in the case of a route server this
        # may actually happen, since all the BGP traffic happens
        # indirectly.
        #
        # So, what we are looking for here is a packet with a destination
        # mac set to us, but an IP address that has nothing to do with us.
        # The destination IP must be ALIVE, and we must have MAC for it in
        # our table. If we see this, we send a unicast ARP update with the
        # correct info to the packet's source.
        return if ! $self->arp_update_flags();
        return if $eth_obj->{dest_mac} ne $self->my_mac;

        my $dst_ip = $ip_obj->{dest_ip};
        return if $self->is_my_ip($dst_ip);                   # Not our IP
        return if $self->get_state($dst_ip) != ALIVE();       # IP is alive

        my ($dst_mac, $mtime) = $self->arp_table->lookup_ip($dst_ip);
        return if !$dst_mac or $dst_mac eq ETH_ADDR_NONE;      # MAC is valid
        $self->send_arp_update(
            tha => $src_mac,
            tpa => $src_ip,
            sha => $dst_mac,
            spa => $dst_ip,
            tag => '[auto] ',
        );
        return;
    }

    return if $eth_obj->{type} != ETH_TYPE_ARP;

    # From this point on, we have an ARP packet.

    my $arp_obj = decode_arp($eth_obj->{data});
    my $dst_ip  = $arp_obj->{tpa};
    my $src_ip  = $arp_obj->{spa};

    # Update state for the source IP address.
    $self->update_state($src_ip, $src_mac);

    # Ignore anything that is not an ARP "WHO-HAS" request.
    return if $arp_obj->{opcode} != ARP_OPCODE_REQUEST;

    # From this point on, we have an ARP "WHO-HAS" request.

    if ( $arp_obj->{sha} ne $src_mac ) {
        # Interesting ...
        event_warning(EVENT_SPOOF,
            "ARP spoofing: src.mac=%s arp.sha=%s arp.spa=%s"
            ." arp.tpa=%s dst.mac=%s",
            hex2mac($src_mac), hex2mac($arp_obj->{sha}),
            hex2ip($src_ip),   hex2ip($dst_ip),
            hex2mac($eth_obj->{dest_mac})
        );
    }

    if ( ! $self->is_my_network($dst_ip) ) {
        # We only store/sponge ARPs for our "local" IP addresses.
        event_warning(EVENT_ALIEN,
            "misplaced ARP: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        return;
    }

    if ($self->is_my_ip($dst_ip)) {
        # ARPs for our addresses require no action (handled by the kernel),
        # except for maybe updating our internal ARP table.
        if (log_is_verbose()) {
            log_sverbose(1, "ARP WHO HAS %s TELL %s (for our IP)\n",
                                hex2ip($dst_ip), hex2ip($src_ip));
        }
        $self->set_alive($dst_ip, $self->my_mac);
        return;
    }

    if ($src_ip eq IPV4_ADDR_NONE) {
        # DHCP duplicate IP detection.
        # See RFC 2131, p38, bottom.
        event_notice(EVENT_SPONGE,
                "DHCP duplicate IP detection: src.mac=%s arp.tpa=%s\n",
                hex2mac($src_mac), hex2ip($dst_ip)
            );


        # Mmmh, don't let go completely yet... If all is well,
        # we'll soon start seeing "real" traffic from this
        # address...
        my $state = $self->get_state($dst_ip);
        if (defined $state && $state != ALIVE) {
            $self->set_pending($dst_ip, 0) if !$self->static_mode;
        }
        return;
    }

    # Devices ARPing for the network or broadcast address indicate
    # possible bad netmasks.
    if ($dst_ip eq $self->network) {
        event_warning(EVENT_ALIEN,
            "ARP for network address: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        $self->send_reply($dst_ip, $arp_obj) if $self->sponge_net;
        return;
    }

    if ($dst_ip eq $self->broadcast) {
        event_warning(EVENT_ALIEN,
            "ARP for broadcast address: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        $self->send_reply($dst_ip, $arp_obj) if $self->sponge_net;
        return;
    }

    if (log_is_verbose() >= 2) {
        log_sverbose(2, "ARP WHO HAS %s TELL %s ",
                          hex2ip($dst_ip), hex2ip($src_ip));
        my $state = $self->get_state($dst_ip);
        if ($state <= DEAD) {
            my $age = time - $self->get_state_mtime($dst_ip);
            log_sverbose(2, "[sponged=yes; %d secs ago]\n", $age);
        }
        else {
            log_verbose(2, "[sponged=no]\n");
        }
    }

    my $query_time = time;

    # Don't do anything else if we are still learning.
    return if $self->learn_time;

    $self->queue->add($dst_ip, $src_ip, time);

    my $state = $self->get_state($dst_ip);

    if (!defined $state) {
        # State is not defined (yet), so make it pending.
        $state = $self->set_pending($dst_ip, 0) if !$self->static_mode;
        return;
    }

    # Reply for a dead address.
    if ($state <= DEAD) {
        $self->send_reply($dst_ip, $arp_obj);
        return;
    }

    # PENDING states are handled by the do_timer() routine.
    # So from here on out we are only interested in ALIVE
    # addresses with a full queue and a rate greater than
    # the max rate.
    return if $state != ALIVE;
    return if ! $self->queue->is_full($dst_ip);
    return if $self->queue->rate($dst_ip) <= $self->max_rate;

    # Check for flood protection.
    my $fp_rate = $self->flood_protection;
    if (!$fp_rate) {
        # No flood protection, so just set address to pending.
        $state = $self->set_pending($dst_ip, 0) if !$self->static_mode;
    }

    # In case of flood protection, reduce the queue
    # by removing flooding sources, then check again...
    my $d1 = $self->queue->depth($dst_ip);
    my $r1 = $self->queue->rate($dst_ip);
    my $d2 = $self->queue->reduce($dst_ip, $fp_rate);
    my $r2 = $self->queue->rate($dst_ip);

    if ($d1 != $d2) {
        event_notice(EVENT_SPONGE,
            "%s queue reduced: [depth,rate] = [%d,%0.1f] -> [%d,%0.1f]",
            hex2ip($dst_ip), $d1, $r1, $d2, $r2
        );
    }
    else {
        event_notice(EVENT_SPONGE,
            "%s queue reduction had no effect: [depth,rate] = [%d,%0.1f]",
            hex2ip($dst_ip), $d1, $r1
        );
    }

    if ($self->queue->is_full($dst_ip) && $r2 > $self->max_rate) {
        $state = $self->set_pending($dst_ip, 0) if !$self->static_mode;
    }

    return;
}


###############################################################################
# update_state($sponge, $src_ip, $src_mac);
#
#   Something sent something from [$src_ip, $src_mac]. Update
#   our internal tables if necessary.
#
#   An exception should be made for STATIC entries, since these should
#   be statically sponged.
#
sub update_state {
    my ($self, $src_ip, $src_mac) = @_;

    # Suppress STATIC warnings a bit.
    state $Last_Static_Error_Time  = 0;
    state $Last_Static_Error       = '';
    state $Static_Error_Count      = 0;

    my $now = time;

    if ($Static_Error_Count > 1 && $now > $Last_Static_Error_Time + 15) {
        # We've seen a bunch of warnings in the last 15 seconds.
        # Only the first was logged. Log the number of repetitions.
        event_warning(EVENT_STATIC,
            "previous STATIC warning repeated %d time(s): %s",
            $Static_Error_Count-1, $Last_Static_Error);
        $Static_Error_Count = 0;
        $Last_Static_Error_Time = $now;
    }

    my $state = $self->get_state($src_ip) // ALIVE;

    $state = STATIC if $state < ALIVE && $self->get_attr('static');

    if ($state == STATIC) {
        my $err = sprintf(
            "traffic from STATIC sponged IP: src.mac=%s src.ip=%s",
            hex2mac($src_mac), hex2ip($src_ip),
        );

        if ($err ne $Last_Static_Error) {
            if ($Static_Error_Count > 1) {
                event_warning(EVENT_STATIC,
                    "previous STATIC warning repeated %d time(s): %s",
                    $Static_Error_Count-1, $Last_Static_Error);
            }
            event_warning(EVENT_STATIC, "%s", $err);
            $Static_Error_Count = 0;
            $Last_Static_Error = $err;
            $Last_Static_Error_Time = $now;
        }

        $Static_Error_Count++;

        $self->arp_table->add($src_ip, $src_mac, $now);
        return;
    }

    $self->set_alive($src_ip, $src_mac);
    return;
}


###############################################################################
# $self->handle_timer;
#
#    Called periodically (~ 1/sec) by the processing loop.
#
#    Process & probe pending entries, handle LEARN mode, sweep, etc.
#
###############################################################################
sub handle_timer {
    my ($self) = @_;

    my $learning = $self->learn_time;
    if ($learning > 0) {
        $self->do_learn();
        $learning -= TIMER_CYCLE;
        if ($learning <= 0) {
            event_notice(EVENT_STATE, "exiting learning state");
            $learning = 0;
        }
        $self->learn_time($learning);
        return;
    }

    $self->do_probe_pending;

    my $next_sweep = $self->next_sweep_at;
    if ($next_sweep && time >= $next_sweep) {
        $self->do_sweep;
        $self->_set_next_sweep_at(time+$self->sweep_sec);
    }
    return;
}


sub do_probe_pending {
    my ($self) = @_;

    my $pending     = $self->get_all_pending;
    my $probe_sleep = $self->probe_sleep;

    if ($self->forced_passive_mode) {
        if (keys %{$pending}) {
            # Log reminders that the sponge was started without an IP address,
            # and no --passive flag.
            event_warning(EVENT_STATE,
                "%s has no IP address; forced --passive;"
                ."%d pending addresses not queried",
                $self->device, int(keys %{$pending}),
            );
        }
    }

    log_verbose(2, "Processing pending addresses...\n");
    my $n = 0;
    for my $ip (sort keys %{$pending}) {
        $n++;
        if ($$pending{$ip} > PENDING($self->max_pending)) {
            $self->set_dead($ip);
            next;
        }
        $self->incr_pending($ip);
        if (!$self->passive_mode) {
            $self->send_arp_who_has($ip);
            if (log_is_verbose() > 1) {
                log_sverbose(2, "probed %s, state=%d\n",
                        hex2ip($ip), $self->state_name($pending->{$ip}));
            }
        }
        $self->handle_input(time + $probe_sleep);
    }

    if ($n > 1 || log_is_verbose() > 1) {
        event_notice(EVENT_STATE, "%d pending address(es) processed", $n);
    }
}


sub do_sweep {
    my ($self) = @_;
    event_notice(EVENT_STATE, "TBD: do_sweep()");
}


###############################################################################
# $self->do_learn;
#
#    Called by the do_timer() job scheduler.
#
###############################################################################
sub do_learn($) {
    my ($self) = @_;

    log_verbose(1, "LEARN: ",
                int($self->learn_time), " secs left\n");
    return;
}


###############################################################################
# $self->start_daemon($Pid_File);
#
#   Fork off into the background, i.e. run as a daemon.
#   Create a PID file as well.
#
###############################################################################
sub start_daemon($$) {
    my ($self) = @_;

    my $pid_file = $self->pid_file;

    # First check the PID file to see if we are already running...
    if (-f $pid_file) {
        my $pid;
        if (open my $pid_fh, '<', $pid_file) {
            chomp($pid = <$pid_fh>);
            close $pid_fh;
        }
        if ($pid) {
            my $proc = read_from_pipe(qw( ps h -o args -p ), $pid);
            if (defined $proc && $proc =~ /$FindBin::Script/) {
                log_fatal("already running (pid = $pid)\n");
            }
        }
        my $msg = "removing stale PID file '$pid_file'";
        say STDERR LOG_IDENT.": [WARNING] $msg";
        event_warning(EVENT_STATE, $msg);
        unlink $pid_file;
    }

    # First fork... Parent will read final child pid from pipe, then exit.
    #
    # Child will perform some magic, then fork a grand child and inform
    # the parent process that they're a grand parent now.

    pipe(my $from_child_fh, my $to_parent_fh)
        or log_fatal("pipe() failed: $!");

    PARENT: {
        my $child = fork // log_fatal("cannot fork: $!");
        last PARENT if !$child;

        # Parent of first child. Read the final pid, log it, and exit.
        close $to_parent_fh;
        my $grand_child = <$from_child_fh>;
        close $from_child_fh;

        waitpid $child, 0;
        if ($?) {
            my ($excode, $signal) = ($? >> 8, $? & 127);
            my $msg = "child #$child exited with code $excode";
            $msg .= " (signal $signal)" if $signal;
            log_fatal($msg);
        }

        defined $grand_child
            or log_fatal("failed to get background child pid from %d",
                    $child);
        
        chomp($grand_child);
        if ($grand_child =~ /D/) {
            log_fatal("unexpected PID response from child %d: '%s'",
                $child, $grand_child);
        }

        event_info(EVENT_STATE, "daemon spawned; pid=%d", $grand_child);
        $self->_set_main_pid($grand_child);
        _exit(0);
    }

    CHILD: {
        $self->_set_main_pid(-1);

        my $session_id = setsid();
        if (!defined $session_id || $session_id < 0) {
            log_fatal("setsid() failed: $!\n");
        }

        my $child = fork // log_fatal("cannot fork: %s", $!);
        last CHILD if !$child;

        # Print child PID to parent
        say $to_parent_fh $child;
        close $to_parent_fh;

        _exit(0);
    }

    GRAND_CHILD: {
        # We are the second generation child (grand child), the _real_
        # daemon process.
        $self->_set_main_pid($$);

        event_info(EVENT_STATE, "now running in daemon mode");

        # Child (daemon) process.
        open my $pid_fh, '>', $pid_file
            or log_fatal("cannot write PID to '%s': %s", $pid_file, $!);

        say $pid_fh $$;
        $self->_set_wrote_pid(1);
        close $pid_fh;
        event_info(EVENT_STATE, "wrote PID %d to '%s'", $$, $pid_file);

        # Make sure we go dark.
        $self->verbose(0);
        close STDOUT;
        close STDERR;
        close STDIN;
    }

    return;
}


sub create_control_socket {
    my ($self) = @_;

    my $socket_file = $self->control_socket;

    if (-e $socket_file) {
        if (!unlink $socket_file) {
            log_fatal("%s cannot delete stale '%s': %s",
                LOG_IDENT, $socket_file, $!);
        }
    }

    my $fh = M6::ArpSponge::Control::Server->create_server($socket_file)
                or log_fatal "%s", M6::ArpSponge::Control->error;

    $self->_set_control_fh($fh);

    my ($sock_uid, $sock_gid) = ($self->socket_uid, $self->socket_gid);
    chown($sock_uid, $sock_gid, $socket_file)
        or log_err(qq{chown %s:%s %s: %s},
                    $sock_uid, $sock_gid, $socket_file, $!);

    my $sock_mode = $self->socket_mode;
    chmod($sock_mode, $socket_file)
        or log_err(qq{chmod %04o %s: %s}, $sock_mode, $socket_file, $!);

    event_info(EVENT_STATE,
        "created control socket '%s': uid=%d, gid=%d, mode=%04o",
        $socket_file, $sock_uid, $sock_gid, $sock_mode);

    return;
}


sub open_capture {
    my ($self) = @_;

    my $err;

    my $pcap_h
        = pcap_open_live(
                $self->device,    # capture device
                512,              # snaplen
                1,                # promiscuous
                $PCAP_TIMEOUT_MS, # timeout in ms for a pcap_dispatch
                \$err,            # error diagnostic
        );

    if (!$pcap_h) {
        log_fatal("cannot capture on '%s': %s", $self->device, $err);
    }

    if (pcap_setnonblock($pcap_h, 1, \$err) < 0) {
        log_fatal("cannot capture in non-blocking mode: %s", $err);
    }

    $self->_set_pcap_handle($pcap_h);
}

###############################################################################
# $sponge->clear_state($ip);
#
#   Wipe all state info for $ip from the sponge. This includes the IP state
#   info, queue entries, and ARP info.
#
###############################################################################
sub clear_state {
    my ($self, $ip) = @_;
    $self->state_table->set_state($ip, undef);
    $self->queue->clear($ip);
    $self->arp_table->clear_ip($ip);
    return;
}


1;
