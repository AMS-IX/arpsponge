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
use Types::Standard qw(
    Bool InstanceOf Int Maybe Num Str
);

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
use POSIX               qw( :signal_h :errno_h _exit );
use File::Path          qw( mkpath );

use IO::Select;
use IO::Socket;

use M6::ArpSponge::App::Settings;

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

###############################################################################

my $Block_Sigset   = POSIX::SigSet->new(SIGUSR1, SIGHUP, SIGALRM);
my $Timer_Cycle    = 1.0;

# Keep track of how many errors we've seen and when we logged the
# last error. This is used to suppress too much logging.
my $Last_Select_Error_Time  = 0;
my $Last_Select_Error       = 0;
my $Select_Error_Count      = 0;

#############################################################################
# Attributes & Constructor Arguments
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

has init_state  => (
    is => 'rw',
    isa => Int->where(sub { $_ >= STATE_MIN }),
    default => NONE,
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

has forced_passive_mode => (
    is       => 'rwp',
    isa      => Bool,
    init_arg => undef,
    default  => sub { 0 },
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
    trigger => sub { $_[0]->_set_probe_sleep(1.0/$_[1]) },
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
    my_ip
    my_ip_s
    my_mac
    my_mac_s
    phys_device
    queue_depth
    sponge_network
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
);

#############################################################################
# Read-only, Automatic, Internal Attributes.
#############################################################################

has control_fh => (
    is => 'rwp',
    init_arg => undef,
);

# "pcap_handle" is also stored in "state" object, but it's an r/w
# attribute there. We implement our pcap_handle, that will trigger
# the construction of pcap_fd, pcap_fh and the state's pcap_handle.
    has pcap_handle => (
    is => 'rwp',
    init_arg => undef,
    trigger => sub {
        my ($self, $pcap_h) = @_;

        my ($pcap_fd, $pcap_fh);
        if ($pcap_h) {
            $pcap_fd = pcap_get_selectable_fd($pcap_h);
            if ($pcap_fd < 0) {
                log_fatal("cannot get selectable fd for %s", $self->device);
            }
            $pcap_fh = IO::Handle->new();
            if (!$pcap_fh->fdopen($pcap_fd, "r")) {
                log_fatal("fdopen(%s,'r') for %s failed: %s",
                            $pcap_fd, $self->device, $!);
            }
        }
        $self->state->pcap_handle($pcap_h);
        $self->_set_pcap_fd($pcap_fd);
        $self->_set_pcap_fh($pcap_fh);
    },
);

has pcap_fd => ( is => 'rwp' );
has pcap_fh => ( is => 'rwp' );

has probe_sleep => (
    is => 'rwp',
    lazy => 1,
    isa => Num->where(sub { $_ >= 0 }),
    builder => sub { 1.0/$_[0]->probe_rate },
);

has start_time => (
    is => 'rwp',
    isa => Num->where(sub { $_ >= 0 }),
    init_arg => undef,
    default => sub { 0 },
);

sub version {
    return $M6::ArpSponge::VERSION;
}

has wrote_pid => (
    is  => 'rwp',
    isa => Bool,
    init_arg => undef,
    default => sub { 0 },
);

has main_pid => (
    is  => 'rw',
    isa => Int,
    init_arg => undef,
    default => sub { $$ },
);

sub BUILD {
    my ($self, $args) = @_;

    # Transfer some of the constructor arguments to the
    # 'state' object (M6::ArpSponge::Sponge).
    my $state = $self->state;
    for my $attr (@STATE_ATTR) {
        next if !exists $args->{$attr};
        $state->$attr($args->{$attr});
    }
}


sub DEMOLISH {
    my ($self, $in_global_destruction) = @_;

    return if $$ != $self->main_pid;

    log_info "cleaning up";

    if ($self->wrote_pid) {
        my $pid_file = $self->pid_file;
        log_info "unlinking PID file '%s'", $pid_file;
        unlink($pid_file);
    }

    if (defined $self->control_fh) {
        my $socket_file = $self->control_socket;
        if (defined $socket_file && -e $socket_file) {
            log_info "unlinking control socket '%s'", $socket_file;
            unlink($socket_file);
        }
    }
}

sub new_from_cli {
    my ($class, %arg) = @_;

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

    init_log();
    log_is_verbose($self->verbose);

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

    $self->state->init_all_state($self->init_state);

    event_notice(EVENT_STATE, "stopping [device=%s, ip=%s, mac=%s]",
                $self->device, $self->my_ip_s, $self->my_mac_s);
}

###############################################################################
# start_daemon($sponge, $Pid_File);
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
        say STDERR LOG_IDENT.": [WARNING] removing stale PID file $pid_file";
        log_warning("removing stale PID file %s", $pid_file);
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

        log_info("daemon spawned; pid=$grand_child");
        $self->main_pid($grand_child);
        _exit(0);
    }

    CHILD: {
        $self->main_pid(-1);

        my $session_id = POSIX::setsid();
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
        $self->main_pid($$);

        log_info("now running in daemon mode");

        # Child (daemon) process.
        open my $pid_fh, '>', $pid_file
            or log_fatal("cannot write PID to '%s': %s", $pid_file, $!);

        say $pid_fh $$;
        $self->_set_wrote_pid(1);
        close $pid_fh;
        log_info("wrote PID %d to '%s'", $$, $pid_file);

        # Make sure we go dark.
        log_is_verbose(0);
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

    log_info("created control socket '%s': uid=%d, gid=%d, mode=%04o",
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

1;
