package M6::ArpSponge::App::Settings;

use 5.014;
use warnings;

use Moo;
use Types::Standard             qw( Str HashRef );
use Data::Dump                  qw( dump );
use FindBin;
use Getopt::Long                qw( GetOptionsFromArray :config bundling );
use NetAddr::IP                 qw( :lower );
use Pod::Usage;
use Pod::Find                   qw( pod_where );

use M6::ArpSponge::Defaults;
use M6::ArpSponge::Event        qw( :const :func );
use M6::ArpSponge::UpdateFlags  qw( parse_update_flags );
use M6::ArpSponge::Log          qw( is_valid_log_level );
use M6::ArpSponge::State        qw( is_valid_state );
use M6::ArpSponge::Util         qw( :all );

use namespace::clean;

###############################################################################
my $PROG      = $FindBin::Script;
my $VERSION   = M6::ArpSponge::Defaults->VERSION;
my $RUN_DIR   = M6::ArpSponge::Defaults->RUN_DIR;
my $USAGE_MSG = "Try '$PROG --help' for more information.\n";

sub version   { return $VERSION   }
sub usage_msg { return $USAGE_MSG }
sub prog_name { return $PROG      }

has hash => (
    is      => 'rwp',
    isa     => HashRef,
    default => sub { {} },
);

has _error => (
    is => 'rw',
    isa => Str,
    default => sub { '' },
);
sub error { $_[0]->_error() }
sub _set_error {
    my ($self, @msg) = @_;
    $self->_error(join('', @msg));
    return;
}

###############################################################################

# $val = _check_num_opt($name, $value, $cmp_op, $cmp_arg);
#
#   Check option ("--$name") value ($value) against a boundary
#   ($cmp_arg) using $cmp_op as the comparison. Set error if
#   the comparison fails and return undef.
#
#   Example:
#
#       $opt_pending = _check_num_opt('max-pending', $opt_pending, '>', 0);
#
#   Returns 1 if $opt_pending is 1, but returns an error
#   if it is 0 or lower: "invalid --max-pending argument '0': must be > 0."
#
sub _check_num_opt {
    my ($self, $name, $val, $cmp_op, $cmp_arg) = @_;
    if (eval "\$val $cmp_op \$cmp_arg") {
        return $val;
    }
    return $self->_set_error(sprintf(
        "invalid --%s argument '%s': must be %s %s",
            $name, $val, $cmp_op, $cmp_arg
    ));
}

# ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, $key);
#
#   Lookup "$key" in %opt. Lookup is tried with the original
#   $key, $key with '_' replaced with '-', and vice versa.
#
#   The returned "$key" is always lowercase, with any '-' replaced by a '_'.
#   The returned "$opt_name" is the key that matched in %opt.
#
#   So if:
#
#       %opt = (
#           'dash-mode'       => 'DASH',
#           'underscore_mode' => 'UNDERSCORE',
#           'some-mixed_mode' => 'MIXED',
#       );
#
#   Then:
#       _fetch_opt(\%opt, 'dash-mode');
#       _fetch_opt(\%opt, 'dash_mode');
#       Returns:
#           ('dash_mode', 'dash-mode', 'DASH');
#
#       _fetch_opt(\%opt, 'underscore-mode');
#       _fetch_opt(\%opt, 'underscore_mode');
#       Returns:
#           ('underscore_mode', 'underscore_mode', 'UNDERSCORE');
#
#       _fetch_opt(\%opt, 'SOME-mixed_mode');
#       Returns:
#           ('some_mixed_mode', 'some-mixed_mode', 'MIXED');
#
#   (But note that 'some_mixed-mode' would not return anything!)
#
sub _fetch_opt {
    my ($opt, $key) = @_;

    my $opt_name = $key;
    my $key_name = lc $key =~ tr'-'_'r;

    my @tries = (
        $key,               lc($key),
        ($key =~ tr'_'-'r), lc($key =~ tr'_'-'r),
        ($key =~ tr'-'_'r), lc($key =~ tr'-'_'r),
    );

    for my $opt_name (@tries) {
        return ($key_name, $opt_name, $opt->{$opt_name})
            if exists $opt->{$opt_name};
    }
    return;
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
    my ($self, %arg) = @_;

    my $args = $arg{args} // \@ARGV;

    my $debug = $arg{debug};

    my %opt = $self->default_options;

    my @getopt_errors;
    my $getopt_ok = eval {
        local $SIG{__WARN__} = sub {
            push @getopt_errors, @_;
        };
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
            'log-level|loglevel=s',
            'log-mask|logmask=s',
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
                -input => pod_where({-inc => 1}, 'M6::ArpSponge::App::Manual'),
                );
            },
            'manual' => sub {
                pod2usage(
                -exitstatus => 0,
                -verbose => 2,
                -input => pod_where({-inc => 1}, 'M6::ArpSponge::App::Manual'),
                );
            },
        );
    };

    if (!$getopt_ok) {
        my $error;
        if (@getopt_errors) {
            chomp($error = lcfirst join('', @getopt_errors));
        }
        else {
            $error = "UNKNOWN GetOptionsFromArray() error";
        }
        return $self->_set_error($error);
    }

    if ($debug) {
        say "Opt:\n", dump(\%opt), "\n";
    }

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
            return $self->_set_error("not enough parameters") if @${args} < 1;
            $opt_network = shift @{$args};
            $argname = $opt_name;
        }
        if (!is_valid_ip($opt_network)) {
            return $self->_set_error(
                "invalid $argname argument '$opt_network'");
        }
        $network = NetAddr::IP->new($opt_network)
            or return $self->_set_error(
                "invalid $argname argument '$opt_network'");

        $param{network}   = ip2hex($network->addr);
        $param{prefixlen} = $network->masklen;

        if (defined $opt{device}) {
            $device = $opt{device};
        }
        else {
            return $self->_set_error("not enough parameters") if @${args} < 2;

            my $arg = lc shift @{$args};
            if ($arg ne 'dev') {
                return $self->_set_error(
                    "invalid parameter: expected 'dev' instead of '$arg'.");
            }
            $device = shift @{$args};
        }
        $param{device} = $device;
        return $self->_set_error("too many parameters")  if @${args} > 0;
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
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val' ($err)");
        }
        $param{$key} = $val;
    }

    INIT_STATE: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'init_state');
        my $val = is_valid_state($opt_val);
        if (!defined $val) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        $param{$key} = $val;
    }

    LOG_LEVEL: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'log_level');
        my $val = is_valid_log_level($opt_val);
        if (!defined $val) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        $param{$key} = $val;
    }

    EVENT_MASK: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'log_mask');
        my $val = parse_event_mask($opt{log_mask}, -err => \(my $err));
        if (!defined $val) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        $param{$key} = $val;
    }

    PERMISSIONS: {
        my ($key, $opt_name, $opt_val)
            = _fetch_opt(\%opt, 'socket_permissions');

        my @dfl_perms  = split(':', M6::ArpSponge::Defaults->SOCK_PERMS);
        my @perms      = split(':', $opt_val);
        if (@perms > 3) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        my $sock_owner = $perms[0] // $dfl_perms[0];
        my $sock_group = $perms[1] // $dfl_perms[1];
        my $sock_mode  = oct($perms[2] // $dfl_perms[2]);

        $param{socket_uid} = getpwnam($sock_owner)
            // return $self->_set_error(
                    "--socket-permissions: unknown user name '$sock_owner'.");

        $param{socket_gid} = getgrnam($sock_group)
            // return $self->_set_error(
                    "--socket-permissions: unknown group name '$sock_group'.");

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
        return if !$self->_check_num_opt($opt_name, $opt_val, '>', 0);
        $param{$key} = $opt_val;
    }

    # Numerical, must be >= 0.
    for my $var (qw(
        learn_time
        max_arp_age
        max_arp_rate
    )) {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, $var);
        return if !$self->_check_num_opt($opt_name, $opt_val, '>', 0);
        $param{$key} = $opt_val;
    }

    SWEEP: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'sweep');
        if (!defined $opt_val || !length($opt_val)) {
            last SWEEP;
        }

        if ($opt_val !~ m|^(\d+)/(\d+)$|) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        my ($sweep_sec, $sweep_threshold) = ($1, $2);

        if (!$self->_check_num_opt(
                "$opt_name (seconds)", $sweep_sec, '>=', 0)) {
            return;
        }
        if (!$self->_check_num_opt(
                "$opt_name (threshold)", $sweep_threshold, '>=', 0)) {
            return;
        }

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

    if ($debug) {
        say "Program parameters:\n", dump(\%param);
    }

    $self->_set_hash(\%param);
    return 1;
}

sub BUILD {
    my ($self, $args) = @_;
    if ($args->{args}) {
        $self->parse_command_line(
            args => $args->{args},
            debug => $args->{debug}
        );
    }
}

1;
