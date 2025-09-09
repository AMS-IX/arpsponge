#===============================================================================
#
#       Module:  M6::ArpSponge::App::Settings
#         File:  Settings.pm
#
#  Description:  check command line for arpsponge(1)
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#      Created:  2025-09-09
#
#   Copyright (c) 2025 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6::ArpSponge::App::Settings;

use 5.014;
use warnings;

use Moo;
use Carp                        qw( confess );
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
#   (But note that 'some_mixed-mode' would fail!)
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
    # uncoverable statement
    confess "INTERNAL ERROR: _fetch_opt(): cannot match '$key'",
            "; tried: ", join(', ', map { "'$_'" } @tries);
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
        'sweep'               => '',
        'sweep-at-start'      => 0,
        'sweep-skip-alive'    => 0,
        'verbose'             => 0,
    );
}

sub parse_command_line {
    my ($self, %arg) = @_;

    $self->_set_error('');

    my $args = $arg{args} // [];

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
            'sweep-skip-alive!',
            'verbose|v+',

            'version|V' => sub {
                say $self->prog_name, ' ', $self->version;
                exit 0;
            },
            'help|h|?' => sub { pod2usage(
                -exitstatus => 0,
                -verbose => 0,
                -input => pod_where({-inc => 1}, 'M6::ArpSponge::App::Manual'),
            ) },
            'manual' => sub { pod2usage(
                -exitstatus => 0,
                -verbose => 2,
                -input => pod_where({-inc => 1}, 'M6::ArpSponge::App::Manual'),
            ) },
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
        $network = NetAddr::IP->new($opt_network);

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
        my $val = parse_event_mask($opt_val, -err => \(my $err));
        if (!defined $val) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        $param{$key} = $val;
    }

    PERMISSIONS: {
        my ($key, $opt_name, $opt_val)
            = _fetch_opt(\%opt, 'socket_permissions');

        my @perms = split(':', $opt_val);
        if (@perms != 3) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }
        my ($sock_owner, $sock_group, $sock_mode) = @perms;

        $param{socket_uid} = getpwnam($sock_owner)
            // return $self->_set_error(
                    "--socket-permissions: unknown user name '$sock_owner'.");

        $param{socket_gid} = getgrnam($sock_group)
            // return $self->_set_error(
                    "--socket-permissions: unknown group name '$sock_group'.");

        $sock_mode =~ /^0*\d{3,4}$/
            or return $self->_set_error(
                    "--socket-permissions: bad mode '$sock_mode'.");
        $param{socket_mode} = oct($sock_mode);
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
        return if !$self->_check_num_opt($opt_name, $opt_val, '>=', 0);
        $param{$key} = $opt_val;
    }

    SWEEP: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'sweep');
        if (!length($opt_val)) {
            last SWEEP;
        }

        if ($opt_val !~ m|^(\d+)/(\d+)$|) {
            return $self->_set_error(
                "invalid --$opt_name argument '$opt_val'");
        }

        $param{sweep_sec} = $1;
        $param{sweep_threshold} = $2;
    }

    RUNDIR_CONTROL_PIDFILE_STATUSFILE: {
        my ($key, $opt_name, $opt_val) = _fetch_opt(\%opt, 'run_dir');
        my $run_dir = $opt_val // "$RUN_DIR/$device";
        $param{run_dir}         = $run_dir;
        $param{control_socket}  = $opt{'control-socket'} // "$run_dir/control";
        $param{pid_file}        = $opt{'pid-file'}       // "$run_dir/pid";
        $param{status_file}     = $opt{'status-file'}    // "$run_dir/status";
    }

    $self->_set_hash(\%param);
    return 1;
}

sub BUILD {
    my ($self, $args) = @_;
    if ($args->{args}) {
        $self->parse_command_line(
            args => $args->{args},
        );
    }
}

1;

__END__

=encoding utf8

=head1 NAME

M6::ArpSponge::App::Settings - check command line for arpsponge(1)

=head1 SYNOPSIS

 use M6::ArpSponge::App::Settings;

 $settings = M6::ArpSponge::App::Settings->new( args => \@ARGV );

 $settings = M6::ArpSponge::App::Settings->new();

 $settings->parse_command_line( args => \@ARGV )
    or die $settings->error;

 say "program: ", $settings->prog_name;
 say "version: ", $settings->version;
 say "usage:   ", $settings->usage_msg;

 my $hash = $settings->hash;
 for my $k (sort keys %{$hash}) {
    say "$k = $hash->{$k}";
 }

=head1 DESCRIPTION

B<M6::ArpSponge::App::Settings>
provides an interface to parse command line arguments for
L<B<arpsponge>(1)|arpsponge.1>.

It checks for the presence of required parameters and the
validity of all supplied options and arguments.

This class is used by
L<B<M6::ArpSponge::App>(3)|M6::ArpSponge::App>'s
B<new_from_cli>
and is of little use outside of that context.

=head1 CONSTRUCTORS

=head2 new

  $OBJ = M6::ArpSponge::App::Settings->new();
  $OBJ = M6::ArpSponge::App::Settings->new(args => \@argv);

Creates a new object instance.

If the C<args> parameter is provided, the
L<B<parse_command_line>|/parse_command_line>
method is called on the newly created instance.

Returns a reference to the newly created instance.

=head1 METHODS

=head2 default_options

  %HASH = M6::ArpSponge::App::Settings->default_options;
  %HASH = $OBJ->default_options;

Return the default values for all valid command line options.
Options are named without the leading hyphen(s).

=head2 error

Returns the latest error from
L<B<parse_command_line>|/parse_command_line>.

=head2 hash

  $HASH = $OBJ->hash;

Returns a HASHREF that holds all the program options.
The hash contains an entry for every valid command line option.
Command line options are translated to keys as follows:

=over

=item 1.

The name is translated to lowercase.

=item 2.

Any leading hyphens (C<->) are stripped.

=item 3.

Any remaining hyphens (C<->) are translated to underscore (C<_>).

=back

This means that the value for C<--max-arp-age> can be retrieved
under the key C<max_arp_age>.

The key names correspond to accessor names in
L<B<M6::ArpSponge::App>(3)|M6::ArpSponge::App>.

=head2 parse_command_line

  $BOOL = $OBJ->parse_command_line(args => \@ARGS);

Parses the command line arguments contained in I<@ARGS>.
The elements of I<@ARGS> are consumed as they are parsed,
so if it is important to keep the original argument list,
make sure to copy it first, for example:

  $settings->parse_command_line(args => [@ARGV]);

Upon success, the values are stored in 
I<$OBJ>'s L<B<hash>|/hash> attribute,
the object's L<B<error>|/error> attribute is cleared,
and the function returns true.

Upon failure, 
the object's L<B<error>|/error> attribute is set
and the function returns false.

=head2 prog_name

    $STR = M6::ArpSponge::App::Settings->prog_name;
    $STR = $OBJ->prog_name;

Returns the program name.

=head2 usage_msg

    $STR = M6::ArpSponge::App::Settings->usage_msg;
    $STR = $OBJ->usage_msg;

Returns a wummary usage hint to be printed in diagnostics,
along the lines of
"Try '<PROG_NAME> --help' for more information".

=head2 version

    $STR = M6::ArpSponge::App::Settings->version;
    $STR = $OBJ->version;

Returns the program version string
(see L<B<$M6::ArpSponge::VERSION>|M6::ArpSponge>).

=begin MOO-INTERNALS

=head2 Moo Internals
X<BUILD>

Moo internal.

=end MOO-INTERNALS

=head1 EXAMPLES

Use of L<B<default_options>|/default_options>:

  use M6::ArpSponge::App::Settings;

  my $settings = M6::ArpSponge::App::Settings->new();

  $settings->parse_command_line(args => \@ARGV)
    or die $settings->error."\n";

  my %defaults = $settings->default_options;
  for my $k (sort keys %defaults) {
    my $val  = $defaults{$k};
    printf("%-20s : %s\n", $k, $defaults{$k} // '(undef)');
  }


=head1 SEE ALSO

L<B<M6::ArpSponge>(3)|M6::ArpSponge>,
L<B<M6::ArpSponge::App>(3)|M6::ArpSponge::App>,
L<B<arpsponge>(1)|arpsponge>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2025.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 AMS-IX B.V.; All rights reserved.

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. See "perldoc perlartistic."

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
