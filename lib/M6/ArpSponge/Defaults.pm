#===============================================================================
#
#       Module:  M6::ArpSponge::Defaults
#         File:  Defaults.pm
#
#  Description:  Define default parameters for arpsponge.
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#      Created:  2024-02-20
#
#   Copyright (c) 2024 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6::ArpSponge::Defaults;

use 5.014;
use warnings;

use version;
use FindBin;
use List::Util qw( first );
use Carp qw( croak );

use M6::ArpSponge;

my $NAME     = 'arpsponge';
our $VERSION = version->parse($M6::ArpSponge::VERSION);

# Directories to search for "ifconfig".
my @SYS_DIRS = qw(
    /sbin /usr/sbin /bin /usr/bin /usr/ucb
    /usr/local/sbin /usr/local/bin /etc
);

### Function interface:
use parent qw( Exporter );

my %Defaults = (
    MAX_ARP_AGE      => 600,
    FLOOD_PROTECTION => 3,
    INIT_STATE       => 'ALIVE',
    LEARN_TIME       => 5,
    LOG_LEVEL        => 'info',
    LOG_EVENT_MASK   => 'all',
    MAX_PENDING      => 5,
    PROBE_RATE       => 100,
    QUEUE_DEPTH      => 1000,
    MAX_ARP_RATE     => 50,
    NAME             => $NAME,
    VERSION          => $VERSION->normal =~ s/^v//r,
    IFCONFIG         => _get_ifconfig(),
    IP_CMD           => _get_ip_cmd(),
    SOCK_PERMS       => _get_sock_perms(),
    RUN_DIR          => _get_run_dir(),
    BIN_DIR          => _get_bin_dir(),
);

sub all { return %Defaults }

sub get {
    my $key = pop @_;
    $key =~ s{\s+}{_}gx;
    $key =~ s{ ([a-z])([A-Z]) }{$1_$2}gx;

    return $Defaults{uc $key};
}

sub _get_ifconfig {
    my $ifconfig =
        first { -f $_ && -x $_ }
            map { "$_/ifconfig" } @SYS_DIRS;

    return $ifconfig;
}


sub _get_ip_cmd {
    my $ip_cmd =
        first { -f $_ && -x $_ }
            map { "$_/ip" } @SYS_DIRS;

    return $ip_cmd;
}


sub _get_bin_dir {
    my $bin_dir =
        first { -f $_ && -x $_ }
            map { "$_/$NAME" } ($FindBin::Bin, @SYS_DIRS);

    $bin_dir //= $FindBin::Bin;

    return $bin_dir;
}


sub _get_sock_perms {
    my $user = my $group = 'root';

    if ($^O eq 'linux') {
        $group = 'adm';
    }
    elsif ($^O =~ /bsd$/) {
        $group = 'wheel';
    }

    return "$user:$group:0660";
}


sub _get_run_dir {
    my $base = first { -d $_ } qw( /run /var/run /tmp );
    return "$base/$NAME";
}

sub AUTOLOAD {
    our $AUTOLOAD;              # keep 'use strict' happy
    my $func_name = $AUTOLOAD;
    $func_name =~ s/^.*:://;
    return $Defaults{$func_name} if exists $Defaults{$func_name};
    croak "Undefined subroutine &$AUTOLOAD";
}

1;

__END__

=encoding utf8

=head1 NAME

M6::ArpSponge::Defaults - default parameters for the arpsponge

=head1 SYNOPSIS

 use M6::ArpSponge::Defaults;

 # All defaults at once.
 %hash = M6::ArpSponge::Defaults->all();

 # Fetch by name.
 $rate = M6::ArpSponge::Defaults->get('RATE');

 # Fetch by symbolic constant name.
 $perms = M6::ArpSponge::Defaults->SOCK_PERMS;

=head1 DESCRIPTION

This class defines default parameters for the L<B<arpsponge>(8)|arpsponge>
and related programs.

Some parameters are OS dependent and will be determined at run-time.

=head1 CLASS METHODS

=head2 all

    %DEFAULTS = M6::ArpSponge::Defaults->all();

Return all defaults as a list (hash), where keys (e.g. C<MAX_ARP_AGE>)
maps to a value.

=head2 get

    $VAL = M6::ArpSponge::Defaults->get( $KEY );

Return the default value for parameter I<$KEY>; lookup is case-insensitive,
although camel case and spaces are replaced with underscores
(so C<maxArpAge> and C<max ARP age> become C<MAX_ARP_AGE>).

=head2 Per-parameters methods

    $VAL = M6::ArpSponge::Defaults->MAX_ARP_AGE;
    $VAL = M6::ArpSponge::Defaults->FLOOD_PROTECTION;
    ...

Instead of using L</get> to get a specific parameter, you can also call
a class method with the parameter name.

Valid method names correspond to the keys in the hash returned by L</all>:

=over

=item B<BIN_DIR>

System-dependent, determined at run-time.
Directory where the C<arpsponge> executable is installed.

=item B<FLOOD_PROTECTION>

Default flood protection parameter.

=item B<IFCONFIG>

System-dependent, determined at run-time.
Path to the L<ifconfig>(8) executable.

=item B<INIT_STATE>

Initialisation state for IP addresses at startup.

=item B<IP_CMD>

System-dependent, determined at run-time.
Path to the L<ip>(8) executable (typically only on Linux systems).

=item B<LEARN_TIME>

How many seconds to spend in "learning mode" upon startup.

=item B<LOG_EVENT_MASK>

Which even types to log.

=item B<LOG_LEVEL>

At which level log events are sent to L<syslog>(2).

=item B<MAX_ARP_AGE>

Default maximum age for ARP entries.

=item B<MAX_ARP_RATE>

Threshold of ARP queries/sec above which we will consider sponging an IP
address.

=item B<MAX_PENDING>

How many unanswered ARP requests we can have for a particular IP before
sponging.

=item B<NAME>

Package name.

=item B<PROBE_RATE>

Rate of pkts/sec (decimal number) that determines the rate at which we
send probe packets (ARP requests) during sweeps.

=item B<QUEUE_DEPTH>

Size of "ARP queue" for each IP address.

=item B<RUN_DIR>

System-dependent, determined at run-time.
Volatile "run" directory for the arpsponge, typically 
F</run/arpsponge> or F</var/run/arpsponge>.

=item B<SOCK_PERMS>

System-dependent, determined at run-time.
Control socket permissions (I<user>B<:>I<group>B<:>I<mode>).

=item B<VERSION>

Package version.

=back

=head1 EXAMPLES

=head2 Access all parameters

  my %h = M6::ArpSponge::Defaults->all();
  say join(" ", sort keys %h);

Will print (output broken to multiple lines for readability):

  BIN_DIR FLOOD_PROTECTION IFCONFIG INIT_STATE IP_CMD LEARN_TIME
  LOG_EVENT_MASK LOG_LEVEL MAX_ARP_AGE MAX_ARP_RATE MAX_PENDING NAME
  PROBE_RATE QUEUE_DEPTH RUN_DIR SOCK_PERMS VERSION

=head2 Access parameter by name

  chomp(my $key = <>);

  say "$key = ", M6::ArpSponge::Defaults->get( $key );

=head2 Access parameter as method

  say "MAX_ARP_AGE = ", M6::ArpSponge::Defaults->MAX_ARP_AGE;

=head1 SEE ALSO

L<perl>(1).

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2024.

=head1 COPYRIGHT AND LICENSE

Copyright E<copy> 2025 AMS-IX B.V.; All rights reserved.

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. See "perldoc perlartistic."

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
