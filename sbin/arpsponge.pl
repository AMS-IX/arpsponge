#!@PERL@ -I../lib
# [Net::ARP is not clean, so "-w" flag to perl produces spurious warnings]
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
use feature ':5.10';
use strict;
use Getopt::Long;
use Pod::Usage;
use FindBin;
use Config;

use Net::Pcap qw( pcap_open_live pcap_dispatch pcap_fileno
                  pcap_get_selectable_fd pcap_setnonblock );

use M6::ARP::NetPacket  qw( :all );
use NetAddr::IP         qw( :lower );

use Time::HiRes         qw( time sleep );
use POSIX               qw( strftime :signal_h :errno_h );

use File::Path          qw( mkpath );

use IO::File;
use IO::String;
use IO::Select;
use IO::Socket;

use M6::ARP::Sponge;
use M6::ARP::Log        qw( :standard );
use M6::ARP::Event      qw( :standard );
use M6::ARP::Const      qw( :all );
use M6::ARP::Util       qw( :all );
use M6::ARP::Control::Server;

###############################################################################

use constant SYSLOG_IDENT => '@NAME@';

my $PROG                 = $FindBin::Script;
my $VERSION              = '@RELEASE@';

my $SPONGE_VAR           = '@SPONGE_VAR@';
my $DFL_LOGMASK          = 'all';
my $DFL_LOGLEVEL         = '@DFL_LOGLEVEL@';
my $DFL_RATE             = '@DFL_RATE@';
my $DFL_ARP_AGE          = '@DFL_ARP_AGE@';
my $DFL_PENDING          = '@DFL_PENDING@';
my $DFL_LEARN            = '@DFL_LEARN@';
my $DFL_QUEUEDEPTH       = '@DFL_QUEUEDEPTH@';
my $DFL_PROBERATE        = '@DFL_PROBERATE@';
my $DFL_FLOOD_PROTECTION = '@DFL_FLOOD_PROTECTION@';
my $DFL_INIT             = '@DFL_INIT@';
my $DFL_SOCK_PERMS       = '@DFL_SOCK_PERMS@';

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

$::USAGE=<<EOF;
Usage: $PROG [options] IPADDR/PREFIXLEN dev IFNAME

Options:
  --age=secs              - time in seconds until we consider an ARP entry
                            "stale" ($DFL_ARP_AGE)
  --arp-update-methods=.. - how to update neighbor ARP caches
  --control=socket        - location of the control socket (<rundir>/control)
  --[no]daemon            - put process in background
  --dummy                 - simulate sponging; turns off syslog
  --passive               - do NOT source any ARP queries
  --flood-protection=n    - protect against floods from single sources;
                            queries from a source coming in faster than
                            "n" (q/sec) are ignored
  --[no]gratuitous        - send gratuitous ARP when sponging
  --init=state            - how to initialize (default: $DFL_INIT)
  --learning=secs         - number of seconds to spend in LEARN state
  --loglevel=level        - syslog logging level ("$DFL_LOGLEVEL")
  --logmask=mask          - syslog event filter ("$DFL_LOGMASK")
  --pending=n             - number of seconds we send ARP queries before
                            sponging ($DFL_PENDING)
  --permissions=u:g:m     - permissions for the control socket
  --pidfile=pidfile       - override default pidfile (<rundir>/pid)
  --proberate=n           - number queries/sec we send when learning or
                            sweeping ($DFL_PROBERATE)
  --queuedepth=n          - number of ARP queries before we take notice
                            ($DFL_QUEUEDEPTH)
  --rate=n                - ARP threshold rate in queries/min ($DFL_RATE)
  --rundir=path           - override base directory for run-time files
                            ($SPONGE_VAR/<IFNAME>)
  --sponge-network        - sponge the network and broadcast addresses as well
  --statusfile=file       - where to write status information when receiving
                            HUP or USR1 signal (<rundir>/status)
  --sweep=sec/thr         - periodically sweep for "quiet" IP addresses
  --sweep-at-start        - perform sweep for all addresses at startup
  --sweep-skip-alive      - sweep avoids IP addresses in state ALIVE
  --verbose[=n]           - be verbose; print information on STDOUT;
                            turns off syslog

See also "perldoc $PROG".
EOF

###############################################################################

my $Wrote_Pid      = 0;
my $Pid_File        = undef;
my $Control_Socket = undef;
my $Block_Sigset   = POSIX::SigSet->new(SIGUSR1, SIGHUP, SIGALRM);
my $Timer_Cycle    = 1.0;

# Keep track of how many errors we've seen and when we logged the
# last error. This is used to suppress too much logging.
my $Last_Error       = 0;
my $Error_Count      = 0;

# ============================================================================
END {
    if (defined $Wrote_Pid && $$ == $Wrote_Pid) {
        print STDERR "$$ unlinking $Pid_File\n";
        unlink($Pid_File);
        if (defined $Control_Socket && -e $Control_Socket) {
            print STDERR "$$ unlinking $Control_Socket\n";
            unlink($Control_Socket);
        }
    }
}
# ============================================================================

# Some forward declarations.
sub start_daemon($$);

###############################################################################
# Main program code :-)
###############################################################################
sub Main {
    init_log(SYSLOG_IDENT);

    Getopt::Long::Configure('no_ignore_case');

    GetOptions(
        'age=i'               => \(my $age              = $DFL_ARP_AGE),
        'arp-update-method=s' => \(my $arp_update_methods),
        'control=s'           => \$Control_Socket,
        'daemon!'             => \(my $daemon),
        'dummy!'              => \(my $dummy),
        'passive!'            => \(my $passive),
        'flood-protection=f'  => \(my $flood_protection = $DFL_FLOOD_PROTECTION),
        'gratuitous!'         => \(my $gratuitous),
        'help|?'              => sub { print $::USAGE; exit 0 },
        'init=s'              => \(my $init_arg         = $DFL_INIT),
        'learning=i'          => \(my $learning         = $DFL_LEARN),
        'loglevel=s'          => \(my $loglevel         = $DFL_LOGLEVEL),
        'logmask=s'           => \(my $logmask          = $DFL_LOGMASK),
        'man'                 => \(my $man),
        'pending=i'           => \(my $pending          = $DFL_PENDING),
        'permissions=s'       => \(my $permissions      = $DFL_SOCK_PERMS),
        'pidfile=s'           => \$Pid_File,
        'proberate=i'         => \(my $proberate        = $DFL_PROBERATE),
        'queuedepth=i'        => \(my $queuedepth       = $DFL_QUEUEDEPTH),
        'rate=f'              => \(my $rate             = $DFL_RATE),
        'rundir=s'            => \(my $rundir),
        'sponge-network'      => \(my $sponge_net),
        'statusfile=s'        => \(my $statusfile),
        'sweep=s'             => \(my $sweep_sec),
        'sweep-at-start!'     => \(my $sweep_at_start),
        'sweep-skip-alive'    => \(my $sweep_skip_alive),
        'verbose|v+'          => \(my $verbose),
        'version|V'           => sub { print "$PROG $VERSION\n"; exit 0 },
    ) or pod2usage(2);

    pod2usage(-exitstatus => 0, -verbose => 2) if $man;

    log_is_verbose($verbose);

    if (defined(my $level = is_valid_log_level($loglevel))) {
        log_level($level);
    }
    else {
        log_fatal("Bad value '%s' for --loglevel", $loglevel);
    }
    if (defined(my $mask = parse_event_mask($logmask, -err => \(my $err)))) {
        event_mask($mask);
    }
    else {
        log_fatal("Bad value '%s' for --logmask: %s", $logmask, $err);
    }


    my $sweep_threshold  = undef;
    if (length($sweep_sec)) {
        ($sweep_sec, $sweep_threshold) = $sweep_sec =~ m|^(\d+)/(\d+)$|
            or log_fatal("Bad value for --sweep");
    }

    ####################################################################

    log_fatal("Not enough parameters\n$::USAGE") if @ARGV < 3;
    log_fatal("Too many parameters\n$::USAGE")   if @ARGV > 3;

    my $network = NetAddr::IP->new($ARGV[0])
        or log_fatal qq{Bad network address or prefix length in "$ARGV[0]"\n};

    ####################################################################

    my ($device);

    log_fatal("Invalid parameter syntax: expected \"dev\" instead of \"$ARGV[1]\"\n")
        unless lc $ARGV[1] eq 'dev';

    $device = $ARGV[2];

    $rundir         //= "$SPONGE_VAR/$device";
    $statusfile     //= "$rundir/status";

    ####################################################################

    # Create the "var" directory for the sponge.
    mkpath($rundir, { mode => 0775, error => \my $err });
    if (@$err) {
        my $msg = "$PROG: errors creating $rundir\n";
        for my $diag (@$err) {
            my ($file, $str) = %$diag;
            $msg .= "$file: " if length $file;
            $msg .= "$str\n";
        }
        log_fatal($msg);
    }

    if ($daemon) {
        $Pid_File //= "$rundir/pid";
    }

    ####################################################################
    $| = ($verbose > 0 ? 1 : 0);

    my $sponge = new M6::ARP::Sponge(
            verbose          => $verbose,
            is_dummy         => $dummy,
            queuedepth       => $queuedepth,
            device           => $device,
            network          => ip2hex($network->addr),
            prefixlen        => $network->masklen,
            max_pending      => $pending,
            max_rate         => $rate,
            arp_age          => $age,
            sponge_net       => $sponge_net,
            gratuitous       => $gratuitous,
            flood_protection => $flood_protection,
        );

    $sponge->is_dummy($dummy);

    # Sanitise proberate
    $proberate = $DFL_PROBERATE if $proberate < 0 || $proberate > 1e6;

    $sponge->user(
        version          => $VERSION,
        net_lo           => scalar $network->first->numeric,
        net_hi           => scalar $network->last->numeric,
        hex_network      => ip2hex($network->network),
        hex_broadcast    => ip2hex($network->broadcast),
        start_time       => time,
        statusfile       => $statusfile,
        learning         => $learning,
        probesleep       => 1.0/$proberate,
        sweep_skip_alive => $sweep_skip_alive,
        passive          => $passive,
    );

    if ($sponge->my_ip eq $IPv4_ADDR_NONE) {
        if (!$passive) {
            event_alert(EVENT_STATE, 
                "%s has no IP address; forcing --passive",
                $sponge->device, $sponge->my_ip_s
            );
            $sponge->user('passive', 1);
            # Signal to other parts of the program that the "passive" mode was
            # forced, so they can issue appropriate warnings.
            $sponge->user('forced_passive', 1);
        }
    }

    if ($sweep_sec) {
        $sponge->user(
            sweep_sec  => $sweep_sec,
            next_sweep => time+$sweep_sec,
            sweep_age  => $sweep_threshold,
        );
    }

    if (defined $init_arg && $init_arg !~ /^\s*none\s*/i) {
        my $init = is_valid_state($init_arg, -err => \(my $err));
        if (defined $err) {
            log_fatal(qq{bad --init argument "$init": $err\n});
        }
        init_state($sponge, $init);
    }

    if ($arp_update_methods) {
        my $flags = parse_update_flags($arp_update_methods, -err => \(my $err));
        if (defined $err) {
            log_fatal(qq{bad --arp-update-methods argument "%s": %s},
                      $arp_update_methods, $err);
        }
        $sponge->arp_update_flags($flags);
    }

    ####################################################################

    # Create the control socket.
    $Control_Socket //= "$rundir/control";
    my $control_fh = create_control_socket($sponge, $Control_Socket, $permissions);

    ####################################################################

    my $pcap_h
        = pcap_open_live(
                $sponge->device, # capture device
                512,             # snaplen
                1,               # promiscuous
                $PCAP_TIMEOUT,   # timeout in ms for a pcap_dispatch
                \$err,           # error diagnostic
        );

    if (!$pcap_h) {
        log_fatal("cannot capture on %s: %s", $sponge->device, $err);
    }

    if (pcap_setnonblock($pcap_h, 1, \$err) < 0) {
        log_fatal("cannot capture in non-blocking mode: %s", $err);
    }

    my $pcap_fd = pcap_get_selectable_fd($pcap_h);
    if ($pcap_fd < 0) {
        log_fatal("cannot get selectable fd for %s", $sponge->device);
    }

    my $pcap_fh = IO::Handle->new();
    if (!$pcap_fh->fdopen($pcap_fd, "r")) {
        log_fatal("fdopen(%s,'r') for %s failed: %s",
                           $pcap_fd, $sponge->device, $!);
    }

    $sponge->user(
        pcap_fd => $pcap_fd,
        pcap_fh => $pcap_fh,
    );
    $sponge->pcap_handle($pcap_h);

    ####################################################################

    event_notice(EVENT_STATE, "Initializing $PROG on [%s, %s, %s]",
                    $sponge->device, $sponge->my_ip_s, $sponge->my_mac_s);

    # If we have to run in daemon mode, do so.
    start_daemon($sponge, $Pid_File) if $daemon;

    ####################################################################

    $::SIG{'INT'}  = sub { process_signal($sponge, 'INT')  };
    $::SIG{'QUIT'} = sub { process_signal($sponge, 'QUIT') };
    $::SIG{'TERM'} = sub { process_signal($sponge, 'TERM') };
    $::SIG{'USR1'} = sub { do_status('USR1', $sponge)      };
    $::SIG{'HUP'}  = sub { do_status('HUP',  $sponge)      };
    # $::SIG{'ALRM'} = sub { do_timer($sponge)               };

    if ($sweep_at_start) {
        $sponge->user(next_sweep => time-1);
    }

    packet_capture_loop($sponge);

    exit(0);
}

sub create_control_socket {
    my ($sponge, $ctl_socket, $permissions) = @_;

    if (-e $ctl_socket) {
        if (!unlink $ctl_socket) {
            log_fatal("$PROG cannot delete stale $ctl_socket $!\n");
        }
    }

    my $control_fh = M6::ARP::Control::Server->create_server($Control_Socket)
                        or log_fatal "%s", M6::ARP::Control->error;

    $sponge->user(control => $control_fh);

    my @dfl_perms  = split(':', $DFL_SOCK_PERMS);
    my @perms      = split(':', $permissions);
    my $sock_owner = $perms[0] // $dfl_perms[0];
    my $sock_group = $perms[1] // $dfl_perms[1];
    my $sock_perms = oct($perms[2] // $dfl_perms[2]);

    my $sock_uid = getpwnam($sock_owner)
        // log_fatal qq{$PROG: unknown username "$sock_owner"\n};

    my $sock_gid = getgrnam($sock_group)
        // log_fatal qq{$PROG: unknown group "$sock_group"\n};

    chown($sock_uid, $sock_gid, $Control_Socket)
        or log_err(qq{chown %s:%s %s: %s},
                    $sock_owner, $sock_group, $Control_Socket, $!);

    chmod($sock_perms, $Control_Socket)
        or log_err(qq{chmod %04o %s: %s},
                    $sock_perms, $Control_Socket, $!);

    return $control_fh;
}

###############################################################################
# handle_input
#
#    Handle input (packets, etc.) for a specific amount of time.
#
###############################################################################
sub handle_input {
    my ($sponge, $next_alarm) = @_;

    my $pcap_h     = $sponge->pcap_handle;
    my $pcap_fd    = $sponge->user('pcap_fd');
    my $pcap_fh    = $sponge->user('pcap_fh');
    my $control_fh = $sponge->user('control');
    my $control_fd = $control_fh->fileno;

    # Prepare the bit vector for the select() calls.
    my $select = $sponge->user('select');

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
        my @ready = $select->can_read($next_alarm - $now);

        $now = time; # Update time.

        if ($Error_Count > 1 && $now > $Last_Error + 15) {
            # We've seen multiple select errors in the last 15 seconds.
            # Only the first was logged. Log the number of repetitions.
            event_err(EVENT_IO, "select error repeated %d time(s)", $Error_Count-1);
            $Error_Count = 0;
        }

        if (@ready == 0) {
            # A signal or another error.
            if ($! == EINTR) { # Ignore EINTR errors; they are expected.
                $Error_Count++;
                if ($Error_Count == 1) { # Suppress multiple errors.
                    event_err(EVENT_IO, "error in select(): %s", $!);
                    $Last_Error = $now;
                }
            }
            next;
        }

        for my $ready_fh (@ready) {
            my $ready_fd = $ready_fh->fileno;
            if ($ready_fd == $pcap_fd) { # [4]
                sigprocmask(SIG_BLOCK, $Block_Sigset);
                pcap_dispatch($pcap_h, $MAX_PKT_PER_CYCLE, \&process_pkt, $sponge);
                sigprocmask(SIG_UNBLOCK, $Block_Sigset);
                next;
            }
            if ($ready_fd == $control_fd) {
                if (my $client = $control_fh->accept()) {
                    $select->add($client);
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
            if (!$ready_fh->handle_command($sponge)) {
                $select->remove($ready_fh);
                remove_notify($ready_fh);
                event_info(EVENT_CTL,
                    "[client %d] disconnected", $ready_fh->fileno);
                $ready_fh->close;
                next;
            }
        }
    }
}


###############################################################################
# packet_capture_loop($sponge);
#
#    Loop over incoming traffic for sponge instance $sponge.
#
###############################################################################
sub packet_capture_loop {
    my ($sponge) = @_;

    # Prepare the bit vector for the select() calls.
    $sponge->user(
        select => IO::Select->new(
                    $sponge->user('pcap_fh'),
                    $sponge->user('control'),
        ),
    );

    # [1] Schedule our next periodic task run.
    my ($now, $next_alarm) = reset_timer($sponge, time);

    while (1) {
        handle_input($sponge, $next_alarm);
        do_timer($sponge);
        ($now, $next_alarm) = reset_timer($sponge, $next_alarm);
    }

    # We don't really ever exit this loop...
    log_fatal("unexpected end of loop!\n");
}

###############################################################################
#####   HANDLING CONTROL INPUT   ##############################################

sub get_status_info_s {
    my ($sponge) = @_;

    my $now = time;
    my $start_time = $sponge->user('start_time');

    my $learning = $sponge->user('learning');

    my @response = (
        sprintf("%-17s %s\n", 'id:', SYSLOG_IDENT),
        sprintf("%-17s %d\n", 'pid:', $$),
        sprintf("%-17s %s\n", 'version:', $sponge->user('version')),
        sprintf("%-17s %s [%d]\n", 'date:', format_time($now), $now),
        sprintf("%-17s %s [%d]\n", 'started:',
                format_time($start_time), $start_time),
        sprintf("%-17s %s/%d\n", 'network:',
                $sponge->network_s, $sponge->prefixlen),
        sprintf("%-17s %s\n", 'interface:', $sponge->device),
        sprintf("%-17s %s [%s]\n", 'ip/mac:',
                $sponge->my_ip_s, $sponge->my_mac_s),
        sprintf("%-17s %d\n", 'queue depth:', $sponge->queuedepth),
        sprintf("%-17s %0.2f\n", 'max rate:', $sponge->max_rate),
        sprintf("%-17s %0.2f\n", 'flood protection:',
                $sponge->flood_protection),
        sprintf("%-17s %d\n", 'max pending:', $sponge->max_pending),
        sprintf("%-17s %d sec\n", 'sweep period:', $sponge->user('sweep_sec')),
        sprintf("%-17s %d sec\n", 'sweep age:', $sponge->user('sweep_age')),
        sprintf("%-17s %s\n", 'sweep skip alive:',
                $sponge->user('sweep_skip_alive') ? "yes" : "no"),
        sprintf("%-17s %d sec\n", 'proberate:',
                1/$sponge->user('probesleep')),
        sprintf("%-17s %d sec\n", 'next sweep in:',
                $sponge->user('next_sweep')-$now),
        sprintf("%-17s %s\n", 'learning:',
                $learning ? "yes ($learning sec left)" : "no"),
        sprintf("%-17s %s\n", 'dummy:',
                $sponge->is_dummy ? "yes" : "no", "\n"),
    );
    return join('', @response);
}

sub get_ip_state_table_s {
    my ($sponge) = @_;

    my $fh = IO::String->new;
    $fh->print("<STATE>\n");
    $fh->print(
             sprintf("%-17s %-12s %7s %12s %7s\n",
                     "# IP", "State", "Queue", "Rate (q/min)", "Updated")
         );

    my $states = $sponge->state_table;
    my $queue = $sponge->queue;

    my ($nalive, $ndead, $npending) = (0,0,0);

    my $ip;
    for $ip (sort { $a cmp $b } keys %$states) {
        my $state = $$states{$ip};
        next unless defined $state;

        my $depth = $queue->depth($ip);
        my $rate  = $queue->rate($ip);
        my $stamp = $sponge->state_mtime($ip);

        $fh->print(
            sprintf("%-17s %-12s %7d %8.3f     %s\n", hex2ip($ip),
                    $sponge->state_name($state), $depth, $rate,
                    format_time($stamp)
        ));

        if ($state == DEAD) {
            $ndead++;
            next;
        }
        if ($state == ALIVE) {
            $nalive++;
            next;
        }
        if ($state >= PENDING(0)) {
            $npending++;
            next;
        }
    }
    $fh->print("</STATE>\n");
    return (
        ${$fh->string_ref}, $nalive, $ndead, $npending,
    );
}

sub get_arp_table_s {
    my ($sponge) = @_;

    my $fh = IO::String->new;

    $fh->print(
            "<ARP-TABLE>\n",
            sprintf("%-17s %-17s %-11s %s\n", "# MAC", "IP", "Epoch", "Time")
        );

    my $nmac = 0;
    for my $ip (sort { $a cmp $b } keys %{$sponge->arp_table}) {
        my ($mac, $time) = @{$sponge->arp_table->{$ip}};
        $nmac++;
        $fh->print(sprintf("%-17s %-17s %-11d %s\n",
                        hex2mac($mac), hex2ip($ip), $time, format_time($time)
                ));
    }

    $fh->print("</ARP-TABLE>\n");

    return ($nmac, ${$fh->string_ref});
}

###############################################################################
# ($now, $next_alarm) = reset_timer($sponge, $prev_alarm)
#
#    Calculate when we need to run our timer trigger again.
#    Normally, this is $prev_alarm + $Timer_Cycle, but if that
#    has already passed (which can happen if the timer trigger
#    is slow), we need to adjust our cycle.
#
###############################################################################
sub reset_timer {
    my ($sponge, $next_alarm) = @_;

    my $now = time;

    # Keep the intervals as steady as possible by keying off
    # of the previous alarm time if possible.
    if ($now >= $next_alarm + $Timer_Cycle) {
        # We've been dragging our feet. Rather than setting
        # a new alarm time that's already in the past, adjust
        # to offset from current time. This is not elegant,
        # but it's better than running timer triggers in tight
        # circles.
        my $caller = (caller(1))[3];
        event_warning(EVENT_STATE,
            "$caller - timer event LAG: %s; %s",
            strftime("planned=%H:%M:%S", localtime($next_alarm+$Timer_Cycle)),
            strftime("adjusted=%H:%M:%S", localtime($now+$Timer_Cycle)),
        );
        $next_alarm = $now;
    }
    return ($now, $next_alarm + $Timer_Cycle);
}

###############################################################################
# do_timer($sponge)
#
#    Called periodically (~ 1/sec) by the processing loop.
#
#    Process & probe pending entries, handle LEARN mode, sweep, etc.
#
###############################################################################
sub do_timer($) {
    my ($sponge) = @_;

    my $learning = $sponge->user('learning');
    if ($learning > 0) {
        do_learn($sponge);
        $sponge->user(learning => $learning-1);
        if ($learning-1 == 0) {
            event_notice(EVENT_STATE, "exiting learning state");
        }
        return;
    }

    do_probe_pending($sponge);

    my $next_sweep = $sponge->user('next_sweep');
    if ($next_sweep && time >= int($next_sweep)) {
        do_sweep($sponge);
        $sponge->user(next_sweep => time+$sponge->user('sweep_sec'));
    }
    return;
}


###############################################################################
# do_probe_pending($sponge)
#
#    Called by do_timer() to query pending IP addresses.
#
###############################################################################
sub do_probe_pending($) {
    my ($sponge) = @_;
    my $pending  = $sponge->pending;
    my $sleep    = $sponge->user('probesleep');

    if (keys %$sponge > 0 && $sponge->user('forced_passive')) {
        # Log reminders that the sponge was started without an IP address, and
        # no --passive flag.
        event_warning(EVENT_STATE, 
            "%s has no IP address; forced --passive; not querying pending IPs",
            $sponge->device,
        );
    }

    return if $sponge->user('passive');

    log_verbose(2, "Querying pending addresses...\n");
    my $n = 0;
    for my $ip (sort keys %$pending) {
        $n++;
        if ($$pending{$ip} > PENDING($sponge->max_pending)) {
            $sponge->set_dead($ip);
            next;
        }
        $sponge->send_query($ip);
        $sponge->incr_pending($ip);
        log_verbose(2, "probed $ip, state=",
                                $sponge->get_state($ip), "\n");
        handle_input($sponge, time+$sleep);
    }

    if ($n > 1 || log_is_verbose() > 1) {
        event_notice(EVENT_STATE, "%d pending IPs queried", $n);
    }
}
###############################################################################
# init_state($sponge)
#
#    Initialize the states for all IP addresses.
#
###############################################################################
sub init_state {
    my ($sponge, $state) = @_;

    my $lo = $sponge->user('net_lo');
    my $hi = $sponge->user('net_hi');
    for (my $num = $lo; $num <= $hi; $num++) {
        my $ip = sprintf("%08x", $num);
        $sponge->set_state($ip, $state, 0);
    }
}

###############################################################################
# do_learn($sponge)
#
#    Called by the do_timer() interrupt handler.
#
###############################################################################
sub do_learn($) {
    my ($sponge) = @_;

    log_verbose(1, "LEARN: ",
                int($sponge->user('learning')), " secs left\n");
    return;
}

###############################################################################
# do_sweep($sponge [, OPT => VAL, ...])
#
#    Called by the do_time() interrupt handler.
#
#    Sweep the range of IP addresses and send ARP requests for the ones
#    that have been quiet for at least sweep_age seconds.
#
###############################################################################
sub do_sweep {
    my ($sponge, %opts) = @_;

    my $interval   = $opts{'sweep_sec'}  // $sponge->user('sweep_sec');
    my $threshold  = $opts{'sweep_age'}  // $sponge->user('sweep_age');
    my $sleep      = $opts{'probesleep'} // $sponge->user('probesleep');
    my $skip_alive = $opts{'sweep_skip_alive'}
                      // $sponge->user('sweep_skip_alive');

    event_notice(EVENT_STATE, "sweeping for quiet entries on %s/%d",
                        hex2ip($sponge->network), $sponge->prefixlen);

    my $lo = $sponge->user('net_lo');
    my $hi = $sponge->user('net_hi');

    my $nquery = 0;
    my $verbose = log_is_verbose();
    log_is_verbose($verbose-1) if $verbose>0;
    for (my $num = $lo; $num <= $hi; $num++) {
        my $ip = sprintf("%08x", $num);
        my $age = time - $sponge->state_mtime($ip);

        my $do_query = 0;
        if ($sponge->get_state($ip) == ALIVE) {
            my ($dst_mac, $mtime) = $sponge->arp_table($ip);
            if ($age >= $threshold) {
                if (!$skip_alive || !defined $dst_mac) {
                    $do_query++;
                }
            }
        }
        elsif ($age >= $threshold) {
            $do_query++;
        }

        if ($do_query) {
            if ($verbose>1) {
                log_sverbose(1, "DO PROBE %s (%d >= %d)\n",
                                hex2ip($ip), $age, $threshold);
            }
            $sponge->send_query($ip);
            $sponge->set_state_mtime($ip, time);
            $nquery++;
            handle_input($sponge, time+$sleep);
            next;
        }
        if ($verbose>1) {
            log_sverbose(1, "SKIP PROBE %s (%d < %d)\n",
                            hex2ip($ip), $age, $threshold);
        }
    }
    log_is_verbose($verbose);
    event_notice(EVENT_STATE, "queried $nquery IP address(es)");
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
    my ($sponge, $src_ip, $src_mac) = @_;

    if ($sponge->get_state($src_ip) != STATIC) {
        $sponge->set_alive($src_ip, $src_mac);
        return;
    }
    event_warning(EVENT_STATIC,
        "traffic from STATIC sponged IP: src.mac=%s src.ip=%s",
        hex2mac($src_mac), hex2ip($src_ip),
    );
}

###############################################################################
# process_pkt($sponge, $hdr, $pkt);
#
#    Called by pcap_dispatch() as:
#
#        process_pkt($sponge, $hdr, $pkt);
#
#    Process sniffed packets. The "$sponge" parameter is what was passed
#    as the "user data" parameter to the pcap_dispatch() call. In our
#    case, that is the M6::ARP::Sponge instance, a.k.a. "$sponge".
#
###############################################################################
sub process_pkt {
    my ($sponge, $hdr, $pkt) = @_;
    my $eth_obj = decode_ethernet($pkt);
    my $src_mac = $eth_obj->{src_mac};

    # Self-generated packets are not relevant.
    return if $src_mac eq $sponge->my_mac;

    # Always "unsponge" the source IP address on any IP packet.
    if ($eth_obj->{type} == $ETH_TYPE_IP) {
        my $ip_obj  = decode_ipv4($eth_obj->{data});
        my $src_ip  = $ip_obj->{src_ip};

        # Nothing to do if the source IP is not on our local network.
        return if ! $sponge->is_my_network($src_ip);

        # Update state for the source IP address.
        update_state($sponge, $src_ip, $src_mac);

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
        return if ! $sponge->arp_update_flags();
        return if $eth_obj->{dest_mac} ne $sponge->my_mac;

        my $dst_ip = $ip_obj->{dest_ip};
        return if $sponge->is_my_ip($dst_ip);                   # Not our IP
        return if $sponge->get_state($dst_ip) != ALIVE();       # IP is alive

        my ($dst_mac, $mtime) = $sponge->arp_table($dst_ip);
        return if !$dst_mac or $dst_mac eq $ETH_ADDR_NONE;      # MAC is valid
        $sponge->send_arp_update(
            tha => $src_mac,
            tpa => $src_ip,
            sha => $dst_mac,
            spa => $dst_ip,
            tag => '[auto] ',
        );
        return;
    }

    return if $eth_obj->{type} != $ETH_TYPE_ARP;

    # From this point on, we have an ARP packet.

    my $arp_obj = decode_arp($eth_obj->{data});
    my $dst_ip  = $arp_obj->{tpa};
    my $src_ip  = $arp_obj->{spa};

    # Update state for the source IP address.
    update_state($sponge, $src_ip, $src_mac);

    # Ignore anything that is not an ARP "WHO-HAS" request.
    return if $arp_obj->{opcode} != $ARP_OPCODE_REQUEST;

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

    if ( ! $sponge->is_my_network($dst_ip) ) {
        # We only store/sponge ARPs for our "local" IP addresses.
        event_warning(EVENT_ALIEN,
            "misplaced ARP: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        return;
    }

    if ($sponge->is_my_ip($dst_ip)) {
        # ARPs for our IPs require no action (handled by the kernel),
        # except for maybe updating our internal ARP table.
        if (log_is_verbose()) {
            log_sverbose(1, "ARP WHO HAS %s TELL %s (for our IP)\n",
                                hex2ip($dst_ip), hex2ip($src_ip));
        }
        $sponge->set_alive($dst_ip, $sponge->my_mac);
        return;
    }

    if ($src_ip eq $IPv4_ADDR_NONE) {
        # DHCP duplicate IP detection.
        # See RFC 2131, p38, bottom.
        event_notice(EVENT_SPONGE,
                "DHCP duplicate IP detection: src.mac=%s arp.tpa=%s\n",
                hex2mac($src_mac), hex2ip($dst_ip)
            );

        # Mmmh, don't let go completely yet... If all is well,
        # we'll soon start seeing "real" traffic from this
        # address...
        my $state = $sponge->get_state($dst_ip);
        if (defined $state && $state != ALIVE) {
            $sponge->set_pending($dst_ip, 0);
        }
        return;
    }

    # Devices ARPing for the network or broadcast address indicate
    # possible bad netmasks.
    if ($dst_ip eq $sponge->user('hex_network')) {
        event_warning(EVENT_ALIEN,
            "ARP for network address: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        $sponge->send_reply($dst_ip, $arp_obj) if $sponge->sponge_net;
        return;
    }

    if ($dst_ip eq $sponge->user('hex_broadcast')) {
        event_warning(EVENT_ALIEN,
            "ARP for broadcast address: src.mac=%s arp.spa=%s arp.tpa=%s",
            hex2mac($src_mac),
            hex2ip($src_ip),
            hex2ip($dst_ip),
        );
        $sponge->send_reply($dst_ip, $arp_obj) if $sponge->sponge_net;
        return;
    }

    if (log_is_verbose() >= 2) {
        log_sverbose(2, "ARP WHO HAS %s TELL %s ",
                          hex2ip($dst_ip), hex2ip($src_ip));
        my $state = $sponge->get_state($dst_ip);
        if ($state <= DEAD) {
            my $age = time - $sponge->state_mtime($dst_ip);
            log_sverbose(2, "[sponged=yes; %d secs ago]\n", $age);
        }
        else {
            log_verbose(2, "[sponged=no]\n");
        }
    }

    my $query_time = time;

    # Don't do anything else if we are still learning.
    return if $sponge->user('learning');

    $sponge->queue->add($dst_ip, $src_ip, time);

    my $state = $sponge->get_state($dst_ip);

    if (!defined $state) {
        # State is not defined (yet), so make it pending.
        $state = $sponge->set_pending($dst_ip, 0);
        return;
    }

    # Reply for a dead address.
    if ($state <= DEAD) {
        $sponge->send_reply($dst_ip, $arp_obj);
        return;
    }

    # PENDING states are handled by the do_timer() routine.
    # So from here on out we are only interested in ALIVE
    # addresses with a full queue and a rate greater than
    # the max rate.
    return if $state != ALIVE;
    return if ! $sponge->queue->is_full($dst_ip);
    return if $sponge->queue->rate($dst_ip) <= $sponge->max_rate;

    # Check for flood protection.
    my $fp_rate = $sponge->flood_protection;
    if (!$fp_rate) {
        # No flood protection, so just set address to pending.
        $state = $sponge->set_pending($dst_ip, 0);
    }

    # In case of flood protection, reduce the queue
    # by removing flooding sources, then check again...
    my $d1 = $sponge->queue->depth($dst_ip);
    my $r1 = $sponge->queue->rate($dst_ip);
    my $d2 = $sponge->queue->reduce($dst_ip, $fp_rate);
    my $r2 = $sponge->queue->rate($dst_ip);
    event_notice(EVENT_SPONGE,
            "%s queue reduced: [depth,rate] = "
            ."[%d,%0.1f] -> [%d,%0.1f]",
            hex2ip($dst_ip), $d1, $r1, $d2, $r2
        );
    if ($sponge->queue->is_full($dst_ip) &&
        $r2 > $sponge->max_rate)
    {
        $state = $sponge->set_pending($dst_ip, 0);
    }


    return;
}

###############################################################################
# start_daemon($sponge, $Pid_File);
#
#   Fork off into the background, i.e. run as a daemon.
#   Create a PID file as well.
#
###############################################################################
sub start_daemon($$) {
    my ($sponge, $Pid_File) = @_;

    if (-f $Pid_File) {
        open(PID, "<$Pid_File"); chomp(my $pid = <PID>); close PID;
        if ($pid) {
            chomp(my $proc = `ps h -p $pid -o args`);
            if ($proc =~ /$PROG/) {
                log_fatal("already running (pid = $pid)\n");
            }
        }
        print STDERR "$PROG: WARNING: removing stale PID file $Pid_File\n";
        log_warning("removing stale PID file %s", $Pid_File);
        unlink $Pid_File;
    }

    if (my $pid = fork) {
        # Parent process. We are going to exit, letting our child
        # roam free.
        log_verbose(1, "$PROG: going into the background; pid=$pid\n");
        exit(0);
    }

    # Child (daemon) process.
    open my $pid_fh, '>', $Pid_File
        or log_fatal("cannot write pid to %s: %s", $Pid_File, $!);

    print $pid_fh $$, "\n";
    $Wrote_Pid = $$;
    close $pid_fh;

    # Close the standard file descriptors.
    close STDOUT;
    close STDERR;
    close STDIN;

    # Verbosity has no place in a daemon.
    log_is_verbose(0);
    return undef;
}

###############################################################################
# process_signal($name);
#
#   We received a signal $name. Handle it, i.e. gracefully exit.
#
###############################################################################
sub process_signal {
    my ($sponge, $name) = @_;

    log_crit("Received %s signal -- exiting", $name);
    exit(1);
}


###############################################################################
#                              UTILITY ROUTINES
###############################################################################

# do_status($signal, $sponge)
#
#   Write status information to the 'statusfile'.
#
sub do_status {
    my ($signal, $sponge) = @_;
    my $fname = $sponge->user('statusfile');
    my $start_time = $sponge->user('start_time');

    if (!length($fname)) {
        $fname = '/dev/null';
    }

    event_info(EVENT_STATE, "SIG%s; dumping status to %s", $signal, $fname);

    # Open the status file as read/write, non-blocking,
    # and don't buffer anything. This is useful if the destination
    # is a FIFO and there is not always a reader.

    my $fh = new IO::File($fname, O_RDWR|O_CREAT);

    unless ($fh) {
        event_err(EVENT_IO, "cannot write status to %s: %s", $fname, $!);
        return;
    }

    $fh->truncate(0);
    $fh->autoflush(1);
    $fh->blocking(0);

    ##########################################################################
    $fh->print( get_status_info_s($sponge), "\n" );
    ##########################################################################
    my ($state_table_s, $nalive, $ndead, $npending)
            = get_ip_state_table_s($sponge);
    $fh->print( $state_table_s, "\n" );
    ##########################################################################
    my ($nmac, $arp_table_s) = get_arp_table_s($sponge);
    $fh->print( $arp_table_s );
    ##########################################################################
    $fh->print(sprintf("\nalive=%d dead=%d pending=%d ARP_entries=%d\n",
                        $nalive, $ndead, $npending, $nmac));
    ##########################################################################
    $fh->close;
    event_notice(EVENT_STATE,
            "status dumped; alive=%d dead=%d pending=%d ARP_entries=%d",
            $nalive, $ndead, $npending, $nmac);
}

Main;

1;

__END__

=pod

=head1 NAME

@NAME@ - automatically "sponge" ARP requests for dead IP addresses

=head1 SYNOPSIS

B<@NAME@> [I<options>] I<NETPREFIX/LEN> B<dev> I<DEV>

I<Options>:

    --age=secs
    --arp-update-methods={all,none,request,reply,gratuitous}*
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
    --sponge-network
    --statusfile=file
    --sweep=interval/threshold
    --sweep-at-start
    --sweep-skip-alive
    --verbose[=n]

B</etc/init.d/@NAME@> {B<start>|B<stop>|B<restart>|B<status>}

=head1 DESCRIPTION

The C<@NAME@> program "sponges" ARP queries from an Ethernet interface.

=head2 Sponging

The program monitors ARP queries for addresses in the I<NETPREFIX/LEN>
network and starts spoofing replies for them when the queries reach a
threshold (default @DFL_QUEUEDEPTH@ unanswered queries with an average
rate of @DFL_RATE@ or more per minute).

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

The program writes sponge/unsponge events to L<syslogd(8)|syslogd> with
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

=head1 OPTIONS

=over

=item B<--age>=I<secs>
X<--age>

Time until we consider an ARP entry "stale" (default @DFL_ARP_AGE@).
This really controls how often we refresh the entries in our internal
ARP cache.

=item B<--arp-update-methods>=[B<!>]I<method>,...
X<--arp-update-methods>

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

This value is also used by the L<inform|asctl/inform> command of L<asctl>(1).

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
L<syslogd(8)|syslogd>.

=item B<--passive>
X<--passive>

=item B<--no-passive>
X<--no-passive>

Run (don't run) in passive mode. When passive mode is activated, the
sponge will I<never> send ARP queries from its own IP address. See

=item B<--dummy>
X<--dummy>

Dummy operation (simulate sponging). Does send ARP queries, but no ARP
(sponge) replies.

=item B<--flood-protection>=I<r>
X<--flood-protection>

ARP threshold rate in queries/sec (default @DFL_FLOOD_PROTECTION@) above
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
X<--gratuitious>X<--nogratuitous>

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

Logging level for L<syslogd(8)|syslogd> logging. Default is C<info>.

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
(default: @DFL_PENDING@).

The L<pending state|/Pending State> (see L<above|/Pending State>)
serves as an extra check before sponging: if it gets a response from
the target IP, then that address is obviously not dead yet.

Choosing the I<pending> parameter wisely (larger than one, but not much
larger than @DFL_PENDING@) will prevent unjustified sponging (e.g. when
a Black Hat sends streams of ARP queries in the hopes of getting the
target sponged).

B<Tip>: Increasing the value pending parameter by one adds one second
of delay before the sponge kicks in. If you increase this value significantly,
you should consider decreasing the L<--queuedepth|/--queuedepth> parameter
as well.

=item B<--permissions>=[I<owner>]:[I<group>]:[I<mode>]
X<--permissions>

Set the permissions on the L<control socket|/--control>. Default is
C<@DFL_SOCK_PERMS@>.

=item B<--pidfile>=I<pidfile>
X<--pidfile>

Write daemon PID to I<pidfile> instead of the default
(I<rundir>/pid).

=item B<--proberate>=I<n>
X<--proberate>

The rate at which we send our ARP queries. Used when sweeping
and querying pending addresses.
Default is @DFL_PROBERATE@, but check the rate your network can
comfortably handle.

Generally speaking, the following formula gives an upper bound for
the time spent in a probing sweep:


            IP_SIZE
  Tmax =   ---------
           PROBERATE

So a sweep over 100 addresses with a query rate of 50 takes about 2 seconds.

The CPU can usually throw ICMP packets at an interface much faster than
the actual wire-speed, so many do not make it onto the wire.
Furthermore, since ARP queries are broadcast and thus typically CPU-bound,
they may get rate-limited by the L2 infrastructure or at the
receiving stations.

Having the sponge itself be a source of periodic broadcast storms pretty
much defeats the purpose of the thing.

=over 7

=item NOTE:

Due to the way the C<proberate> delays are implemented, it's possible
that you will not be able to go higher than 100 and possibly even get stuck
at 50 or so.  See also L<Bugs and Limitations|/BUGS AND LIMITATIONS>
below.

=back

=item B<--queuedepth>=I<n>
X<--queuedepth>

Number of ARP queries over which to calculate average rate (default
@DFL_QUEUEDEPTH@).
Sponging is not triggered until at least this number of ARP queries are seen.

=item B<--rate>=I<r>
X<--rate>

ARP threshold rate in queries/min (default @DFL_RATE@). If the ARP queue
(see above) is full, and the average rate of incoming queries per second
exceeds I<r>, we move the target IP to I<PENDING> state (but see also
L<--flood-protection|/--flood-protection>.

=item B<--rundir>=I<path>
X<--rundir>

Base directory for run-time files. Default is "F<@SPONGE_VAR@>/I<interface>".

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
L<asctl|asctl>(8) utility.

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
This options turns off logging to L<syslogd(8)|syslogd> and
causes the information to be printed to F<STDOUT> instead.
The higher the level I<n> (default is 1 if not given), the
more detailed information is printed.  Not recommended for
production use.

Has no effect when L<--daemon|/--daemon> is specified.

=back

=head1 EXAMPLES

To start the program on C<eth0> for the C<91.200.17.0/26> network,
simply use:

   @NAME@ 91.200.17.0/26 dev eth0

=head2 Status Dumping

To use the status dumping functionality, do:

   @NAME@ --daemon --statusfile=/tmp/sponge.out \
        91.200.17.0/26 dev eth0

Then send a C<USR1> signal to the process:

   pkill -USR1 @NAME@

Now F</tmp/sponge.out> should contain something like:

  id:               @NAME@
  pid:              27482
  version:          @RELEASE@(146)
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

The sponge can be started by an L<init(1)|init> script,
F</etc/init.d/@NAME@>. This script looks for the following files:

=over 4

=item F</etc/default/@NAME@/defaults>

Contains default options for every sponge instance. The options are
specified as L<sh(1)|sh> shell variables.

=item F</etc/default/@NAME@/ethX>

Contains a network definition for the sponge on I<ethX>.

=back

For every I<ethX> file the script finds, it starts a sponge daemon on
the I<ethX> interface. The sponge daemon will write its status file to
F<$SPONGE_VAR/ethX/status> and create a control socket in
F<$SPONGE_VAR/ethX/control>.

=head2 Init Variables

For boolean variables, "true", "yes", "on" and positive integers evaluate
to "true", other values are "false".

=over 4

=item I<AGE> (integer)

The argument to C<--age>.

=item I<DISABLED> (boolean)

Whether the arpsponge is disabled. Can be set globally or per
interface. Note that if it is set globally, the individual interface
files can still explicitly override this value.

=item I<DUMMY_MODE> (boolean)

Use C<--dummy> on the sponge. Note that L<asctl(8)|asctl> clients can
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

=item I<PERMISSIONS>

The argument to C<--permissions>.

=item I<QUEUE_DEPTH> (integer)

The argument to C<--queuedepth>.

=item I<RATE> (integer)

The argument to C<--rate>.

=item I<SPONGE_NETWORK> (boolean)

Use C<--sponge-network>

=item I<SPONGE_VAR> (default: F<@SPONGE_VAR@>)

Directory root that holds state information for the various sponge
instances. The script will create the directory if it doesn't exist yet.
Together with the interface (I<$INTERFACE>) this is used to specify the
I<rundir> to the sponge ("B<--rundir>=I<$SPONGE_VAR>/I<$INTERFACE>").

=item I<SWEEP>

The argument to C<--sweep>.

=item I<SWEEP_AT_START> (boolean)

Use C<--sweep-at-start>

=item I<SWEEP_SKIP_ALIVE> (boolean)

Use C<--sweep-skip-alive>

=back

The I<ethX> files can override each of the above and can also specify:

=over 4

=item I<NETWORK> (mandatory)

This specifies the network for which to sponge.

=item I<DEVICE> (optional)

By default, the init script will use I<ethX> as the device name, but this
can be overridden with the I<DEVICE> variable.

=back

=head1 FILES

=over 4

=item F</etc/init.d/@NAME@>

Init script for the @NAME@.

=item F</etc/default/@NAME@/defaults>

Contains default options for the sponge's L<init(1)|init> script.

=item F</etc/default/@NAME@/ethX>

Contains a interface specific options for the sponge on I<ethX>.
This I<must> define the C<NETWORK> variable.

This is used by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/status>

Status file for the sponge daemon that runs on interface I<ethX>.
This is set up by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/control>

Control socket for L<asctl>(8).
This is set up by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/pid>

PID file for the sponge daemon that runs on interface I<ethX>.
This is set up by the sponge's L<init(1)|init> script.

=back

=head1 SEE ALSO

L<asctl(8)|asctl>,
L<aslogtail(8)|aslogtail>,
L<perl(1)|perl>, L<arp(8)|arp>.

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

Copyright 2003-2019, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
