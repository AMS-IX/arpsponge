#!@PERL@ -I../lib
# [Net::ARP is not clean, so "-w" flag to perl produces spurious warnings]
###############################################################################
# @(#)$Id$
###############################################################################
#
# ARP sponge
#
# (c) Copyright AMS-IX B.V. 2004; all rights reserved.
#
# See the LICENSE file that came with this package.
#
# A.Vijn,   2003-2004;
# S.Bakker, November 2004;
#
# Yes, this file is BIG. There's a POD at the end.
#
###############################################################################
use strict;
use Getopt::Long;
use Pod::Usage;

use Net::PcapUtils;
use NetPacket::Ethernet qw( :types );
use NetPacket::ARP qw( ARP_OPCODE_REQUEST );
use NetPacket::IP;
use Time::HiRes qw( time );
use Net::ARP;
use Sys::Syslog;
use Net::IPv4Addr qw( :all );
use IO::File;
use POSIX qw( strftime );

use M6::ARP::Sponge qw( :states );
use M6::ARP::Util qw( :all );

###############################################################################
$0 =~ s|.*/||g;
###############################################################################

use constant SYSLOG_IDENT => '@NAME@';

my $DFL_LOGLEVEL   = '@DFL_LOGLEVEL@';
my $DFL_RATE       = '@DFL_RATE@';
my $DFL_ARP_AGE    = '@DFL_ARP_AGE@';
my $DFL_PENDING    = '@DFL_PENDING@';
my $DFL_QUEUEDEPTH = '@DFL_QUEUEDEPTH@';

$::USAGE=<<EOF;
Usage: $0 [options] IPADDR/PREFIXLEN dev IFNAME

Options:
  --verbose[=n]     - be verbose; print information on STDOUT; turns off syslog
  --dummy           - dummy operation (simulate sponging); turns off syslog
  --loglevel=level  - syslog logging level ("$DFL_LOGLEVEL")
  --queuedepth=n    - number of ARP queries before we take notice ($DFL_QUEUEDEPTH)
  --rate=n          - ARP threshold rate in queries/min ($DFL_RATE)
  --pending=n       - number of ARP queries we send before sponging ($DFL_PENDING)
  --daemon=pidfile  - put process in background, write pid to pidfile
  --notify=file     - print notifications of sponge actions to file
  --age=secs        - time until we consider an ARP entry "stale" ($DFL_ARP_AGE)
  --statusfile=file - write status to "file" when receiving HUP or USR1 signal
  --re-init=file    - read initial sponge state from "file"
  --sweep=sec/thr   - periodically sweep for "quiet" IP addresses

See also "perldoc $0".
EOF

###############################################################################

my $Start_time   = time;

my %ARP_table;   # Keep an ARP table, keyed by IP, values are [MAC, time].

my $wrote_pid = 0;
my $daemon    = undef;

# ============================================================================
END {
	if (defined $wrote_pid && $wrote_pid>0) {
		print STDERR "$$ unlinking $daemon\n";
		unlink($daemon);
	}
}
# ============================================================================

# Some forward declarations.
sub start_daemon($$);

###############################################################################
# Main program code :-)
###############################################################################
sub Main {
	my $loglevel   = $DFL_LOGLEVEL;
	my $queuedepth = $DFL_QUEUEDEPTH;
	my $pending    = $DFL_PENDING;
	my $rate       = $DFL_RATE;
	my $age        = $DFL_ARP_AGE;
	my $notify     = undef;
	my $gratuitous = undef;
	my $dummy      = undef;
	my $statusfile = undef;
	my $re_init    = undef;
	my $verbose    = undef;
	my $help       = undef;
	my $man        = undef;
	my $sweep_sec       = undef;
	my $sweep_threshold = undef;

	####################################################################

	GetOptions(
		'verbose:i'    => sub { $verbose = defined($_[1]) ? $_[1] : 1 },
		'help|?'       => \$help,
		'man'          => \$man,
		'dummy!'       => \$dummy,
		'loglevel=s'   => \$loglevel,
		'rate=i'       => \$rate,
		'pending=i'    => \$pending,
		'statusfile=s' => \$statusfile,
		'daemon=s'     => \$daemon,
		'queuedepth=i' => \$queuedepth,
		'notify=s'     => \$notify,
		'age=i'        => \$age,
		're-init=s'    => \$re_init,
		'sweep=s'      => \$sweep_sec,
		'gratuitous!'  => \$gratuitous,
	) or pod2usage(2);

	die($::USAGE) if $help;
	pod2usage(-exitstatus => 0, -verbose => 2) if $man;

	if (length($sweep_sec)) {
		($sweep_sec, $sweep_threshold) = $sweep_sec =~ m|^(\d+)/(\d+)$|
			or die("Bad value for --sweep\n$::USAGE");
	}

	####################################################################

	my ($network, $netmask);

	die("Not enough parameters\n$::USAGE") if @ARGV < 3;
	die("Too many parameters\n$::USAGE")   if @ARGV > 3;

	die("Bad IP address \"$ARGV[0]\"\n")	
		unless Net::IPv4Addr::ipv4_chkip($ARGV[0]);

	($network, $netmask) = ipv4_network($ARGV[0]);

	die("Bad network mask or prefix length in \"$ARGV[0]\"\n")
		unless $netmask > 0;

	####################################################################

	my ($device);

	die("Invalid parameter syntax: expected \"dev\" instead of \"$ARGV[1]\"\n")
		unless lc $ARGV[1] eq 'dev';

	$device = $ARGV[2];

	####################################################################

	my ($notify_fh);

	if (defined $notify) {

		# Open the notification file as read/write, non-blocking,
		# and don't buffer anything. This is useful if the destination
		# is a FIFO and there is not always a reader.

		$notify_fh = new IO::File($notify, O_RDWR|O_CREAT)
			or die("$0: cannot write to $notify: $!\n");
		$notify_fh->truncate(0);
		$notify_fh->autoflush(1);
		$notify_fh->blocking(0);
	}

	####################################################################

	$| = ($verbose > 0 ? 1 : 0);

	my $sponge = new M6::ARP::Sponge(
			verbose      => $verbose,
			dummy        => $dummy,
			queuedepth   => $queuedepth,
			device       => $device,
			notify       => $notify_fh,
			loglevel     => $loglevel,
			network      => $network,
			netmask      => $netmask,
			max_pending  => $pending,
			max_rate     => $rate,
			arp_age      => $age,
			gratuitous   => $gratuitous,
			syslog_ident => SYSLOG_IDENT
		);

	$sponge->print_notify("action=init;dev=%s;ip=%s;mac=%s",
					$sponge->device, $sponge->my_ip, $sponge->my_mac);

	$sponge->print_log("Initializing $0 on [%s, %s, %s]",
					$sponge->device, $sponge->my_ip, $sponge->my_mac);

	# If we have to run in daemon mode, do so.
	start_daemon($sponge, $daemon) if length $daemon;

	####################################################################

	$::SIG{'INT'}  = sub { process_signal($sponge, 'INT')  };
	$::SIG{'QUIT'} = sub { process_signal($sponge, 'QUIT') };
	$::SIG{'TERM'} = sub { process_signal($sponge, 'TERM') };
	$::SIG{'USR1'} = sub { do_status('USR1', $sponge, $statusfile) };
	$::SIG{'HUP'}  = sub { do_status('HUP',  $sponge, $statusfile) };

	$::SIG{'ALRM'} = sub { do_sweep($sponge, $sweep_sec, $sweep_threshold) };

	alarm($sweep_sec);
	my $err = Net::PcapUtils::loop(
			\&process_pkt,
			USERDATA => $sponge,
			DEV      => $device,
			PROMISC  => 1
		);
	alarm(0);

	if (length($err)) {
		print "ERROR: $err\n";
		exit(1);
	}
	exit(0);
}

Main;

###############################################################################
# do_sweep($sponge, $interval, $threshold);
#
#    Called by the alarm() interrupt.
#
#    Sweep the range of IP addresses and send ARP requests for the ones
#    that have been quiet for at least $threshold seconds.
#
#    After the sweep, reset the alarm timer to $interval.
#
###############################################################################
sub do_sweep($$) {
	my $sponge     = shift;
	my $interval   = shift;
	my $threshold  = shift;

	my ($net, $mask) = ($sponge->network, $sponge->netmask);
	$sponge->print_log("sweeping for quiet entries on $net/$mask");
	
	my $lo = ip2int(ipv4_network($net, $mask))+1;
	my $hi = ip2int(ipv4_broadcast($net, $mask))-1;

	my $nprobe = 0;
	my $v = $sponge->is_verbose($sponge->is_verbose-1);
	for (my $num = $lo; $num <= $hi; $num++) {
		my $ip = int2ip($num);
		my $age = time - $sponge->state_mtime($ip);
		if ($age >= $threshold) {
			$sponge->verbose(1, "DO PROBE $ip ($age >= $threshold)\n");

			$sponge->send_probe($ip);
			$sponge->set_state_mtime($ip, time);
			$nprobe++;
		} else {
			$sponge->verbose(1, "SKIP PROBE $ip ($age < $threshold)\n");
		}
	}
	$sponge->is_verbose($v);
	alarm($interval);
	$sponge->print_log("probed $nprobe IP addresses");
}

###############################################################################
# process_pkt($sponge, $hdr, $pkt);
#
#    Called by Net::PcapUtils::loop() as:
#
#        process_pkt($sponge, $hdr, $pkt);
#
#    Process sniffed packets. The "$sponge" parameter is what was passed
#    as the USERDATA parameter to the Net::PcapUtils::loop call. In our
#    case, that is the M6::ARP::Sponge instance, a.k.a. "$sponge".
#
###############################################################################
sub process_pkt {
	my ($sponge, $hdr, $pkt) = @_;
	my $eth_obj = NetPacket::Ethernet->decode($pkt);
	my $src_mac = hex2mac($eth_obj->{src_mac});

	# Self-generated packets are not relevant.
	return if $src_mac eq $sponge->my_mac;

	# Always "unsponge" the source IP address!
	if ($eth_obj->{type} == ETH_TYPE_IP) {
		my $ip_obj  = NetPacket::IP->decode($eth_obj->{data});
		my $src_ip  = $ip_obj->{src_ip};
		$sponge->set_alive($src_ip, $src_mac);
		return;
	}
	else {
		return unless $eth_obj->{type} == ETH_TYPE_ARP;
	}

	# From this point on, we have an ARP packet.

	my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
	my $dst_ip  = hex2ip($arp_obj->{tpa});
	my $src_ip  = hex2ip($arp_obj->{spa});

	# Always "unsponge" the source IP address!
	$sponge->set_alive($src_ip, $src_mac);

	# Ignore anything that is not an ARP "WHO-HAS" request.
	return unless $arp_obj->{opcode} == ARP_OPCODE_REQUEST;

	# From this point on, we have an ARP "WHO-HAS" request.

	unless ( $sponge->is_my_network($dst_ip) )
	{
		# We only store/sponge ARPs for our "local" IP addresses.

		$sponge->print_log("misplaced ARP for %s from %s\@%s",
								$dst_ip, $src_ip, $src_mac);
		$sponge->print_notify("action=misfit;src=%s;mac=%s;dst=%s",
								$src_ip, $src_mac, $dst_ip);

		return; # b-bye...
	}

	if ($sponge->is_my_ip($dst_ip)) {
		# ARPs for our IPs require no action (handled by the kernel),
		# except for maybe updating our internal ARP table.

		$sponge->verbose(1, "ARP from $src_ip for our $dst_ip\n");
		$sponge->set_alive($dst_ip, $sponge->my_mac);
		return;
	}
	elsif ($src_ip eq '0.0.0.0') {
		# DHCP duplicate IP detection.
		# See RFC 2131, p38, bottom.
		$sponge->verbose(1, "DHCP duplicate IP detection",
				" from $src_ip\@$src_mac",
				" for $dst_ip\n"
			);

		# Mmmh, don't let go completely yet... If all is well,
		# we'll soon start seeing "real" traffic from this
		# address...
		if ($sponge->get_state($dst_ip) != ALIVE) {
			$sponge->set_pending($dst_ip, 0);
		}
		return;
	}

	my $state = $sponge->get_state($dst_ip);

	$sponge->verbose(2, "ARP WHO HAS $dst_ip TELL $src_ip ");
	if ($state == DEAD) {
		my $age = time-$sponge->state_mtime($dst_ip);
		$sponge->verbose(2, "[sponged=yes; $age secs ago]\n");
	} else {
		$sponge->verbose(2, "[sponged=no]\n");
	}

	my $query_time = time;

	$sponge->queue->add($dst_ip, time);

	if ($state == ALIVE) {
		if ($sponge->queue->is_full($dst_ip)) {
			if ($sponge->queue->rate($dst_ip) > $sponge->max_rate) {
				$state = $sponge->set_pending($dst_ip, 0);
			}
		}
	}

	if ($state >= PENDING(0)) {
		if ($state > PENDING($sponge->max_pending)) {
			$state = $sponge->set_dead($dst_ip);
		}
		else {
			$state = $sponge->incr_pending($dst_ip);
			#print STDERR "$dst_ip: STATE $state\n";
			$sponge->send_probe($dst_ip);
		}
	}

	if ($state == DEAD) {
		$sponge->send_reply($dst_ip, $arp_obj);
	}
}

####################
####################
####################

###############################################################################
# start_daemon($sponge, $pidfile);
#
#	Fork off into the background, i.e. run as a daemon.
#	Create a PID file as well.
#
###############################################################################
sub start_daemon($$) {
	my $sponge  = shift;
	my $pidfile = shift;
	if (-f $pidfile) {
		open(PID, "<$pidfile"); chomp(my $pid = <PID>); close PID;
		if ($pid) {
			chomp(my $proc = `ps h -p $pid -o args`);
			if ($proc =~ /$0/) {
				$sponge->print_log("$0 already running (pid = %d)", $pid);
				die("$0: already running (pid = $pid)\n");
			}
		}
		print STDERR "$0: WARNING: removing stale PID file $pidfile\n";
		$sponge->print_log("removing stale PID file %s", $pidfile);
		unlink $pidfile;
	}

	if (my $pid = fork) {
		# Parent process. We are going to exit, letting our child
		# roam free.
		$sponge->verbose(1, "$0: going into the background; pid=$pid\n");
		exit(0);
	}

	# Child (daemon) process.
	if (open(PID, ">$pidfile")) {
		print PID $$, "\n";
		$wrote_pid++;
		close PID;
	}
	else {
		my $err = $!;
		$sponge->print_log("FATAL: cannot write pid to %s: %s", $pidfile, $err);
		die("$0: cannot write pid to $pidfile: $err\n");
	}

	# Close the standard file descriptors.
	close STDOUT;
	close STDERR;
	close STDIN;
	$sponge->is_verbose(undef);
	$sponge->is_dummy(undef);
	return undef;
}

###############################################################################
# process_signal($name);
#
# 	We received a signal $name. Handle it, i.e. gracefully exit.
#
###############################################################################
sub process_signal {
	alarm(0);
	my $sponge = shift;
	my $name = shift;

	$sponge->print_log("Received %s signal -- exiting", $name);
	$sponge->print_notify("action=quit;reason=SIG$name");
	exit(1);
}


###############################################################################
#                              UTILITY ROUTINES
###############################################################################

# do_status($filename)
#
#	Write status information to $filename.
#
sub do_status {
	my $signal = shift;
	my $sponge = shift;
	my $filename = shift;

	unless (length($filename)) {
		$sponge->verbose(1, "Ignoring SIG$signal -- no dump file set\n");
		return;
	}

	$sponge->verbose(1, "SIG$signal -- dumping status to $filename\n");


	# Open the status file as read/write, non-blocking,
	# and don't buffer anything. This is useful if the destination
	# is a FIFO and there is not always a reader. Same thing as
	# the $notify_fh case, really.

	my $fh = new IO::File($filename, O_RDWR|O_CREAT);

	unless ($fh) {
		$sponge->print_log("cannot write status to $filename: $!");
		return;
	}

	$fh->truncate(0);
	$fh->autoflush(1);
	$fh->blocking(0);

	my $now = time;
	$fh->print(
			"id:      ", $sponge->syslog_ident, "\n",
			"network: ", $sponge->network, "/", $sponge->netmask, "\n",
			"date:    ",
				strftime("%Y-%m-%d %H:%M:%S", localtime($now)),
				" [", int($now), "]\n",
			"started: ",
				strftime("%Y-%m-%d %H:%M:%S", localtime($Start_time)),
				" [", int($Start_time), "]\n",
			"\n"
	);

	##########################################################################
	$fh->print(
			"<STATE>\n",
			 sprintf("%-17s %-12s %7s %12s %7s\n",
					 "# IP", "State", "Queries", "Rate (q/min)", "Updated")
		 );

	my $queue = $sponge->queue;
	my $states = $sponge->state_table;
	
	my $ip;
	for $ip (sort { ip2int($a) <=> ip2int($b) } keys %$states) {
		my $state = $$states{$ip};
		next unless defined $state;

		my $depth = $queue->depth($ip);
		my $rate  = $queue->rate($ip);
		my $stamp = $sponge->state_mtime($ip);

		my $str;
		SWITCH: {
			$state == DEAD			&&do{
				$str = 'DEAD';
				last SWITCH};
			$state == ALIVE			&&do{
				$str = 'ALIVE';
				last SWITCH};
			$state == STATIC		&&do{
				$str = 'STATIC';
				last SWITCH};
			$state >= 0				&&do{
				$str = 'PENDING('.int($state).')';
				last SWITCH};
		}

		if ($stamp > 0) {
			$stamp = strftime("%Y-%m-%d %H:%M:%S", localtime($stamp));
		}
		else {
			$stamp = 'never';
		}
		$fh->print(
			sprintf("%-17s %-12s %7d %8.3f     %s\n",
				$ip, $str, $depth, $rate, $stamp)
		);
	}
	$fh->print("</STATE>\n\n");

	##########################################################################

	$fh->print(
			"<ARP-TABLE>\n",
			sprintf("%-17s %-17s %-11s %s\n", "# MAC", "IP", "Epoch", "Time")
		);

	for $ip (sort { ip2hex($a) cmp ip2hex($b) } keys %{$sponge->arp_table}) {
		my ($mac, $time) = @{$sponge->arp_table->{$ip}};

		$fh->print(
			sprintf("%-17s %-17s %-11d ", $mac, $ip, int($time)),
			strftime("%Y-%m-%d %H:%M:%S\n", localtime($time))
		);
	}

	$fh->print("</ARP-TABLE>\n");

	##########################################################################
	$fh->close;
}


1;

__END__

# do_status($filename)
#
#	Write status information to $filename.
#
sub do_status {
	my $sponge = shift;
	my $filename = shift;

	return unless length($filename);

	# Open the status file as read/write, non-blocking,
	# and don't buffer anything. This is useful if the destination
	# is a FIFO and there is not always a reader. Same thing as
	# the $Notify_fh case, really.

	my $fh = new IO::File($filename, O_RDWR|O_CREAT);

	unless ($fh) {
		print_log("cannot write status to $filename: $!");
		return;
	}

	$fh->truncate(0);
	$fh->autoflush(1);
	$fh->blocking(0);

	my $now = time;
	$fh->print(
			"id:      ", SYSLOG_IDENT, "\n",
			"date:    ",
				strftime("%Y-%m-%d %H:%M:%S", localtime($now)),
				" [$now]\n",
			"started: ",
				strftime("%Y-%m-%d %H:%M:%S", localtime($Start_time)),
				" [$Start_time]\n",
			"sponged: ", int(keys %Sponged), "\n",
			"\n"
	);

	##########################################################################
	$fh->print(
			"<QUEUE DEPTH=$::opt_queuedepth>\n",
			 sprintf("%-17s %7s %11s %11s %12s\n", "# IP", "Queries",
											"First", "Last", "Rate (q/sec)"));

	my @iplist = sort { ip2hex($a) cmp ip2hex($b) } keys %Query_times;

	for my $ip (@iplist) {
		my $q = $Query_times{$ip};
		my $depth = int(@$q);
		next unless $depth;
		my $first = $q->[0];
		my $last = $q->[$depth-1];
		$fh->print(
				sprintf("%-17s %7d %11d %11d %8.3f\n",
					$ip, $depth, $first, $last,
					$depth*1.0/($last>$first ? ($last-$first) : 1)));
	}
	$fh->print("</QUEUE>\n\n");
	##########################################################################
	$fh->print(
			"<SPONGE-TABLE>\n",
			sprintf("%-17s %-17s %-11s %s\n", "# IP", "MAC", "Epoch", "Time")
		);

	for my $ip (sort { ip2hex($a) cmp ip2hex($b) } keys %Sponged) {
		my $mac = $ARP_table{$ip} ? $ARP_table{$ip}->[0] : 'unknown';

		$fh->print(
			sprintf("%-17s %-17s %-11d ", $ip, $mac, $Sponged{$ip}),
			strftime("%Y-%m-%d %H:%M:%S\n", localtime($Sponged{$ip}))
		);
	}

	$fh->print("</SPONGE-TABLE>\n\n");
	##########################################################################
	$fh->print(
			"<ARP-TABLE>\n",
			sprintf("%-17s %-17s %-11s %s\n", "# MAC", "IP", "Epoch", "Time")
		);

	for my $ip (sort { ip2hex($a) cmp ip2hex($b) } keys %ARP_table) {
		my ($mac, $time) = @{$ARP_table{$ip}};

		$fh->print(
			sprintf("%-17s %-17s %-11d ", $mac, $ip, $time),
			strftime("%Y-%m-%d %H:%M:%S\n", localtime($time))
		);
	}

	$fh->print("</ARP-TABLE>\n");
	##########################################################################
	$fh->close;

}


=pod

=head1 NAME

@NAME@ - automatically "sponge" ARP requests for dead IP addresses

=head1 SYNOPSIS

B<@NAME@> [I<options>] I<NETPREFIX/LEN> B<dev> I<DEV>

=over 4

=item I<options>:

[B<--verbose>[=I<n>]]
[B<--dummy>]
[B<--loglevel>=I<level>]
[B<--rate>=I<n>]
[B<--pending>=I<n>
[B<--queuedepth>=I<n>]
[B<--daemon>=I<pidfile>]
[B<--sweep>=I<interval>/I<threshold>]
[B<--[no]gratuitous>
[B<--notify>=I<file>]
[B<--age>=I<secs>]
[B<--status>=I<file>]
[B<--re-init>=I<file>]

=back

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

Many systems (mostly routers) will send a gratuitous ARP when they bring
up their interfaces, advertising their presence and seeding ARP caches.

=item 2.

The sponge receives an arbitrary IP or ARP packet from the sponged IP address.

Some systems do not send gratuitous ARP packets when bringing up interfaces.
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

=head3 Gratuitous ARP

The program can send out a gratuitous ARP when it starts to sponge an
address. This should bring down the ARP rate on the LAN further, since
ideally all devices update their ARP cache immediately.

=head3 Sweeping

Not all devices send a gratuitous ARP when they come up, so it may be
necessary to periodically sweep the IP range for dead or very
quiet addresses. This also helps to clear the status for very quiet
hosts.

=head3 Logging

The program writes sponge/unsponge events to L<syslogd(8)|syslogd> with
priority C<info>.

It can also write more detailed event info to a file or fifo (see
B<--notify> below) and when the B<--statusfile> argument is given, it will
write a summary of its current state upon receiving a C<HUP> or C<USR1>
signal.

=head1 OPTIONS

=over

=item X<--age>B<--age>=I<secs>

Time until we consider an ARP entry "stale" (default @DFL_ARP_AGE@).
This really controls how often we refresh the entries in our internal
ARP cache.

=item X<--daemon>B<--daemon>=I<pidfile>

Put process in background (run as a daemon). Leave the process
identification (PID) in I<pidfile>.

If I<pidfile> already exists and the value in the file is that of a
running sponge process, the program will exit with an appropriate
error diagnostic. Otherwise, it forks into the background, closes
the standard input, output and error file descriptors and writes its
PID to I<pidfile>.

This option turns off C<--dummy> and  C<--verbose> and
enables logging to L<syslogd(8)|syslogd>.

=item X<--dummy>B<--dummy>

Dummy operation (simulate sponging). Does not send probes or replies, but
pretends it does.
This options turns off logging to L<syslogd(8)|syslogd> and
causes the information to be printed to F<STDOUT> instead.

Does not work in conjunction with C<--daemon>.

=item X<--gratuitious>X<--nogratuitous>B<--[no]gratuitous>

Do (not) send gratuitous ARP queries when sponging an address.

=item X<--loglevel>B<--loglevel>=I<level>

Logging level for L<syslogd(8)|syslogd> logging. Default is C<info>.

=item X<--notify>B<--notify>=I<file>

Print notifications of sponge actions to I<file>. The I<file> can grow quite
large, so this is really meant for writing to a FIFO (see L<mkfifo(1)|mkfifo>).

See also L<NOTIFICATIONS> below.

=item X<--queuedepth>B<--queuedepth>=I<n>

Number of ARP queries over which to calculate average rate (default
@DFL_QUEUEDEPTH@).
Sponging is not triggered until at least this number of ARP queries are seen.

=item X<--rate>B<--rate>=I<n>

ARP threshold rate in queries/min (default @DFL_RATE@).

=item X<--pending>B<--pending>=I<n>

Number of ARP queries we send ourselves before sponging an IP address
(default: @DFL_PENDING@).

After the ARP queue for an IP address if full and the rate exceeds the
L<--rate|/--rate> parameter, the sponge allows I<n> more ARP queries,
but each time sends a query itself as well. This serves as an extra check
before sponging.

Choosing the I<pending> parameter wisely (around @DFL_PENDING@) will
prevent unjustified sponging (e.g. when a Black Hat sends streams of
ARP queries in the hopes of getting the target sponged).

=item X<--re-init>B<--re-init>=I<file>

Read initial sponge state from I<file>. The format of this file should
be the same as that of the status file (see above). The sponge will read
the entries between C<E<lt>SPONGE-TABLEE<gt>> and
C</E<lt>SPONGE-TABLEE<gt>> and enter this into its initial sponge table.

=item X<--statusfile>B<--statusfile>=I<file>

Write status to I<file> when receiving the C<HUP> or C<USR1> signal.

=item X<--sweep>B<--sweep>=I<interval>/I<threshold>

Every I<interval> seconds, sweep the IP range for IP addresses who we
haven't heard from or queried in the last I<threshold> seconds. This sweeps
over all IP addresses, both sponged and quietly alive.

Example: C<--sweep=900/3600>. This will cause the program to sweep every
15 minutes, looking for the IP addresses it hasn't heard anything from
or sent anything to in the last hour. This does not mean that it queries
a silent address every 15 minutes, it just checks whether it should and
sends out no more than one query per hour for that address.

If the I<interval> vs. I<threshold> thing is confusing, just remember the
following:

=over 4

=item o

A shorter I<interval> generally results in a better spread of
sweep ARP queries at the cost of more processing spent in sweeping.

=item o

A shorter I<threshold> results in a quicker rediscovery of a sponged
address that has come back but has been quiet for some reason at the
cost of more ARP queries from the host.

=back

=item X<--verbose>B<--verbose>[=I<n>]

Be verbose; print information on F<STDOUT>;
This options turns off logging to L<syslogd(8)|syslogd> and
causes the information to be printed to F<STDOUT> instead.
The higher the level I<n> (default is 1 if not given), the
more detailed information is printed.  Not recommended for
production use.

Does not work in conjunction with C<--daemon>.

=back

=head1 NOTIFICATIONS

The program can write notifications of "significant" events to a separate file.
This is not really meant to be a regular file (unless you want to create
really large files), but rather FIFOs (see L<mkfifo(1)|mkfifo>).

Notifications take the form of:

=over 4

=item id=B<@NAME@>;action=B<init>;dev=I<DEV>;ip=I<IPADDR>;mac=I<MACADDR>

This event is written when the program starts and indicates its local
interface (I<DEV>), IP address (I<IPADDR>) and MAC address (I<MACADDR>).

=item id=B<@NAME@>;action=B<flip>;ip=I<IPADDR>;mac=I<NEWMAC>;old=I<OLDMAC>

IP address (I<IPADDR>) changed from I<OLDMAC> to I<NEWMAC>.

=item id=B<@NAME@>;action=I<ACTION>;ip=I<IPADDR>;mac=I<MACADDR>

This event is written on a number of occasions. I<ACTION> can be:

=over 12

=item B<learn>:

Program learned a new IP address (I<IPADDR>) behind I<MACADDR>.

=item B<refresh>:

ARP cache entry for (I<IPADDR>, I<MACADDR>) was refreshed.

=item B<clear>:

Unanswered ARP query queue for I<IPADDR> was cleared, because
a frame came in from that address with source MAC I<MACADDR>).

=item B<sponge>:

Sponge for I<IPADDR> kicked in. Sponging using MAC address I<MACADDR>.

=item B<unsponge>:

Sponge for I<IPADDR> aborted.
Address is now owned by I<MACADDR>.

=back

=item id=B<@NAME@>;action=B<quit>;reason=I<REASON>

Program exited because of I<REASON>, which is usually a signal of some sort.

=back

=head1 EXAMPLES

To start the program on C<eth0> for the C<193.194.136.128/25> network,
simply use:

   @NAME@ 193.194.136.128/25 dev eth0

=head2 Using the Event Notification

To use the event notification, do:

   mkfifo --mode=644 /var/run/sponge.out

   @NAME@ --daemon=/var/run/sponge.pid \
             --notify=/var/run/sponge.event \
             193.194.136.128/25 dev eth0 

   cat /var/run/sponge.event

=head2 Status Dumping

To use the status dumping functionality, do:

   @NAME@ --daemon=/var/run/sponge.pid \
             --statusfile=/tmp/sponge.out \
             193.194.136.128/25 dev eth0 

Then send a C<USR1> signal to the process:

   pkill -USR1 @NAME@

Now F</tmp/sponge.out> should contain something like:

   id:      @NAME@
   network: 193.194.136.128/25
   date:    2005-05-01 10:16:12 [1114935372]
   started: 2005-04-30 23:26:39 [1114896399]

   <STATE>
   # IP              State        Queries Rate (q/min) Updated
   193.194.136.129   ALIVE              0    0.000     2005-05-01 10:15:58
   193.194.136.130   DEAD               6    0.012     2005-05-01 09:56:40
   193.194.136.131   ALIVE              1    0.000     2005-05-01 09:41:40
   193.194.136.135   ALIVE              0    0.000     2005-05-01 10:16:12
   193.194.136.139   ALIVE              0    0.000     2005-05-01 10:06:28
   193.194.136.140   DEAD               5    0.018     2005-05-01 09:41:40
   193.194.136.143   DEAD               5    0.021     2005-05-01 10:11:40
   193.194.136.146   ALIVE              0    0.000     2005-05-01 09:41:40
   193.194.136.147   DEAD               6    0.013     2005-05-01 09:26:40
   193.194.136.148   ALIVE              0    0.000     2005-05-01 10:12:38
   193.194.136.185   PENDING(3)         3    0.019     2005-05-01 09:43:16
   193.194.136.205   PENDING(4)         4    0.012     2005-05-01 09:43:16
   </STATE>

   <ARP-TABLE>
   # MAC             IP                Epoch       Time
   00:07:eb:46:48:e1 193.194.136.129   1114935358  2005-05-01 10:15:58
   00:40:96:55:a7:2b 193.194.136.131   1114933300  2005-05-01 09:41:40
   08:00:20:ec:8a:24 193.194.136.132   1114935329  2005-05-01 10:15:29
   00:30:48:29:44:a6 193.194.136.135   1114935372  2005-05-01 10:16:12
   00:60:2e:00:17:9f 193.194.136.139   1114934788  2005-05-01 10:06:28
   00:30:48:29:44:a6 193.194.136.146   1114933300  2005-05-01 09:41:40
   00:03:93:a8:d2:0c 193.194.136.148   1114935158  2005-05-01 10:12:38
   </ARP-TABLE>

=head1 SYSTEM INIT SCRIPT

The sponge can be started by an L<init(1)|init> script,
F</etc/init.d/@NAME@>. This script looks for the following files:

=over 4

=item F</etc/default/@NAME@/defaults>

Contains default options for every sponge instance. The options are
specified as L<sh(1)|sh> shell variables. The options recognised are:

=over 4

=item I<$SPONGE_VAR> (default: F<@SPONGE_VAR@>)

Directory root that holds state information for the various sponge
instances. The script will create the directory if it doesn't exist yet.

=item I<$SPONGE_OPTIONS> (default: C<@SPONGE_OPTIONS@>)

Other command line options to give to the B<@NAME@> daemon. Please note
that the script already provides appropriate C<--notify>, C<--statusfile>
and C<--daemon> options.

=back

=item F</etc/default/@NAME@/ethX>

Contains a network/prefixlen for the sponge on I<ethX>. N.B.: The
I<only> thing in this file should be a line of the form
"I<aaa.bbb.ccc.ddd/len>"!

=back

For every I<ethX> file the script finds, it starts a sponge daemon on
the I<ethX> interface. The sponge daemon will write its status file to
F<$SPONGE_VAR/ethX/status> and the notifications to the
F<$SPONGE_VAR/ethX/notify> FIFO.

=head1 FILES

=over 4

=item F</etc/init.d/@NAME@>

Init script for the @NAME@.

=item F</etc/default/@NAME@/defaults>

Contains default options for the sponge's L<init(1)|init> script.

=item F</etc/default/@NAME@/ethX>

Contains a network/prefixlen for the sponge on I<ethX>.
This is used by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/status>

Status file for the sponge daemon that runs on interface I<ethX>.
This is set up by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/notify>

Notification FIFO for the sponge daemon that runs on interface I<ethX>.
This is set up by the sponge's L<init(1)|init> script.

=item F<@SPONGE_VAR@/ethX/pid>

PID file for the sponge daemon that runs on interface I<ethX>.
This is set up by the sponge's L<init(1)|init> script.

=back

=head1 SEE ALSO

L<perl(1)|perl>, L<arp(8)|arp>, L<mkfifo(1)|mkfifo>.

=head1 BUGS AND LIMITATIONS

=over 3

=item o

Nothing prevents multiple sponge instances for the same interface/network
from being run if they specify different PID files.

=item o

You can specify only one network prefix to listen to per interface.
If you want to monitor multiple prefixes, you will have to find a common
prefix and monitor that.

=item o

The notification FIFO should have I<only one> reader. Multiple readers will
have unpredictable results: some messages are split across the readers
(so they only see partial messages), others are seen by one but not the
others.

=back

=head1 AUTHORS

Arien Vijn at AMS-IX (arien.vijn@ams-ix.net) created
the concept and implemented the first version.

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net) built upon the concept
and produced this beast.

=cut
