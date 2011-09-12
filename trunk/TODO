@(#) $Id$

--------------------------------------------------
Tue Mar 29 23:13:42 CEST 2011

Internal storage of IP and MAC addresses is now done
as hex strings.

Need to rework the client/server protocol, so the
client also sends and receives HEX strings. See the
doc/command_mapping.txt file.

--------------------------------------------------
Wish list for future enhancements:

* setuid() to unprivileged user after opening relevant streams.

* use ithreads for better real-time behaviour:
	
	- process
	- learner
	- sweeper
	- prober

	Process:    Always active, listens to packets on the wire.
                Handles ALIVE->PENDING and DEAD->ALIVE, manages
                the ARP table.

	Learner:    stays active for "n" iterations, then finishes.

	Prober:     waits for Learner to finish, then every second, probes
                the IPs that are PENDING, moving them to DEAD if necessary.

	Sweeper:    waits for Learner to finish, then periodically probes
                "quiet" IPs.

--------------------------------------------------
Wed Mar 23 17:45:17 CET 2011

* DONE: speed improvements:

    MAC and IP addresses already come in as hex strings.
    We currently use "hex2ip" and "hex2mac" to convert them
    before storing them in the relevant hashes.

    Why not keep them in hex form and convert to proper strings
    when needed?

    Also, using hex form only, there's a smart algorithm
    for checking whether an IP address is in a network, which
    dramatically cuts down on the packet handling loop.

#!/usr/bin/perl

use M6::ARP::Util qw( :all );
use Benchmark qw( cmpthese );
use Net::IPv4Addr qw( :all );                                             

my $ip   = '193.194.136.192';
my $net  = '193.194.136.128';
my $mask = '255.255.255.128';
my $len  = 25;

if (1) {
    my $hexip  = ip2hex($ip);
    my $hexnet = ip2hex($net);
    cmpthese($count, {
        'ipv4_in_network' =>
            sub {
                my $bool = ipv4_in_network($net, $mask, $ip);
            },
        'addr_in_net' =>
            sub {
                my $bool = addr_in_net(ip2hex($ip), ip2hex($net), $len)
            },
        'addr_in_net2' =>
            sub {
                my $bool = addr_in_net($hexip, $hexnet, $len)
            },
    });
}

sub addr_in_net {
    my ($addr, $net, $len) = @_;

    my $nibbles = int($len / 4);

    if ($nibbles) {
        if (substr($addr, 0, $nibbles) ne substr($net, 0, $nibbles)) {
            return;
        }
    }

    $len = $len % 4;

    return 1 if !$len;

    my $mask = 0xf & ~( 1<<(4-$len) - 1 );
    my $a = hex(substr($addr,$nibbles,1));
    my $n = hex(substr($net,$nibbles,1));
    return ($a & $mask) == $n;
}


--------------------------------------------------
Thu Oct  7 09:16:50 CEST 2010

[Implemented first approach]

    Add flood protection by somehow limiting the significance of
    ARP queries if they all come from the same source.

    Possible approaches:

    * Add src_ip to the queue as well, and when the queue is full, collapse
      entries of the same source if they are timed too closely together (say,
      less than 750ms).

        * Take list:
            [t0, s1], [t1, s2], [t2, s2], [t3, s1], [t4, s2], [t5, s2]

        * Sort by SRC, then TIMESTAMP:
            [t0, s1], [t3, s1], [t1, s2], [t2, s2], [t4, s2], [t5, s2]

        * Reduce closely spaced entries from the same SRC:
            [t0, s1], [t3, s1], [t1, s2], [t4, s2]

        * Sort by TIMESTAMP again:
            [t0, s1], [t1, s2], [t3, s1], [t4, s2]

      Advantage: works even if multiple sources are spamming us with
      ARP queries.

      Disadvantage: more state to keep, more processing when queue is
      full

    * Add "last_src" to Queue. An ARP is only added if the source
      does not match last_src, OR the difference in timestamps is
      > 750ms.

      Advantage:    less state to keep, less processing when queue is full
      Disadvantage: multiple flooding sources can still cause sponging,
                    extra overhead for adding _each_ entry to the queue.
