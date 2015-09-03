#===============================================================================
#       Module:  M6_ARPSponge_Queue_Test.pm
#
#  Description:  Test class for M6::ARPSponge::Queue
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#
#   Copyright (c) 2015 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6_ARPSponge_Queue_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;
use Data::Dumper;

use Time::HiRes;
use M6::ARPSponge::Queue;
use M6::ARPSponge::Util qw(:all);

my $DEPTH = 5;

sub startup : Test(startup => 2) {
    my $self = shift;
    use_ok( 'M6::ARPSponge::Queue' );
    my $queue = M6::ARPSponge::Queue->new( max_depth => $DEPTH);
    ok(defined $queue, 'constructor');
    $self->{'queue'} = $queue;
}


sub test_methods : Test(1) {
    my $q = shift->{'queue'};
    my @methods = qw(
        max_depth
        clear_all
        clear
        depth
        rate
        is_full
        add
        get_entry
        get_timestamp
        get_queue
        reduce
    );
    can_ok( $q, @methods);
}


sub test_max_depth : Test(1) {
    my $q = shift->{'queue'};
    is($q->max_depth, 5, 'max_depth');
}


sub test_is_full : Test(2) {
    my $q = shift->{'queue'};
    my $ip = ip2hex('10.0.0.1');
    $q->clear($ip);
    ok(!$q->is_full($ip), 'is_full false after clear');

    for my $i (1..$DEPTH) {
        $q->add($ip, $ip, time);
    }

    ok($q->is_full($ip), "is_full true after $DEPTH x add()");
}


sub test_clear_all : Test(3) {
    my $q = shift->{'queue'};
    my $t = $q->_table;

    $q->clear_all();
    is(int(keys %$t), 0, 'clear_all -> empty _table');

    $q->add(ip2hex('10.0.0.2'), ip2hex('10.0.0.1'), time);
    $q->add(ip2hex('10.0.0.3'), ip2hex('10.0.0.1'), time);
    is(int(keys %$t), 2, '2 x add -> 2 entries in table');

    $q->clear_all();
    is(int(keys %$t), 0, 'clear_all -> empty _table');
}


sub test_timestamp : Test(2) {
    my $q = shift->{'queue'};
    my $ip = ip2hex('10.0.0.1');

    my $t;
    for my $i (1..$DEPTH) {
        $t = time;
        $q->add($ip, $ip, $t);
    }

    my $got = $q->get_timestamp($ip);
    is($got, $t, "get_timestamp returns last timestamp");

    $q->clear($ip);
    ok(!defined($q->get_timestamp($ip)), "timestamp for unknown IP returns undef");
}


sub test_get_queue : Test(2) {
    my $q = shift->{'queue'};
    my $ip = ip2hex('10.0.0.1');

    $q->clear($ip);
    ok(!defined($q->get_queue($ip)), "get_queue on unknown IP returns undef");

    $q->add($ip, $ip, time);
    $q->add($ip, $ip, time);
    $q->add($ip, $ip, time);

    isa_ok($q->get_queue($ip), 'ARRAY', 'get_queue on existing IP returns ARRAY ref');
}


sub test_get_entry : Test(6) {
    my $q = shift->{'queue'};
    my $int = ip2int('10.0.0.0');
    my $ip0 = int2ip($int);
    my $ip1 = int2ip($int+1);
    my $ip2 = int2ip($int+2);
    my $ip3 = int2ip($int+3);

    $q->clear($ip0);

    my ($t1, $t2, $t3) = (time-2, time-1, time);

    $q->add($ip0, $ip1, $t1);
    $q->add($ip0, $ip2, $t2);
    $q->add($ip0, $ip3, $t3);

    my $t = $q->get_queue($ip0);
    is(@$t, 3, 'queue size for $ip is 3');
    #print STDERR Dumper($t);

    my $e = $q->get_entry($ip0);
    my $e_0 = $q->get_entry($ip0, 0);
    is_deeply($e, $e_0, 'get_entry($ip) == get_entry($ip, 0)');
    is($$e[0], $ip1, 'get_entry($ip) -> $ip1');

    my $e_min_1 = $q->get_entry($ip0, -1);
    my $e_2 = $q->get_entry($ip0, 2);
    is_deeply($e_min_1, $e_2, 'get_entry($ip, -1) == get_entry($ip, $last_index)');
    is($$e_min_1[0], $ip3, 'get_entry($ip, -1) -> $ip3');

    my $e_min_6 = $q->get_entry($ip0, -6);
    is_deeply($e_min_6, $e, 'get_entry($ip, -6) == get_entry($ip)');
}


sub test_rate : Test(4) {
    my $q = shift->{'queue'};
    my $int = ip2int('10.0.0.0');
    my $ip0 = int2ip($int);
    my $ip1 = int2ip($int+1);
    my $ip2 = int2ip($int+2);
    my $ip3 = int2ip($int+3);
    my $ip4 = int2ip($int+4);
    my $ip5 = int2ip($int+5);

    my $t0 = int(time);
    my ($t1, $t2, $t3, $t4) = ($t0-1.5, $t0-1, $t0-0.5, $t0);

    $q->clear($ip0);

    my $r = $q->rate($ip0);
    ok(!defined($r), 'rate() on unknown ip returns undef');

    $q->add($ip0, $ip1, $t1);

    $r = $q->rate($ip0);
    ok(!defined($r), 'rate() on ip with queuelen < 2 returns undef');

    $q->add($ip0, $ip2, $t2);
    $q->add($ip0, $ip3, $t3);
    $q->add($ip0, $ip4, $t4);

    $r = $q->rate($ip0);
    is($r, (3/($t4-$t1))*60, 'rate() on three probes with 1-second spacing');

  # Bad timestamp...
    $q->add($ip0, $ip5, $t1-1);
    $r = $q->rate($ip0);
    is($r, (4/1)*60, 'rate() on four probes with out-of-sequence timestamps');
}

sub test_reduce : Test(8) {
    my $q = shift->{'queue'};
    my $int = ip2int('10.0.0.0');
    my $ip0 = int2ip($int);
    my $ip1 = int2ip($int+1);

    my $t0 = int(time);
    my ($t1, $t2, $t3, $t4, $t5) = ($t0-2, $t0-1.5, $t0-1, $t0-0.5, $t0);

    $q->clear($ip0);

    my $s = $q->reduce($ip0, 0);
    is($s, 0, 'reduce() on a non-existing IP returns 0');

    $q->add($ip0, $ip1, $t1);
    $q->add($ip0, $ip1, $t2);
    $q->add($ip0, $ip1, $t3);
    $q->add($ip0, $ip1, $t4);
    $q->add($ip0, $ip1, $t5);

    $s = $q->reduce($ip0, -1);
    is($s, 5, 'reduce() with a non-positive rate does nothing');

    $s = $q->reduce($ip0, 10);
    is($s, 5, 'reduce() with a high rate does nothing');

    $s = $q->reduce($ip0, 1);
    is($s, 1, 'reduce() with a low rate reduces');

    $q->clear($ip0);
    $q->add($ip0, $ip1, $t1); # 1: First.
    $q->add($ip0, $ip1, $t2); # 2: Second, high rate.            --> toss #1
    $q->add($ip0, $ip1, $t2); # 3: Duplicate of second.          <-- toss #2
    $q->add($ip0, $ip0, $t3); # 4: Different source IP.          --> keep #4
    $q->add($ip0, $ip1, $t4); # 5: Another entry, slow enough.   --> keep #3
    $q->add($ip0, $ip1, $t5); # 6: Another entry, too fast.      --> toss #5
                              # --> keep #6

    $s = $q->reduce($ip0, 1);
    is($s, 3, 'reduce() only works on consecutive source IP entries');

    is($q->get_timestamp($ip0, 0), $t2, 'after reduce() first entry is $t2');
    is($q->get_timestamp($ip0, 1), $t3, 'after reduce() second entry is $t3');
    is($q->get_timestamp($ip0, 2), $t5, 'after reduce() third entry is $t5');
}

1;
