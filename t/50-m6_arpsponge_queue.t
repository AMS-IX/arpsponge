#!perl

use 5.014;
use warnings;

use Test2::V0;
use M6::ArpSponge::Queue;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Util qw( ip2hex ip2int int2ip );

my $queue = M6::ArpSponge::Queue->new();
ok $queue, "constructor is working.";
is $queue->max_depth, M6::ArpSponge::Defaults->QUEUE_DEPTH,
    "default queue depth set ok.";

my $MAX_DEPTH = 50;
$queue = M6::ArpSponge::Queue->new( max_depth => $MAX_DEPTH );
is $queue->max_depth, $MAX_DEPTH,
    "queue depth set to $MAX_DEPTH at construction.";

$MAX_DEPTH = 5;
$queue->max_depth($MAX_DEPTH);
is $queue->max_depth, $MAX_DEPTH,
    "max_depth($MAX_DEPTH) set correctly.";

{
    my @methods = qw(
        max_depth
        clear_all
        clear
        depth
        rate
        is_full
        add
        get_timestamp
        get_queue
        reduce
    );
    can_ok $queue, @methods;
}

my $dst_ip = '10.1.1.1';
my $dst_hex = ip2hex($dst_ip);

my @src_ip = qw( 10.1.1.2 10.1.1.3 10.1.1.4 10.1.1.5 10.1.1.6 );
my @src_hex;
for my $s (@src_ip) {
    my $h = ip2hex($s);
    push @src_hex, $h;
}

# Test queue fullness.

TEST_QUEUE_FULL : {
    $queue->clear($dst_hex);
    is $queue->depth($dst_hex), 0, "depth($dst_hex) is 0 after clear()";
    ok !$queue->is_full($dst_hex), "is_full($dst_hex) is false after clear()";

    for my $i (1..$MAX_DEPTH) {
            $queue->add($dst_hex, $src_hex[0], time);
    }

    ok $queue->is_full($dst_hex),
        "is_full($dst_hex) is true after ${MAX_DEPTH} x add()";
}

TEST_CLEAR_ALL : {
    my $q = $queue;
    my $t = $q->_table;

    $q->clear_all();
    is(int(keys %$t), 0, 'clear_all -> empty _table');

    $q->add($src_hex[0], $dst_hex, time);
    $q->add($src_hex[1], $dst_hex, time);
    is(int(keys %$t), 2, '2 x add -> 2 entries in table');

    $q->clear_all();
    is(int(keys %$t), 0, 'clear_all -> empty _table');
}

TEST_ADD_GET : {
    my $q = $queue;
    my $ip = $dst_hex;

    my ($first_t, $last_t);
    my $t = 0;
    for my $i (1..$MAX_DEPTH) {
        $q->add($ip, $ip, $t);
        $first_t //= $t;
        $last_t = $t;
        $t++;
    }

    my $got;

    $got = $q->get_timestamp($ip);
    is $got, $first_t, "get_timestamp('$ip') returns first timestamp ($first_t)";

    $got = $q->get_timestamp($ip, -1);
    is $got, $last_t, "get_timestamp('$ip', -1) returns last timestamp ($last_t)";

    $q->clear($ip);
    ok(!defined($q->get_timestamp($ip)), "timestamp for unknown IP returns undef");
}

TEST_GET_QUEUE : {
    my $q = $queue;
    my $ip = $dst_hex;

    $q->clear($ip);
    ok(!defined($q->get_queue($ip)), "get_queue on unknown IP returns undef");

    $q->add($ip, $ip, 0);
    $q->add($ip, $ip, 0);
    $q->add($ip, $ip, 0);

    my $ip_q = $q->get_queue($ip);
    ok defined($ip_q), "get_queue() on existing IP returns defined value";
    ref_ok $ip_q, 'ARRAY', 'get_queue on existing IP returns ARRAY ref';
}

TEST_RATE : {
    my $q = $queue;
    my $int = ip2int($dst_ip);
    my $ip0 = ip2hex(int2ip($int));
    my $ip1 = ip2hex(int2ip($int+1));
    my $ip2 = ip2hex(int2ip($int+2));
    my $ip3 = ip2hex(int2ip($int+3));
    my $ip4 = ip2hex(int2ip($int+4));
    my $ip5 = ip2hex(int2ip($int+5));

    my ($t1, $t2, $t3, $t4) = (0, 1, 2, 3);

    $q->clear($ip0);

    my $r = $q->rate($ip0);
    ok(!defined($r), 'rate() on unknown ip returns undef');

    $q->add($ip0, $ip1, $t1);

    $r = $q->rate($ip0);
    ok(!defined($r), 'rate() on ip with queuelen < 2 returns undef');

    $q->add($ip0, $ip2, $t2);
    $q->add($ip0, $ip3, $t3);
    $q->add($ip0, $ip4, $t4);

    my $depth         = $q->depth($ip0); 
    is $depth, 4, 'depth() after 4 probes is 4';

    $r = $q->rate($ip0);
    my $expected_rate = ((4-1)/3) * 60;
    is $r, $expected_rate,
        "rate() on 4 probes with 1-second spacing = $expected_rate";

  # Bad timestamp...
    $q->add($ip0, $ip5, $t1);
    $r = $q->rate($ip0);
    $expected_rate = ((5-1)/1) * 60;
    is $r, $expected_rate,
        "rate() on 5 probes with 0 interval = $expected_rate";

  # Bad timestamp...
    $q->clear($ip0);
    $q->add($ip0, $ip1, $t1);
    $q->add($ip0, $ip2, $t2);
    $q->add($ip0, $ip3, $t3);
    $q->add($ip0, $ip4, $t4);
    $q->add($ip0, $ip5, $t3);

    $r = $q->rate($ip0);
    $expected_rate = ((5-1)/($t3-$t1)) * 60;
    is $r, $expected_rate,
        "rate() on 5 probes with out-of-sequence timestamps = $expected_rate";
}


TEST_REDUCE : {
    my $q = $queue;
    my $ip0 = $dst_hex;
    my $ip1 = $src_hex[0];

    my ($t1, $t2, $t3, $t4, $t5) = (0, 0.5, 1, 1.5, 2);

    $q->clear_all();

    my $s = $q->reduce($ip0, 0);
    is $s, 0, 'reduce() on a non-existing IP returns 0';

    $q->add($ip0, $ip1, $t1);
    $q->add($ip0, $ip1, $t2);
    $q->add($ip0, $ip1, $t3);
    $q->add($ip0, $ip1, $t4);
    $q->add($ip0, $ip1, $t5);

    $s = $q->reduce($ip0, -1);
    is $s, 5, "reduce('$ip0', -1) with a non-positive rate does nothing";

    $s = $q->reduce($ip0, 10);
    is $s, 5, "reduce('$ip0', 10) does nothing";

    $s = $q->reduce($ip0, 1);
    is $s, 1, "reduce('$ip0', 1) with a low rate reduces";

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

    is($q->get_timestamp($ip0, 0), $t2, "after reduce() first entry is $t2");
    is($q->get_timestamp($ip0, 1), $t3, "after reduce() second entry is $t3");
    is($q->get_timestamp($ip0, 2), $t5, "after reduce() third entry is $t5");
}

TEST_REDUCE_2 : {
    my $q = $queue;
    my $ip0 = $dst_hex;
    my $ip1 = $src_hex[0];

    $q->clear_all();
    $q->max_depth(20);

    $q->clear($ip0);

    $q->add($ip0, $ip1, 0.0); # base
    $q->add($ip0, $ip1, 0.1);
    $q->add($ip0, $ip1, 0.2);
    $q->add($ip0, $ip1, 0.3);
    $q->add($ip0, $ip1, 0.4);
    $q->add($ip0, $ip1, 0.5);
                            # > 1 second
    $q->add($ip0, $ip1, 1.5); 
    $q->add($ip0, $ip1, 1.6);
    $q->add($ip0, $ip1, 1.7);
    $q->add($ip0, $ip1, 1.8);
    $q->add($ip0, $ip1, 1.9);
    $q->add($ip0, $ip1, 2.0);
                            # > 1 second
    $q->add($ip0, $ip1, 3.0);

    my $d = $q->depth($ip0);

    my $got = $q->reduce($ip0, 1);
    my $expected = 3;
    is $got, $expected, "reduce('$ip0', 1) reduces from $d to $expected";
}

done_testing();
