#perl -T

use 5.014;
use warnings;

use Test2::V0;

use Time::HiRes qw( time );
use M6::ArpSponge::Queue;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Util qw( ip2hex );

my $dst_ip = ip2hex('10.1.1.1');
my @src_ip = (
    ip2hex('10.1.1.2'),
    ip2hex('10.1.1.3'),
    ip2hex('10.1.1.4'),
    ip2hex('10.1.1.5'),
);

my $queue = M6::ArpSponge::Queue->new();
ok $queue, "constructor is working.";
is $queue->max_depth, M6::ArpSponge::Defaults->QUEUE_DEPTH,
    "default queue depth set ok.";

my $MAX_DEPTH = 50;
$queue = M6::ArpSponge::Queue->new( max_depth => $MAX_DEPTH );
is $queue->max_depth, $MAX_DEPTH,
    "queue depth set to $MAX_DEPTH at construction.";

$MAX_DEPTH = 100;
$queue->max_depth($MAX_DEPTH);
is $queue->max_depth, $MAX_DEPTH,
    "max_depth(100) set correctly.";

my $d = $queue->depth($dst_ip);
is $d, 0, "initial depth for $dst_ip is 0.";

my $t0                     = time - 24*3600;
my $expected_depth         = 0;
my $per_ip_rate            = 0;
my $gap                    = 0.1;
my $ip_repeat              = 25;
my $per_ip_rate            = 1.0 / $gap;
my $max_rate               = $per_ip_rate * 0.9;
my $expected_reduced_depth = int(@src_ip);

for my $src_ip (@src_ip) {
    for my $n (1..$ip_repeat) {
        $queue->add($dst_ip, $src_ip, $t0);
        $t0 += $gap;
        $expected_depth++;
    }
}

$d = $queue->depth($dst_ip);
is $d, $expected_depth, "depth for $dst_ip is $expected_depth.";

$queue->reduce($dst_ip, $per_ip_rate - 0.1);
my $d2 = $queue->depth($dst_ip);
is $d2, $expected_reduced_depth, "depth for $dst_ip is $d2 after recduction.";
ok $d2 < $d, "depth for $dst_ip is reduced from $d to $d2.";

done_testing;
