#perl -T

use 5.014;
use warnings;

use Test2::V0;

use Time::HiRes qw( time );
use M6::ArpSponge::Queue;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Util qw( ip2hex );

my $dst_ip = '10.1.1.1';
my $dst_hex = ip2hex($dst_ip);
diag "dst_ip '$dst_ip' -> '$dst_hex'";

my @src_ip = qw( 10.1.1.2 10.1.1.3 10.1.1.4 10.1.1.5 10.1.1.6 );
my @src_hex;
for my $s (@src_ip) {
    my $h = ip2hex($s);
    push @src_hex, $h;
    diag "src_ip '$s' -> '$h'";
}

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

my $d = $queue->depth($dst_hex);
is $d, 0, "initial depth for $dst_hex is 0.";

my $t0                     = time - 24*3600;
my $expected_depth         = $MAX_DEPTH;
my $gap                    = 0.1;
my $ip_repeat              = 25;
my $per_ip_rate            = 1.0 / $gap;
my $max_rate               = $per_ip_rate * 0.9;
my $expected_reduced_depth = int($expected_depth / $ip_repeat);

my $inserts = 0;
for my $src_hex (@src_hex) {
    for my $n (1..$ip_repeat) {
        $queue->add($dst_hex, $src_hex, $t0);
        $t0 += $gap;
        $inserts++;
    }
}
diag "added $inserts events to the queue for $dst_hex";
$d = $queue->depth($dst_hex);
is $d, $expected_depth, "depth for $dst_hex is $expected_depth.";

$queue->reduce($dst_hex, $per_ip_rate - 0.1);
my $d2 = $queue->depth($dst_hex);
is $d2, $expected_reduced_depth, "depth for $dst_hex is $expected_reduced_depth after reduction.";
ok $d2 < $d, "depth for $dst_hex is reduced from $d to $d2.";

done_testing;
