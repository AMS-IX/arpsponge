# Test M6::ARP::Queue with flood protection.
#

use strict;
use M6::ARP::Queue;
use Time::HiRes qw( usleep time );
use POSIX qw( strftime );

my $print_table  = 0;
my $some_ip      = '10.1.1.1';
#my @src_ip      = ('10.1.1.2', '10.1.1.3', '10.1.1.4');
my @src_ip       = ((map { '10.1.1.2' } (1..10000)), '10.1.1.3', '10.1.1.4');
my $max_src_rate =  5;
my $max_q_rate   = 70;

my $q = new M6::ARP::Queue(100);

printf("Filling queue for $some_ip (max %d)\n", $q->max_depth);

$q->clear($some_ip);

my $n = 0;
for my $n (0..100) {
    $n++;
    printf("--- %3d ----------------------\n", $n);
    $q->add($some_ip, $src_ip[int rand(int @src_ip)], time);
    usleep(rand(5e5));
    while (!$q->is_full($some_ip)) {
        my $src_ip = $src_ip[int rand(int @src_ip)];
        $q->add($some_ip, $src_ip[0], time);
        print STDERR sprintf("\rdepth: %3d", $q->depth($some_ip));
        usleep(rand(10_000));
    }
    print "\rBefore reduce:\n";
            printf(" depth: %3d\n", $q->depth($some_ip));
    print strftime(" first: %H:%M:%S\n",
                    localtime($q->get_timestamp($some_ip, 0)));
    print strftime(" last:  %H:%M:%S\n",
                    localtime($q->get_timestamp($some_ip, -1)));
            printf(" rate:  %0.2f queries/minute\n", $q->rate($some_ip));

    if ($print_table) {
        $" = ",";
        foreach my $entry (@{$q->get_queue($some_ip)}) {
            print qq{[@$entry]\n};
        }
    }

    $q->reduce($some_ip, $max_src_rate);
    print "\nAfter reduce:\n";
            printf(" depth: %3d\n", $q->depth($some_ip));
    print strftime(" first: %H:%M:%S\n",
                    localtime($q->get_timestamp($some_ip, 0)));
    print strftime(" last:  %H:%M:%S\n",
                    localtime($q->get_timestamp($some_ip, -1)));
            printf(" rate:  %0.2f queries/minute\n", $q->rate($some_ip));

    if ($print_table) {
        foreach my $entry (@{$q->get_queue($some_ip)}) {
            print qq{[@$entry]\n};
        }
    }

    if ($q->is_full($some_ip) && $q->rate($some_ip) > $max_q_rate) {
        print "\n*** Done\n\n";
        last;
    }
}
