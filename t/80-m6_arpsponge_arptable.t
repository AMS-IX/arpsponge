#!perl

use 5.014;
use warnings;

use Test2::V0;
use M6::ArpSponge::ArpTable;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::Util qw( ip2hex mac2hex );

my $table = M6::ArpSponge::ArpTable->new();
ok $table, "constructor is working.";

{
    my @methods = qw(
        add
        clear_ip
        clear_mac
        ip_list
        lookup_ip
        lookup_mac
        mac_list
        purge

    );
    can_ok $table, @methods;
}

# Initialise test data.
my %ip_mac_map = (
    '198.51.100.1' => undef
);

my %mac_ip_map = (
    '0e:1d:ed:41:f4:de' => [ '198.51.100.2' ],
    '46:ae:c8:e3:13:91' => [ '198.51.100.4' ],
    'd6:35:c0:8f:ee:9c' => [ '198.51.100.23', '198.51.100.129' ],
    '26:5d:56:09:60:88' => [ '198.51.100.210', '198.51.100.211', '198.51.100.241' ],
    'a6:44:73:31:14:0a' => [ '198.51.100.169' ],
    '82:09:20:90:ab:2c' => [ '198.51.100.155' ],
    'ae:b1:3e:14:9a:60' => [ '198.51.100.152' ],
    'da:f1:aa:36:86:58' => [ '198.51.100.47' ],
    '0a:d4:88:35:38:c0' => [ '198.51.100.33' ],
    'be:8d:77:e7:f1:f6' => [ '198.51.100.30' ],
    'ca:a3:0b:4c:f4:6d' => [],
);

while (my ($mac, $ip_list) = each %mac_ip_map) {
    for my $ip (@{$ip_list}) {
        $ip_mac_map{$ip} = $mac;
    }
}

# Fill.
my $tstamp = 0;

for my $ip (sort keys %ip_mac_map) {
    my $ip_h = ip2hex($ip);
    my $mac = $ip_mac_map{$ip};
    my $mac_h = mac2hex($mac);
    ++$tstamp if defined $mac_h;
    $table->add($ip_h, $mac_h, $tstamp);
}

TEST_LOOKUP_IP : {
    for my $ip (sort keys %ip_mac_map) {
        my $expected_mac = $ip_mac_map{$ip};
        my $iphex = ip2hex($ip);
        my $hexmac1 = $table->lookup_ip($iphex);
        my ($hexmac2, $tstamp) = $table->lookup_ip($iphex);
        my $expected_hex = $expected_mac ? mac2hex($expected_mac) : undef;
        my $expected_str = $expected_hex ? qq{'$expected_hex'} : qq{undef};
        is $hexmac2, $expected_hex, "lookup_ip('$iphex') returns $expected_str";
        if (defined $expected_mac) {
            cmp_ok $tstamp, '>', 0, "lookup_ip('$iphex') returns positive timestamp";
        }
        else {
            is $tstamp, undef, "lookup_ip('$iphex') returns undefined timestamp";
        }
    }
}

TEST_LOOKUP_MAC : {
    for my $mac (sort keys %mac_ip_map) {
        my $ip_list = $mac_ip_map{$mac};
        my $mac_h = mac2hex($mac);
        my @expected = sort { $a cmp $b } map { ip2hex($_) } @{$ip_list};
        my @got = sort { $a cmp $b } $table->lookup_mac($mac_h);
        is \@got, \@expected,
            "lookup_mac('$mac_h') returns (@expected)";
    }
}

TEST_PURGE : {
    my @ip_list1 = $table->ip_list();
    my @mac_list1 = $table->mac_list();

    is int(@ip_list1), $tstamp, "table has $tstamp IP entries";

    my $cutoff = int($tstamp / 2);
    my $expected_purged = $cutoff - 1;
    my $purged = $table->purge($cutoff);
    is $purged, $expected_purged, "purge($cutoff) => purged $expected_purged IP entries";

    my @ip_list2 = $table->ip_list();
    my $expected_left = $tstamp - $expected_purged;
    is int(@ip_list2), $expected_left, "purge($cutoff) => $expected_left IP entries left";

    my @mac_list2 = $table->mac_list();

    cmp_ok int(@mac_list2),'<',int(@mac_list1),
        "purge reduces the mac_list()";

    $expected_purged = $expected_left;
    $expected_left = 0;
    $purged = $table->purge();
    is $purged, $expected_purged, "purge() => purged $expected_purged IP entries";
    my @ip_list3 = $table->ip_list();
    is int(@ip_list3), $expected_left, "purge() => $expected_left IP entries left";

    my @mac_list3 = $table->mac_list();
    is int(@mac_list3), 0, "purge() => 0 MAC entries left";
}

TEST_CLEAR_IP : {
    $table->purge();
    
    my $mac = 'd6:35:c0:8f:ee:9c';
    my $ip1 = '198.51.100.1';
    my $ip2 = '198.51.100.2';

    my $ip1_h = ip2hex($ip1);
    my $ip2_h = ip2hex($ip2);
    my $mac_h = mac2hex($mac);

    $table->add($ip1_h, $mac_h);
    $table->add($ip2_h, $mac_h);

    my @ip_list = $table->ip_list;
    is int(@ip_list), 2, "add(IP1, MAC) + add(IP2, MAC) => ip_list has 2 entries";
    my @mac_list = $table->mac_list;
    is int(@mac_list), 1, "add(IP1, MAC) + add(IP2, MAC) => mac_list has 1 entry";

    $table->clear_ip($ip1_h);
    @ip_list = $table->ip_list;
    is int(@ip_list), 1, "clear_ip(IP1) => ip_list has 1 entry";
    @mac_list = $table->mac_list;
    is int(@mac_list), 1, "clear_ip(IP1) => mac_list has 1 entry";

    $table->clear_ip($ip2_h);
    @ip_list = $table->ip_list;
    is int(@ip_list), 0, "clear_ip(IP2) => ip_list has 0 entries";
    @mac_list = $table->mac_list;
    is int(@mac_list), 0, "clear_ip(IP2) => mac_list has 0 entries";

    $table->purge();
    $table->add($ip1_h, $mac_h);
    $table->add($ip2_h, $mac_h);

    @ip_list = $table->ip_list;
    is int(@ip_list), 2, "add(IP1, MAC) + add(IP2, MAC) => ip_list has 2 entries";
    @mac_list = $table->mac_list;
    is int(@mac_list), 1, "add(IP1, MAC) + add(IP2, MAC) => mac_list has 1 entry";

    $table->clear_mac($mac_h);
    @ip_list = $table->ip_list;
    is int(@ip_list), 0, "clear_mac(MAC) => ip_list has 0 entries";
    @mac_list = $table->mac_list;
    is int(@mac_list), 0, "clear_mac(MAC) => mac_list has 0 entries";
}

done_testing();
