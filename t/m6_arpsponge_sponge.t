#perl -T

use 5.014;
use warnings;

use Test::More;

use M6::ArpSponge::Sponge;
use M6::ArpSponge::NetPacket qw( :const );
use M6::ArpSponge::Util qw( ip2hex hex2ip hex2mac );

my $dev = 'lo';
my $lo_ip_s = '127.0.0.1';
my $lo_ip_h = ip2hex($lo_ip_s);
my $lo_mac_h = ETH_ADDR_NONE;
my $lo_mac_s = hex2mac($lo_mac_h);

my $net_addr = NetAddr::IP->new('192.168.1.0/24');
my $prefixlen = $net_addr->masklen;
my $network_s = $net_addr->addr;
my $broadcast_s = $net_addr->broadcast->addr;
my $network_h = ip2hex($network_s);
my $broadcast_h = ip2hex($broadcast_s);

my $sponge = M6::ArpSponge::Sponge->new(
    device    => $dev,
    network   => $network_h,
    prefixlen => $prefixlen,
);

subtest 'IP/MAC settings' => sub {
    is $sponge->my_ip_s, $lo_ip_s,
        "sponge on $dev binds to IP $lo_ip_s";

    is $sponge->my_ip, $lo_ip_h,
        "sponge on $dev binds to hex IP $lo_ip_h";

    is $sponge->my_mac_s, $lo_mac_s,
        "sponge on $dev binds to MAC $lo_mac_s";

    is $sponge->my_mac_s, $lo_mac_s,
        "sponge on $dev binds to hex MAC $lo_mac_s";

    my @ip_all = $sponge->get_ip_all;

    ok @ip_all >= 1,
        "sponge's 'ip-all' returns at least one IP address";

    my @lo_match = grep { $_ eq $lo_ip_h } @ip_all;

    ok @lo_match > 0,
        "sponge's 'ip-all' includes '$lo_ip_h'";

    is $sponge->network_s, $network_s,
        "sponge's network_s is '$network_s'";

    is $sponge->broadcast_s, $broadcast_s,
        "sponge's broadcast_s is '$broadcast_s'";

    my $lo_i = $net_addr->first->numeric;
    my $hi_i = $net_addr->last->numeric;

    is $sponge->network_lo_i, $lo_i,
        "first IP address is $lo_i decimal";

    is $sponge->network_hi_i, $hi_i,
        "last IP address is $hi_i decimal";
};

done_testing;
