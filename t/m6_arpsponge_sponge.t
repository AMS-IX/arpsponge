#perl

use 5.014;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";

use Test::More;

use Scalar::Util qw( reftype );
use List::Util   qw( first );

use Test::Mock::Net::Pcap;
use Test::Mock::Sys::Syslog;

my ($mock_syslog, $mock_pcap);

BEGIN {
    my $mock_syslog = Test::Mock::Sys::Syslog->new();
    my $mock_pcap = Test::Mock::Net::Pcap->new();
}

use Net::Pcap;
use M6::ArpSponge::Log qw( :func );
use M6::ArpSponge::Sponge;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::State qw( :const );
use M6::ArpSponge::UpdateFlags qw( :const );
use M6::ArpSponge::NetPacket qw( :const );
use M6::ArpSponge::Util qw( :all );

my $net_addr    = NetAddr::IP->new('198.51.100.0/24');
my $prefixlen   = $net_addr->masklen;
my $network_s   = $net_addr->addr;
my $broadcast_s = $net_addr->broadcast->addr;
my $network_h   = ip2hex($network_s);
my $broadcast_h = ip2hex($broadcast_s);

my %interface;
{
    my $ifconfig = read_from_pipe(M6::ArpSponge::Defaults->IFCONFIG);
    while ($ifconfig =~ m{^ (?<ifname>\S+): \h (?<ifblock>.*?) \n (?=\S|\Z)}xgms) {
        my ($ifname, $ifblock) = @+{qw( ifname ifblock )};
        if ($ifblock =~ m{ inet \h+ (?<inet>[\d\.]+) }x) {
            my $ip_s = $+{inet};
            my $mac_s = hex2mac(ETH_ADDR_NONE);
            if ($ifblock =~ m{ ether \h+ (?<ether>[A-Fa-f\d:]+) }x) {
                $mac_s = $+{ether};
            }
            $interface{$ifname} = {
                ip_s  => hex2ip(ip2hex($ip_s)),
                ip_h  => ip2hex($ip_s),
                mac_s => mac2mac($mac_s),
                mac_h => mac2hex($mac_s),
            };
        }
    }
}

my $dev = first { $interface{$_}{mac_h} ne ETH_ADDR_NONE }
            sort keys %interface;

if (!$dev) {
    if (exists $interface{lo}) {
        $dev = 'lo';
    }
    else {
        fail("determine network interface");
        BAIL_OUT("no valid network interface found on the system");
    }
}

pass("determine network interface");

my $dev_ip_s     = $interface{$dev}{ip_s};
my $dev_ip_h     = $interface{$dev}{ip_h};
my $dev_mac_h    = $interface{$dev}{mac_h};
my $dev_mac_s    = $interface{$dev}{mac_s};

my $sponge = M6::ArpSponge::Sponge->new(
    device    => $dev,
    network   => $network_h,
    prefixlen => $prefixlen,
);

subtest 'IP/MAC settings' => sub {
    is $sponge->my_ip_s, $dev_ip_s,
        "sponge on $dev binds to IP $dev_ip_s";

    is $sponge->my_ip, $dev_ip_h,
        "sponge on $dev binds to hex IP $dev_ip_h";

    is $sponge->my_mac_s, $dev_mac_s,
        "sponge on $dev binds to MAC $dev_mac_s";

    is $sponge->my_mac_s, $dev_mac_s,
        "sponge on $dev binds to hex MAC $dev_mac_s";

    my @ip_all = $sponge->get_ip_all;

    ok @ip_all >= 1,
        "sponge's 'ip-all' returns at least one IP address";

    for my $ip_h (@ip_all) {
        ok $sponge->is_my_ip($ip_h),
            "is_my_ip('$ip_h') is true";

        my $ip_s = hex2ip($ip_h);

        ok $sponge->is_my_ip_s($ip_s),
            "is_my_ip('$ip_s') is true";
    }

    for my $ifname (sort keys %interface) {
        my $mac_h = $interface{$ifname}{mac_h};
        is $sponge->get_mac($ifname), $mac_h,
            "get_mac('$ifname') returns '$mac_h'";
    }

    ok !$sponge->is_my_ip_s('0.0.0.0'),
            "is_my_ip('0.0.0.0') is false";

    my @lo_match = grep { $_ eq $dev_ip_h } @ip_all;

    ok @lo_match > 0,
        "sponge's 'ip-all' includes '$dev_ip_h'";

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

    my $lo_ip_s = int2ip($lo_i);
    my $hi_ip_s = int2ip($hi_i);
    my $outside_ip_s = int2ip($hi_i+2);

    ok $sponge->is_my_network_s($lo_ip_s),
        "is_my_network_s('$lo_ip_s') is true";
    ok $sponge->is_my_network_s($hi_ip_s),
        "is_my_network_s('$hi_ip_s') is true";
    ok !$sponge->is_my_network_s($outside_ip_s),
        "is_my_network_s('$outside_ip_s') is false";

};

subtest 'default settings' => sub {
    my $expected;

    $expected = M6::ArpSponge::Defaults->MAX_ARP_AGE;
    is $sponge->arp_age, $expected,
        "arp_age is $expected";

    $expected = M6::ArpSponge::Defaults->FLOOD_PROTECTION;
    is $sponge->flood_protection, $expected,
        "flood_protection is $expected";

    $expected = M6::ArpSponge::Defaults->MAX_PENDING;
    is $sponge->max_pending, $expected,
        "max_pending is $expected";

    $expected = M6::ArpSponge::Defaults->MAX_ARP_RATE;
    is $sponge->max_rate, $expected,
        "max_rate is $expected";

    $expected = M6::ArpSponge::Defaults->MAX_ARP_RATE;
    is $sponge->max_rate, $expected,
        "max_rate is $expected";

    $expected = ARP_UPDATE_ALL;
    is $sponge->arp_update_flags, $expected,
        "arp_update_flags is $expected";

    ok !$sponge->is_dummy,   "is_dummy is false";
    ok !$sponge->gratuitous, "gratuitous is false";
    ok !$sponge->sponge_net, "sponge_net is false";
};

subtest 'attributes' => sub {
    my %attr1 = (
        foo => 'FOO',
        bar => 'BAR',
        baz => 'BAZ',
    );
    $sponge->set_attr(%attr1);

    for my $k (sort keys %attr1) {
        my $v = $attr1{$k};
        is $sponge->get_attr($k), $v,
        "get_attr('$k') returns '$v'";
    }

    $sponge->del_attr('foo');
    is $sponge->get_attr('foo'), undef,
        "get_attr('foo') returns undef after del_attr";

    $sponge->clear_attr();
    for my $k (sort keys %attr1) {
        is $sponge->get_attr($k), undef,
        "get_attr('$k') returns undef after clear_attr()";
    }
};

subtest 'state_name' => sub {
    my %state = (
        'DEAD'       => DEAD(),
        'ALIVE'      => ALIVE(),
        'PENDING(1)' => PENDING(1),
        'NONE'       => NONE
    );
    for my $state_name (sort keys %state) {
        my $state = $state{$state_name};
        is $sponge->state_name($state), $state_name,
            "state_name($state) returns '$state_name'";
    }
};

subtest 'state_change' => sub {

    my $err;
    init_log();
    my $pcap_h = pcap_open_live($dev, 64*1024, 1, 0, \$err);

    my $sponge = M6::ArpSponge::Sponge->new(
        device      => $dev,
        network     => $network_h,
        prefixlen   => $prefixlen,
        sponge_net  => 1,
        init_state  => ALIVE,
        gratuitous  => 1,
        pcap_handle => $pcap_h,
    );

    my $lo_s = $net_addr->first;
    my $hi_s = $net_addr->last;
    my $lo_h = ip2hex($lo_s->addr);
    my $hi_h = ip2hex($hi_s->addr);

    $sponge->set_alive($lo_h);
    is $sponge->get_state($lo_h), ALIVE,
        "get_state('$lo_h') is ALIVE after set_alive('$lo_h')";

    $sponge->set_pending($lo_h, 0);
    is $sponge->get_state($lo_h), PENDING(0),
        "get_state('$lo_h') is PENDING(0) after set_pending('$lo_h', 0)";

    $sponge->incr_pending($lo_h);
    is $sponge->get_state($lo_h), PENDING(1),
        "get_state('$lo_h') is PENDING(1) after incr_pending('$lo_h')";

    $sponge->set_dead($lo_h);
    is $sponge->get_state($lo_h), DEAD,
        "get_state('$lo_h') is DEAD after set_dead('$lo_h')";

    $sponge->set_alive($lo_h);
    is $sponge->get_state($lo_h), ALIVE,
        "get_state('$lo_h') is ALIVE after set_alive('$lo_h')";
};

done_testing;
