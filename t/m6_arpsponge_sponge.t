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
    $mock_syslog = Test::Mock::Sys::Syslog->new();
    $mock_pcap = Test::Mock::Net::Pcap->new();
}

use Net::Pcap;
use M6::ArpSponge::Log qw( :func );
use M6::ArpSponge::Sponge;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::State qw( :const );
use M6::ArpSponge::UpdateFlags qw( :const );
use M6::ArpSponge::NetPacket qw( :const :func );
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

sub check_arp_sent {
    my ($sponge, %expected) = @_;

    my $pcap_h = $sponge->pcap_handle;
    my $sent = $mock_pcap->get_sent($pcap_h);
    is int(@{$sent}), 1, "1 packet sent via Net::Pcap"
        or return;

    my $packet = $sent->[-1];
    my $eth_data = decode_ethernet($packet);

    $expected{src_mac} //= $sponge->my_mac,
    $expected{sha}     //= $expected{src_mac} // $sponge->my_mac;
    $expected{spa}     //= $sponge->my_ip;

    $expected{dst_mac} //= $expected{tha} // ETH_ADDR_BROADCAST;
    $expected{tha}     //= $expected{dst_mac};

    my @expected_eth = (
        [ src_mac  => $expected{src_mac} ],
        [ dest_mac => $expected{dst_mac} ],
    );
    for my $chk (@expected_eth) {
        my ($key, $expected) = @{$chk};
        is $eth_data->{$key}, $expected,
            "Ethernet $key is '$expected'";
    }

    is $eth_data->{type}, ETH_TYPE_ARP, "packet is an ARP packet"
        or return;

    my $arp_data = decode_arp($eth_data->{data});
    my @expected_arp = (
        [ htype  => ARP_HTYPE_ETHERNET ],
        [ proto  => ARP_PROTO_IPV4 ],
        [ hlen   => ARP_HLEN_ETHERNET ],
        [ plen   => ARP_PLEN_IPV4 ],
        [ opcode => $expected{opcode} ],
        [ sha    => $expected{sha} ],
        [ spa    => $expected{spa} ],
        [ tha    => $expected{tha} ],
        [ tpa    => $expected{tpa} ],
        [ data   => undef ],
    );
    for my $chk (@expected_arp) {
        my ($key, $expected) = @{$chk};
        my $exp_str = defined $expected ? "'$expected'" : 'undef';
        is $arp_data->{$key}, $expected,
            "ARP $key is $exp_str";
    }
}

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

    my $lo_s     = $net_addr->first;
    my $lo_h     = ip2hex($lo_s->addr);

    my $static_s = $net_addr->first+1;
    my $static_h = ip2hex($static_s->addr);

    my $hi_s     = $net_addr->last;
    my $hi_h     = ip2hex($hi_s->addr);

    $sponge->set_alive($lo_h);
    is $sponge->get_state($lo_h), ALIVE,
        "get_state('$lo_h') is ALIVE after set_alive('$lo_h')";

    $sponge->set_pending($lo_h, 0);
    is $sponge->get_state($lo_h), PENDING(0),
        "get_state('$lo_h') is PENDING(0) after set_pending('$lo_h', 0)";

    $sponge->incr_pending($lo_h);
    is $sponge->get_state($lo_h), PENDING(1),
        "get_state('$lo_h') is PENDING(1) after incr_pending('$lo_h')";

    subtest 'set_dead' => sub {
        $mock_pcap->clear_sent($pcap_h);
        $sponge->set_dead($lo_h);
        is $sponge->get_state($lo_h), DEAD, "get_state('$lo_h') is DEAD";

        subtest 'gratuitous_arp' => sub {
            check_arp_sent($sponge,
                spa     => $lo_h,
                tpa     => $lo_h,
                opcode  => ARP_OPCODE_REQUEST,
            );
        };
    };

    subtest 'set_static' => sub {
        $mock_pcap->clear_sent($pcap_h);
        $sponge->set_static($static_h);
        is $sponge->get_state($static_h), STATIC,
            "get_state('$static_h') is STATIC";

        subtest 'gratuitous_arp' => sub {
            check_arp_sent($sponge,
                spa     => $static_h,
                tpa     => $static_h,
                opcode  => ARP_OPCODE_REQUEST,
            );
        };
    };

    $sponge->set_alive($lo_h);
    is $sponge->get_state($lo_h), ALIVE,
        "get_state('$lo_h') is ALIVE after set_alive('$lo_h')";

    $sponge->set_dead($lo_h);
    is $sponge->get_state($lo_h), DEAD,
        "get_state('$lo_h') is DEAD after set_dead('$lo_h')";

    my $request_ip = $hi_h;
    my $request_mac = 'a6a6b7b7c8c8';

    subtest 'send_reply' => sub {
        $mock_pcap->clear_sent($pcap_h);
        $sponge->send_reply($lo_h,
            { spa => $request_ip, sha => $request_mac });

        check_arp_sent($sponge,
            dst_mac => $request_mac,
            spa     => $lo_h,
            tpa     => $request_ip,
            opcode  => ARP_OPCODE_REPLY,
        );
    };

    subtest 'send_query' => sub {
        $mock_pcap->clear_sent($pcap_h);
        $sponge->send_query($lo_h);
        check_arp_sent($sponge,
            dst_mac => ETH_ADDR_BROADCAST,
            tpa     => $lo_h,
            opcode  => ARP_OPCODE_REQUEST,
        );
    };

    subtest 'ARP sending' => sub {
        # Simulate that we received a packet from
        # ($inform_ip @ $inform_mac) that was addressed
        # to ($about_ip @ $my_mac).
        #
        # Inform $inform_ip that $about_ip is now at $about_mac.

        my $inform_ip  = $lo_h;
        my $inform_mac = 'a6a6b7b7c8c8';

        my $about_ip   = $hi_h;
        my $about_mac  = '1e1e2e2e3e3e';

        subtest 'send_arp_update(reply)' => sub {
            # Send to $inform_mac:
            #   ARP $about_ip IS-AT $about_mac
            $mock_pcap->clear_sent($pcap_h);
            $sponge->arp_update_flags(ARP_UPDATE_REPLY);
            $sponge->send_arp_update(
                tpa => $inform_ip,
                tha => $inform_mac,
                spa => $about_ip,
                sha => $about_mac,
                tag => '[auto]',
            );

            check_arp_sent($sponge,
                dst_mac => $inform_mac,
                tpa     => $inform_ip,
                tha     => $inform_mac,
                spa     => $about_ip,
                sha     => $about_mac,
                opcode  => ARP_OPCODE_REPLY,
            );
        };

        subtest 'send_arp_update(request)' => sub {
            # Send to $inform_mac:
            #   ARP WHO-HAS $inform_ip TELL $about_ip @ $about_mac
            $mock_pcap->clear_sent($pcap_h);
            $sponge->arp_update_flags(ARP_UPDATE_REQUEST);
            $sponge->send_arp_update(
                tpa => $inform_ip,
                tha => $inform_mac,
                spa => $about_ip,
                sha => $about_mac,
                tag => '[auto]',
            );

            check_arp_sent($sponge,
                dst_mac => $inform_mac,
                tpa     => $inform_ip,
                tha     => $inform_mac,
                spa     => $about_ip,
                sha     => $about_mac,
                opcode  => ARP_OPCODE_REQUEST,
            );
        };

        subtest 'send_arp_update(gratuitous)' => sub {
            # Send to $inform_mac:
            #   ARP WHO-HAS $about_ip TELL $about_ip @ $about_mac
            $mock_pcap->clear_sent($pcap_h);
            $sponge->arp_update_flags(ARP_UPDATE_GRATUITOUS);
            $sponge->send_arp_update(
                tpa => $about_ip,
                tha => $inform_mac,
                spa => $about_ip,
                sha => $about_mac,
                tag => '[auto]',
            );

            check_arp_sent($sponge,
                dst_mac => $inform_mac,
                tpa     => $about_ip,
                tha     => $inform_mac,
                spa     => $about_ip,
                sha     => $about_mac,
                opcode  => ARP_OPCODE_REQUEST,
            );
        };

        subtest 'is_dummy' => sub {
            $sponge->is_dummy(1);
            note "set is_dummy to ", $sponge->is_dummy();
            # Send to $inform_mac:
            #   ARP WHO-HAS $about_ip TELL $about_ip @ $about_mac
            $mock_pcap->clear_sent($pcap_h);
            $sponge->arp_update_flags(ARP_UPDATE_GRATUITOUS);
            $sponge->send_arp_update(
                tpa => $about_ip,
                tha => $inform_mac,
                spa => $about_ip,
                sha => $about_mac,
                tag => '[auto]',
            );
            my $sent = $mock_pcap->get_sent($pcap_h);
            is @{$sent}, 0, "send_arp_update() sends no packet";

            $mock_pcap->clear_sent($pcap_h);
            $sponge->send_reply($lo_h,
                { spa => $request_ip, sha => $request_mac });
            $sent = $mock_pcap->get_sent($pcap_h);
            is @{$sent}, 0, "send_reply() sends no packet";

            $mock_pcap->clear_sent($pcap_h);
            $sponge->send_query($lo_h);
            $sent = $mock_pcap->get_sent($pcap_h);
            is @{$sent}, 1, "send_query() still sends a packet";
        };
    };
};

subtest 'clear_state' => sub {
    my $lo_s   = $net_addr->first;
    my $lo_h   = ip2hex($lo_s->addr);
    my $hi_s   = $net_addr->last;
    my $hi_h   = ip2hex($hi_s->addr);
    my $mac_h  = 'a6a6b7b7c8c8';

    $sponge->set_alive($lo_h, $mac_h);
    $sponge->set_pending($lo_h, 3);

    is $sponge->get_state($lo_h), PENDING(3),
        "get_state('$lo_h') is PENDING(3)";

    my ($mac, $mtime) = $sponge->arp_table->lookup_ip($lo_h);
    is $mac, $mac_h,
        "'$lo_h' is at MAC '$mac_h'";

    $sponge->queue->add($lo_h, $hi_h, time);
    $sponge->queue->add($lo_h, $hi_h, time);
    $sponge->queue->add($lo_h, $hi_h, time);
    $sponge->queue->add($lo_h, $hi_h, time);

    is $sponge->queue->depth($lo_h), 4,
        "'$lo_h' queue depth is 4";

    note "call clear_state('$lo_h')";
    $sponge->clear_state($lo_h);

    is $sponge->get_state($lo_h), undef,
        "get_state('$lo_h') is undef (aka NONE)";

    ($mac, $mtime) = $sponge->arp_table->lookup_ip($lo_h);
    is $mac, undef,
        "'$lo_h' is not in ARP table";

    is $sponge->queue->depth($lo_h), 0,
        "'$lo_h' queue depth is 0";
};
done_testing;
