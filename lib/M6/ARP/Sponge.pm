###############################################################################
# @(#)$Id$
###############################################################################
#
# ARP sponge
#
#   Copyright (c) 2005-2011 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc
#   perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#   See the "Copying" file that came with this package.
#
# A.Vijn,   2003-2004;
# S.Bakker, 2004-2010;
#
# IMPORTANT:
#
#   * IP and MAC addresses are stored as HEX strings, use
#     M6::ARP::Util::hex2{ip,mac} to convert to human-readable
#     form.
#
###############################################################################
package M6::ARP::Sponge;

use strict;

use base qw( M6::ARP::Base );

use M6::ARP::Queue;
use M6::ARP::Event;
use M6::ARP::Log;
use M6::ARP::Const      qw( :all );
use M6::ARP::Util       qw( :all );
use M6::ARP::NetPacket  qw( :all );

use POSIX               qw( strftime );
use Net::ARP;
use IO::Select;

our $VERSION = 1.07;

# Accessors; use the factory :-)
__PACKAGE__->mk_accessors(qw( 
                is_dummy
                queuedepth      my_ip               my_mac
                network         prefixlen
                arp_age         gratuitous          flood_protection
                max_rate        max_pending         sponge_net
                pcap_handle
                arp_update_flags
        ));

###############################################################################
#
#                   User Attributes
#
###############################################################################

# $hash = $sponge->user;
# $val = $sponge->user($attr);
# $oldval = $sponge->user($attr, $newval);
sub user {
    my $self = shift;
    my $user = $self->{'user'};

    return $user if @_ == 0;

    my $attr = shift;
    my $oldval = $user->{$attr};
    if (@_) {
        my $val = shift;
        $user->{$attr} = $val;
    }
    return $oldval;
}

sub state_name { return state_to_string($_[1]) }

###############################################################################
#
#                   Object Attributes
#
###############################################################################

sub queue            { shift->{'queue'} }
sub device           { shift->{'device'} }
sub phys_device      { shift->{'phys_device'} }
sub pending          { shift->{'pending'} }

sub is_my_ip         { $_[0]->{'ip_all'}->{$_[1]} }
sub is_my_ip_s       { $_[0]->{'ip_all'}->{ip2hex($_[1])} }

sub my_ip_s          { return hex2ip(shift->my_ip)   }
sub network_s        { return hex2ip(shift->network) }
sub my_mac_s         { return hex2mac(shift->my_mac) }

sub state_atime      { $_[0]->{state_atime}->{$_[1]} }
sub set_state_atime  { $_[0]->{state_atime}->{$_[1]} = $_[2] }

sub state_mtime      { $_[0]->{state_mtime}->{$_[1]} }
sub set_state_mtime  { $_[0]->{state_mtime}->{$_[1]} = $_[2] }

sub state_table      { shift->{state} }
sub get_state        { $_[0]->{state}->{$_[1]} }

sub set_state    {
    my ($self, $ip, $state, $time) = @_;

    if (defined $state) {
        $time //= time;
        $self->{state_mtime}->{$ip} = $self->{state_atime}->{$ip} = $time;
        $self->{state}->{$ip} = $state;
        if ($state >= PENDING(0)) {
            $self->{'pending'}->{$ip} = $state;
        }
        else {
            delete $self->{'pending'}->{$ip};
        }
    }
    else {
        delete $self->{state_mtime}->{$ip};
        delete $self->{state_atime}->{$ip};
        delete $self->{state}->{$ip};
        delete $self->{'pending'}->{$ip};
        $self->queue->clear($ip);
    }
    return $state;
}

###############################################################################
# $sponge = new M6::ARP::Sponge(ARG => VAL ...)
#
#    Create a new Sponge object.
#
###############################################################################
sub new {
    my $type = shift;

    my $self = {
            'arp_update_flags'  => ARP_UPDATE_ALL,
            'queuedepth'        => $M6::ARP::Queue::DFL_DEPTH,
        };

    while (@_ >= 2) {
        my $k = shift @_;
        my $v = shift @_;
        $k =~ s/^-//;
        $self->{lc $k} = $v;
    
    }
    bless $self, $type;

    ($self->{'phys_device'}) = split(/:/, $self->{'device'});
    
    $self->{'ip_all'} = { map { $_ => 1 } $self->get_ip_all };
    $self->my_ip( $self->get_ip );
    $self->my_mac( $self->get_mac );

    $self->{user}        = {};
    $self->{queue}       = new M6::ARP::Queue($self->queuedepth);

    $self->init_all_state();

    if (log_is_verbose) {
        log_sverbose(1, "Device: %s\n", $self->device);
        log_sverbose(1, "Device: %s\n", $self->phys_device);
        log_sverbose(1, "MAC:    %s\n", $self->my_mac_s);
        log_sverbose(1, "IP:     %s\n", $self->my_ip_s);
    }
    return $self;
}

###############################################################################
# $sponge->init_all_state();
#
#   Wipe all state info from the sponge. This includes all IP state info,
#   all queue info, all timings, all ARP info.
#
#   The only info left in the tables is the sponge's own address.
#
###############################################################################
sub init_all_state {
    my $self = shift;

    $self->{pending}     = {};
    $self->{state}       = {};
    $self->{state_mtime} = {};
    $self->{state_atime} = {};
    $self->{queue}->clear_all();
    $self->{'arp_table'} = {};

    # Build up a bit of state again...

    $self->set_state($self->network, STATIC) if $self->sponge_net;

    for my $ip ($self->my_ip, keys %{$self->{'ip_all'}}) {
        $self->set_alive($ip, $self->my_mac);
    }
    return $self;
}

###############################################################################
# $table = $sponge->arp_table;
# ($mac, $time) = $sponge->arp_table($ip);
# ($mac, $time) = $sponge->arp_table($ip, $mac [, $time]);
#
#   Perform a ARP table lookup, or update the ARP table.
#
###############################################################################
sub arp_table {
    my $self = shift;

    return $self->{'arp_table'} if @_ == 0;

    my $ip        = shift;
    my $arp_table = $self->{'arp_table'};

    if (@_) {
        my $mac = shift;
        my $time = @_ ? shift : time;
        if (defined $mac && $mac ne $ETH_ADDR_NONE) {
            $self->{'arp_table'}->{$ip} = [ $mac, $time ];
        }
        else {
            delete $self->{'arp_table'}->{$ip};
        }
    }
    return $self->{'arp_table'}->{$ip} ? @{$self->{'arp_table'}->{$ip}} : ();
}

###############################################################################
# $mac = $sponge->get_mac;
# $mac = $sponge->get_mac($device);
# $mac = get_mac($device);
#
#   Return MAC address for device $device.
#
###############################################################################
sub get_mac {
    my $dev = pop @_;
    if (ref $dev) { $dev = $dev->device }

    # get_mac is SCARY! and WRONG!
    my $mac = Net::ARP::get_mac($dev);

    #print STDERR "Net::ARP::get_mac($dev) -> \"$mac\"\n";
    return mac2hex($mac);
}

###############################################################################
# @ip = $sponge->get_ip_all;
#
#   Return all IP addresses for physical device $device. This includes all
#   addresses configured on "sub" interfaces.
#
###############################################################################
sub get_ip_all {
    my @ip;

    open(IFCONFIG, 'ifconfig -a 2>/dev/null|');
    local($_);
    while (<IFCONFIG>) {
        if (/^.*inet addr:(\S+)/) {
            push @ip, ip2hex($1);
        }
    }
    close IFCONFIG;
    return @ip;
}

###############################################################################
# $ip = $sponge->get_ip;
# $ip = $sponge->get_ip($device);
# $ip = get_ip($device);
#
#   Return IP address for device $device, or '0.0.0.0' if none.
#
###############################################################################
sub get_ip {
    my $dev = pop @_;
    if (ref $dev) { $dev = $dev->device }
    my $ip = `ifconfig $dev 2>/dev/null`;

    if ($ip !~ s/^.*inet addr:(\S+).*$/$1/s) {
        $ip = '0.0.0.0';
    }
    return ip2hex($ip);
}

###############################################################################
# $bool = $sponge->is_my_network($ip)
#
#   Returns whether or not $ip is in the monitored
#   network range(s).
#
###############################################################################
sub is_my_network {
    my ($self, $ip) = @_;
    return hex_addr_in_net($ip, $self->network, $self->prefixlen);
}

sub is_my_network_s {
    my ($self, $ip) = @_;
    return hex_addr_in_net(ip2hex($ip), $self->network, $self->prefixlen);
}


###############################################################################
# $state = $sponge->set_pending($ip, $n);
#
#   Set $ip's state to PENDING "$n". Returns new state.
#
###############################################################################
sub set_pending {
    my ($self, $ip, $n) = @_;
    my $state = $self->set_state($ip, PENDING($n));
    event_notice(EVENT_SPONGE, "pending: ip=%s state=%d", hex2ip($ip), $n);
    return $state;
}

###############################################################################
# $state = $sponge->incr_pending($ip);
#
#   Increment $ip's PENDING state. Returns new state.
#
###############################################################################
sub incr_pending {
    my ($self, $ip) = @_;
    my $pending = $self->get_state($ip) - PENDING(0);
    return $self->set_pending($ip, $pending+1);
}

###############################################################################
# $sponge->send_probe($ip);
#
#   Send a (probe) ARP "WHO HAS $ip". This prevents us from
#   erroneously sponging when there's a cretin sending ARP floods.
#
###############################################################################
sub send_probe {
    my ($self, $ip) = @_;

    if (log_is_verbose >=2) {
        log_sverbose(2,
            "Probing [dev=%s]: %s\n", $self->phys_device, hex2ip($ip)
        );
    }

    $self->set_state_atime($ip, time);

    $self->send_arp( tha => $ETH_ADDR_BROADCAST,
                     tpa => $ip,
                     opcode => $ARP_OPCODE_REQUEST );
    return;
}

###############################################################################
# $sponge->gratuitous_arp($ip);
#
#   Send a (sponge) ARP WHO HAS $ip TELL $ip".
#
###############################################################################
sub gratuitous_arp {
    my ($self, $ip) = @_;

    if (log_is_verbose) {
        log_sverbose(1, "%sgratuitous ARP [dev=%s]: %s\n",
                ($self->is_dummy ? '[DUMMY] ' : ''),
                $self->phys_device, hex2ip($ip));
    }

    $self->set_state_atime($ip, time);

    return if $self->is_dummy;

    my $ip_s = hex2ip($ip);
    $self->send_arp( spa => $ip,
                     tha => $ETH_ADDR_BROADCAST,
                     tpa => $ip,
                     opcode => $ARP_OPCODE_REQUEST );
}

###############################################################################
# $sponge->send_arp($opcode, $sha, $spa, $tha, $tpa);
#
#   Send an ARP packet.
#
###############################################################################
sub send_arp {
    my ($self, %args) = @_;

    my $pcap_h = $self->pcap_handle or return;

    $args{spa}      //= $self->my_ip;
    $args{sha}      //= $self->my_mac;
    $args{src_mac}  //= $self->my_mac;
    $args{dest_mac} //= $args{tha};
    $args{opcode}   //= $ARP_OPCODE_REQUEST;

    my $pkt = encode_ethernet({
                    dest_mac => $args{tha},
                    src_mac  => $args{src_mac},
                    type     => $ETH_TYPE_ARP,
                    data     => encode_arp({
                                    sha => $args{sha},
                                    spa => $args{spa},
                                    tha => $args{tha},
                                    tpa => $args{tpa},
                                    opcode => $args{opcode},
                                })
                });

    if (Net::Pcap::sendpacket($pcap_h, $pkt) < 0) {
        event_err(EVENT_IO, "ERROR sending ARP packet: %s", $!);
    }
    return;
}

###############################################################################
# $sponge->send_arp_reply(%args);
#
#   Send an ARP "xx IS AT yy".
#
###############################################################################
sub send_arp_update {
    my ($self, %args) = @_;

    my $pcap_h = $self->pcap_handle;

    if (!$pcap_h || log_is_verbose) {
        my $dst_mac_s = hex2mac($args{tha});
        my $dst_ip_s  = hex2ip($args{tpa});
        my $src_mac_s = hex2mac($args{sha});
        my $src_ip_s  = hex2ip($args{spa});
        my $tag       = $args{tag} // '';
        log_sverbose(1, "%s%sarp inform %s\@%s about %s\@%s\n",
                        $tag,
                        (!$pcap_h || $self->is_dummy ? '[DUMMY] ' : ''),
                         $dst_ip_s, $dst_mac_s,
                         $src_ip_s, $src_mac_s,
                    );
    }
    return if (!$pcap_h || $self->is_dummy);

    my $update_flags = $self->arp_update_flags;

    # Try various ways of updating the neighbour's cache...
    if ($update_flags & ARP_UPDATE_REPLY) {
        $self->send_arp( sha => $args{sha},
                         spa => $args{spa},
                         tha => $args{tha},
                         tpa => $args{tpa},
                         opcode => $ARP_OPCODE_REPLY );
    }

    if ($update_flags & ARP_UPDATE_REQUEST) {
        $self->send_arp( sha => $args{sha},
                         spa => $args{spa},
                         tha => $args{tha},
                         tpa => $args{tpa},
                         opcode => $ARP_OPCODE_REQUEST );
    }

    # Third option: fake a gratuitous ARP: "unicast proxy gratuitous ARP
    # request" :-)
    if ($update_flags & ARP_UPDATE_GRATUITOUS) {
        $self->send_arp( sha => $args{sha},
                         spa => $args{spa},
                         tha => $args{tha},
                         tpa => $args{spa},
                         opcode => $ARP_OPCODE_REQUEST );
    }
    return;
}

###############################################################################
# $sponge->send_reply($src_ip, $arp_obj);
#
#   Send a (sponge) ARP "$src_ip IS AT" in reply to the $arp_obj request.
#
###############################################################################
sub send_reply {
    my ($self, $src_ip, $arp_obj) = @_;

    $self->set_state_atime($src_ip, time);

    my $pcap_h = $self->pcap_handle;

    if (!$pcap_h || $self->is_dummy) {
        my $dst_mac_s = hex2mac($arp_obj->{sha});
        my $dst_ip_s  = hex2ip($arp_obj->{spa});
        my $src_ip_s  = hex2ip($src_ip);
        log_sverbose(1, "%s: DUMMY sponge reply to %s\@%s\n",
                           $src_ip_s, $dst_ip_s, $dst_mac_s);
        return;
    }
    elsif (log_is_verbose) {
        my $dst_mac_s = hex2mac($arp_obj->{sha});
        my $dst_ip_s  = hex2ip($arp_obj->{spa});
        my $src_ip_s  = hex2ip($src_ip);
        log_sverbose(1, "%s: sponge reply to %s\@%s\n",
                           $src_ip_s, $dst_ip_s, $dst_mac_s);
    }

    $self->send_arp( spa => $src_ip,
                     tha => $arp_obj->{sha},
                     tpa => $arp_obj->{spa},
                     opcode => $ARP_OPCODE_REPLY );
    return;
}

###############################################################################
# $sponge->set_dead($ip);
#
#    Set $ip's state to DEAD (i.e. "sponged").
#
###############################################################################
sub set_dead {
    my ($self, $ip) = @_;
    my $rate = $self->queue->rate($ip) // 0.0;

    event_notice(EVENT_SPONGE,  
        "sponging: ip=%s rate=%0.1f", hex2ip($ip), $rate);

    $self->gratuitous_arp($ip) if $self->gratuitous;
    $self->set_state($ip, DEAD);
    # This is the place where we could send a gratuitous ARP for
    # the sponged address to shut up all other queriers.
}

###############################################################################
# set_alive($data, $ip, $target_mac);
#
#   Unsponge the $ip, which is now seen from $target_mac.
#   Update ARP cache and print appropriate notifications.
#
###############################################################################
sub set_alive {
    my ($self, $ip, $mac) = @_;

    return if ! $self->is_my_network($ip);

    my @arp = $self->arp_table($ip);

    $mac //= $arp[0] // $ETH_ADDR_NONE;

    if ($self->get_state($ip) == DEAD) {
        event_notice(EVENT_SPONGE,
            "unsponging: ip=%s mac=%s", hex2ip($ip), hex2mac($mac));
    }
    elsif ($self->get_state($ip) >= PENDING(0)) {
        event_notice(EVENT_SPONGE,
            "clearing: ip=%s mac=%s", hex2ip($ip), hex2mac($mac));
    }
    elsif (log_is_verbose && $self->queue->depth($ip) > 0) {
        log_sverbose(1,
            "clearing: ip=%s mac=%s\n", hex2ip($ip), hex2mac($mac));
    }

    $self->queue->clear($ip);
    $self->set_state($ip, ALIVE);

    if (log_is_verbose) {
        if (!@arp) {
            log_sverbose(1, "learned: ip=%s mac=%s old=none\n",
                               hex2ip($ip), hex2mac($mac));
        }
        elsif ($arp[0] ne $mac) {
            log_sverbose(1, "learned: ip=%s mac=%s old=%s\n",
                              hex2ip($ip), hex2mac($mac), hex2mac($arp[0]));
        }
    }
    $self->arp_table($ip, $mac, time);
}

1;
