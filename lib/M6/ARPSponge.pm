###############################################################################
#
# M6::ARPSponge
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
# S.Bakker, 2004-2015;
#
# IMPORTANT:
#
#   * IP and MAC addresses are stored as HEX strings, use
#     M6::ARP::Util::hex2{ip,mac} to convert to human-readable
#     form.
#
###############################################################################
package M6::ARPSponge;

use Modern::Perl;
use Moo;
use Types::Standard -types;

use M6::ARPSponge::Queue;
use M6::ARP::Event;
use M6::ARP::Log;
use M6::ARP::Const      qw( :all );
use M6::ARP::Util       qw( :all );
use M6::ARP::NetPacket  qw( :all );

use POSIX               qw( strftime );
use IPC::Run            qw( run );
use IO::Select;
use File::Which         qw( which );

our $VERSION = 1.08;

my $INT_ZERO    = sub {0};
my $EMPTY_HASH  = sub {{}};

# Required attributes.
has 'device'           => ( is => 'ro', isa => Str,  required => 1);
has 'network'          => ( is => 'ro', isa => Str,  required => 1);
has 'prefixlen'        => ( is => 'ro', isa => Int,  required => 1);
has 'max_pending'      => ( is => 'rw', isa => Int,  required => 1);
has 'pcap_handle'      => ( is => 'rw', isa => Object, required => 1);

# Public r/w attributes.
has 'arp_age'     => ( is => 'rw', isa => Num,     default => $INT_ZERO );
has 'is_dummy'    => ( is => 'rw', isa => Bool,    default => $INT_ZERO );
has 'gratuitous'  => ( is => 'rw', isa => Bool,    default => $INT_ZERO );
has 'sponge_net'  => ( is => 'rw', isa => Bool,    default => $INT_ZERO );
has 'max_rate'    => ( is => 'rw', isa => Num,     default => $INT_ZERO );
has 'state_table' => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has 'queuedepth'  => ( is => 'rw', isa => Int, 
                            default => sub { $M6::ARPSponge::Queue::DFL_DEPTH });
has 'arp_update_flags' => ( is => 'rw', isa => Int,
                            default => sub { ARP_UPDATE_ALL });
has 'flood_protection' => ( is => 'rw', isa => Num,  default => $INT_ZERO );

# Public r/o attributes.
has 'my_ip'  => ( is => 'rw', isa => Str,    writer => '_set_my_ip' );
has 'my_mac' => ( is => 'rw', isa => Str,    writer => '_set_my_mac' );
has 'queue'  => ( is => 'rw', isa => Object, writer => '_set_queue' );

# Private attributes.
has '_phys_device' => ( is => 'rw', isa => Str ); 
has '_all_ip'      => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_user_data'   => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_pending'     => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_state'       => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_state_mtime' => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_state_atime' => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );
has '_arp_table'   => ( is => 'rw', isa => HashRef, default => $EMPTY_HASH );

###############################################################################
# $sponge = new M6::ARPSponge(ARG => VAL ...)
#
#    Create a new Sponge object.
#
###############################################################################
sub BUILD {
    my ($self, $args) = @_;

    $self->_phys_device((split /:/, $self->{'device'})[0]);
    
    $self->_all_ip( { map { ip2hex($_) => 1 } $self->_get_all_ip_addr } );
    $self->my_ip( $self->_get_ip );
    $self->my_mac( $self->_get_mac );

    $self->_set_queue(M6::ARP::Queue->new($self->queuedepth));

    $self->init_all_state();

    if (log_is_verbose) {
        log_sverbose(1, "Device: %s\n", $self->device);
        log_sverbose(1, "Device: %s\n", $self->_phys_device);
        log_sverbose(1, "MAC:    %s\n", $self->my_mac_s);
        log_sverbose(1, "IP:     %s\n", $self->my_ip_s);
    }
    return $self;
}

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
    my $user = $self->_user_data;

    return $user if @_ == 0;

    my $attr = shift;

    if (@_) {
        my $old = $user->{$attr};
        $user->{$attr} = shift;
        return $old;
    }
    else {
        return $user->{$attr};
    }
}

sub state_name { return state_to_string($_[1]) }

###############################################################################
#
#                   Simple Queries
#
###############################################################################

###############################################################
# $bool = $sponge->is_my_ip( $hex );
#
#   Return whether $hex is one of the host's IP addresses.
###############################################################
sub is_my_ip {
    $_[0]->_all_ip->{$_[1]}
}

###############################################################
# $bool = $sponge->is_my_ip_s( $str );
#
#   Return whether $str is one of the host's IP addresses.
###############################################################
sub is_my_ip_s {
    return $_[0]->_all_ip->{ip2hex($_[1])}
}

###############################################################
# $ip_str = $sponge->my_ip_s();
#
#   Return the sponge's IP address as a string.
###############################################################
sub my_ip_s {
    return hex2ip(shift->my_ip);
}

###############################################################
# $ip_str = $sponge->network_s();
#
#   Return the sponge's network address as a string.
###############################################################
sub network_s {
    return hex2ip(shift->network);
}

###############################################################
# $mac_str = $sponge->my_mac_s();
#
#   Return the sponge's MAC address as a string.
###############################################################
sub my_mac_s  {
    return hex2mac(shift->my_mac);
}

###############################################################
# $atime = $sponge->state_atime( $hex_ip );
#
#   Return the access time for the state of $hex_ip.
###############################################################
sub state_atime {
    return $_[0]->_state_atime->{$_[1]};
}

###############################################################
# $atime = $sponge->set_state_atime( $hex_ip, $atime );
#
#   Set the access time for the state of $hex_ip.
###############################################################
sub set_state_atime {
    return $_[0]->_state_atime->{$_[1]} = $_[2];
}

###############################################################
# $mtime = $sponge->state_mtime( $hex_ip );
#
#   Return the modification time for the state of $hex_ip.
###############################################################
sub state_mtime {
    return $_[0]->_state_mtime->{$_[1]}
}

###############################################################
# $mtime = $sponge->set_state_mtime( $hex_ip, $mtime );
#
#   Set the modification time for the state of $hex_ip.
###############################################################
sub set_state_mtime {
    return $_[0]->_state_mtime->{$_[1]} = $_[2]
}

###############################################################
# $state = $sponge->get_state( $hex_ip );
#
#   Return the state for $hex_ip.
###############################################################
sub get_state {
    return $_[0]->state_table->{$_[1]}
}

###############################################################
# $state = $sponge->get_state( $hex_ip );
#
#   Set the state for $hex_ip. Also sets the mtime and atime,
#   and updates the "pending" table.
###############################################################
sub set_state {
    my ($self, $ip, $state, $time) = @_;

    if (defined $state) {
        $time //= time;
        $self->_state_mtime->{$ip} = $self->_state_atime->{$ip} = $time;
        $self->_state_table->{$ip} = $state;
        # If IP is in any pending state, add it to the pending table, to
        # facilitate quick lookup.
        if ($state >= PENDING(0)) {
            $self->_pending->{$ip} = $state;
        }
        else {
            delete $self->_pending->{$ip};
        }
    }
    else {
        delete $self->_state_mtime->{$ip};
        delete $self->_state_atime->{$ip};
        delete $self->_state_table->{$ip};
        delete $self->_pending->{$ip};
        $self->queue->clear($ip);
    }
    return $state;
}


###############################################################################
# $sponge = $sponge->init_all_state();
#
#   Wipe all state info from the sponge. This includes all IP state info,
#   all queue info, all timings, all ARP info.
#
#   The only info left in the tables is the sponge's own address.
#
###############################################################################
sub init_all_state {
    my $self = shift;

    $self->_pending({});
    $self->_state({});
    $self->_state_mtime({});
    $self->_state_atime({});
    $self->_queue->clear_all();
    $self->_arp_table({});

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

    return $self->_arp_table if @_ == 0;

    my $ip = shift;

    if (@_) {
        my $mac  = shift;
        my $time = @_ ? shift : time;
        if (defined $mac && $mac ne $ETH_ADDR_NONE) {
            $self->_arp_table->{$ip} = [ $mac, $time ];
        }
        else {
            delete $self->_arp_table->{$ip};
        }
    }
    return $self->_arp_table->{$ip} ? @{$self->_arp_table->{$ip}} : ();
}


###############################################################################
# $mac = $sponge->_get_mac;
# $mac = $sponge->_get_mac($device);
#
#   Return MAC address for device $device.
#
###############################################################################
sub get_mac {
    my $self = shift;
    my $dev = @_ ? shift @_ : $self->device;

    my (@mac, $err, $excode, $cmd);
    if ($cmd = which('ip')) {
        my $mac_list;
        run [ $cmd, 'addr', 'show', $dev ],
            '<' => \undef,
            '>' => \(my $mac_list),
            '2>' => \$err;

        $excode = $?;
        @mac = $mac_list =~ m{^\s*link/ether ([a-f\d\:]+) }gmi;
    }
    elsif ($cmd = which('ifconfig')) {
        run [ $cmd, $dev ],
            '<' => \undef,
            '>' => \(my $mac_list),
            '2>' => \$err;

        $excode = $?;
        @mac = $mac_list =~ m{\s(?:ether|hwaddr)\s+([a-f\d\:]+) }gmi;
    }
    else {
        die "cannot determine MAC address of $dev: ",
            "no 'ip' or 'ifconfig' command in the PATH";
    }

    $excode >>= 8;
    if ($excode != 0) {
        die "** [ERROR] cannot determine MAC address of $dev: ",
            "$cmd exited with code $excode\n",
            "$cmd: $err\n";
    }
    elsif (length $err) {
        warn "** [WARN] issues determining MAC address of $dev\n",
             "$cmd: $err\n";
    }
    return mac2hex(lc $mac[0]);
}


###############################################################################
# @ip = $sponge->_get_all_ip_addr;
#
#   Return all IP addresses for this host.
#
###############################################################################
sub _get_all_ip_addr {
    my (@ip, $err, $excode, $cmd);

    if ($cmd = which('ip')) {
        my $mac_list;
        run [ $cmd, 'addr', 'show' ],
            '<' => \undef,
            '>' => \(my $ip_list),
            '2>' => \$err;

        $excode = $?;
        @ip = $ip_list =~ m{^\s*inet ([\d\.]+)/\d+ }gm;
    }
    elsif ($cmd = which('ifconfig')) {
        run [ $cmd, '-a' ],
            '<' => \undef,
            '>' => \(my $ip_list),
            '2>' => \$err;

        $excode = $?;
        @ip = $ip_list =~ m{^\s*inet (?:addr:)?([\d\.]+) }gm;
    }
    else {
        die "cannot determine IP address: ",
            "no 'ip' or 'ifconfig' command in the PATH";
    }

    $excode >>= 8;
    if ($excode != 0) {
        die "** [ERROR] cannot determine IP address: ",
            "$cmd exited with code $excode\n",
            "$cmd: $err\n";
    }
    elsif (length $err) {
        warn "** [WARN] issues determining IP address\n", "$cmd: $err\n";
    }

    return ip2hex(lc ($ip[0] // '0.0.0.0'));
}


###############################################################################
# $ip = $sponge->_get_ip;
# $ip = $sponge->_get_ip($device);
#
#   Return IP address for device $device, or '0.0.0.0' if none.
#
###############################################################################
sub _get_ip {
    my $self = shift;
    my $dev = @_ ? shift @_ : $self->device;

    if ($cmd = which('ip')) {
        my $mac_list;
        run [ $cmd, 'addr', 'show', $dev ],
            '<' => \undef,
            '>' => \(my $ip_list),
            '2>' => \$err;

        $excode = $?;
        @ip = $ip_list =~ m{^\s*inet ([\d\.]+)/\d+ }gm;
    }
    elsif ($cmd = which('ifconfig')) {
        run [ $cmd, $dev ],
            '<' => \undef,
            '>' => \(my $ip_list),
            '2>' => \$err;

        $excode = $?;
        @ip = $ip_list =~ m{^\s*inet (?:addr:)?([\d\.]+) }gm;
    }
    else {
        die "cannot determine IP address of $dev: ",
            "no 'ip' or 'ifconfig' command in the PATH";
    }

    $excode >>= 8;
    if ($excode != 0) {
        die "** [ERROR] cannot determine IP address of $dev: ",
            "$cmd exited with code $excode\n",
            "$cmd: $err\n";
    }
    elsif (length $err) {
        warn "** [WARN] issues determining IP address of $dev\n",
             "$cmd: $err\n";
    }

    return ip2hex(lc ($ip[0] // '0.0.0.0'));
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
            "Probing [dev=%s]: %s\n", $self->_phys_device, hex2ip($ip)
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
                $self->_phys_device, hex2ip($ip));
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
