###############################################################################
# @(#)$Id$
###############################################################################
#
# ARP sponge
#
# (c) Copyright AMS-IX B.V. 2004-2005;
#
# See the LICENSE file that came with this package.
#
# A.Vijn,   2003-2004;
# S.Bakker, 2004-2010;
#
###############################################################################
package M6::ARP::Sponge;

use strict;

use base qw( M6::ARP::Base Exporter );

use M6::ARP::Queue;
use M6::ARP::Util       qw( :all );

use POSIX               qw( strftime );
use NetPacket::Ethernet qw( :types );
use NetPacket::ARP      qw( ARP_OPCODE_REQUEST );
use NetPacket::IP;
use Net::ARP;
use Sys::Syslog;
use Net::IPv4Addr       qw( :all );
use IO::File;

BEGIN {
    our $VERSION = 1.06;

    my @states = qw( STATIC DEAD ALIVE PENDING );
    my @log    = qw( print_log print_notify );

    our @EXPORT_OK = ( @states, @log );
    our @EXPORT    = ();

    our %EXPORT_TAGS = ( 
            'states' => \@states,
            'log'    => \@log,
            'all'    => [ @log, @states ]
        );
    0 if 0 && $::opt_verbose;
}

# State constants/macros
use constant STATIC  => -3;
use constant DEAD    => -2;
use constant ALIVE   => -1;

sub PENDING { 0 + $_[$#_] };

# Accessors; use the factory :-)
__PACKAGE__->mk_accessors(qw( 
                syslog_ident    is_verbose  is_dummy
                queuedepth      my_ip       my_mac
                network         netmask     loglevel
                max_pending     notify      max_rate
                arp_age         gratuitous  flood_protection
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

sub state_atime      { $_[0]->{state_atime}->{$_[1]} }
sub set_state_atime  { $_[0]->{state_atime}->{$_[1]} = $_[2] }

sub state_mtime      { $_[0]->{state_mtime}->{$_[1]} }
sub set_state_mtime  { $_[0]->{state_mtime}->{$_[1]} = $_[2] }

sub state_table      { shift->{state} }
sub get_state        { $_[0]->{state}->{$_[1]} }

sub set_state    {
    my ($self, $ip, $state) = @_;

    $self->{state_mtime}->{$ip} = $self->{state_atime}->{$ip} = time;
    $self->{state}->{$ip} = $state;
    if ($state >= PENDING(0)) {
        $self->{'pending'}->{$ip} = $state;
    }
    else {
        delete $self->{'pending'}->{$ip};
    }
    return $state;
}

###############################################################################
# $sponge->DESTROY
#
#   Destructor. Called by Perl's garbage collection.
###############################################################################
sub DESTROY {
    my $self = shift;
    if ($self->notify) {
        $self->notify->close;
    }
}

###############################################################################
# $sponge = new M6::ARP::Sponge(ARG => VAL ...)
#
#    Create a new Sponge object.
#
###############################################################################
sub new {
    my $type = shift;

    my $self = {};
    while (@_ >= 2) {
        my $k = shift @_;
        my $v = shift @_;
        $k =~ s/^-//;
        $self->{lc $k} = $v;
    
    }
    bless $self, $type;

    $self->{queuedepth}   = $M6::ARP::Queue::DFL_DEPTH if !$self->queuedepth;
    if (length $self->syslog_ident == 0) {
        my ($prog) = $0 =~ m|([^/]+)$|;
        $self->syslog_ident($prog);
    }
    $self->{user}        = {};
    $self->{pending}     = {};
    $self->{state}       = {};
    $self->{state_mtime} = {};
    $self->{state_atime} = {};
    $self->{queue}       = new M6::ARP::Queue($self->queuedepth);

    $self->my_ip( $self->get_ip );
    $self->my_mac( $self->get_mac );

    $self->{'ip_all'} = { map { $_ => 1 } $self->get_ip_all };

    $self->loglevel('info') if length $self->loglevel == 0;

    $self->{'arp_table'} = {
        $self->my_ip => [ $self->my_mac, time ]
    };

    ($self->{'phys_device'}) = split(/:/, $self->{'device'});

    if ($self->is_verbose) {
        $self->verbose(1, "Device: ", $self->device, "\n");
        $self->verbose(1, "Device: ", $self->phys_device, "\n");
        $self->verbose(1, "MAC:    ", $self->my_mac, "\n");
        $self->verbose(1, "IP:     ", $self->my_ip, "\n");
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

    my $ip   = shift;

    if (@_) {
        my $mac = shift;
        my $time = @_ ? shift : time;
        $self->{'arp_table'}->{$ip} = [ $mac, $time ];
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
    return mac2mac($mac);
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
            push @ip, $1;
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
    return $ip;
}

###############################################################################
# $bool = $sponge->is_my_network($target_ip)
#
#   Returns whether or not $target_ip is in the monitored
#   network range(s).
#
###############################################################################
sub is_my_network {
    my ($self, $target_ip) = @_;
    return ipv4_in_network($self->network, $self->netmask, $target_ip);
}


###############################################################################
# $state = $sponge->set_pending($target_ip, $n);
#
#   Set $target_ip's state to PENDING "$n". Returns new state.
#
###############################################################################
sub set_pending {
    my ($self, $target_ip, $n) = @_;
    my $state = $self->set_state($target_ip, PENDING($n));
    $self->print_log("pending: %s (state %d)", $target_ip, $n);
    $self->print_notify("action=pending;ip=%s;state=%d", $target_ip, $n);
    return $state;
}

###############################################################################
# $state = $sponge->incr_pending($target_ip);
#
#   Increment $target_ip's PENDING state. Returns new state.
#
###############################################################################
sub incr_pending {
    my ($self, $target_ip) = @_;
    my $pending = $self->get_state($target_ip) - PENDING(0);
    return $self->set_pending($target_ip, $pending+1);
}

###############################################################################
# $sponge->send_probe($target_ip);
#
#   Send a (probe) ARP "WHO HAS $target_ip". This prevents us from
#   erroneously sponging when there's a cretin sending ARP floods.
#
###############################################################################
sub send_probe {
    my ($self, $target_ip) = @_;

    $self->verbose(2, "Probing [dev=", $self->phys_device, "]: $target_ip\n");

    $self->set_state_atime($target_ip, time);

    #return if $self->is_dummy;

    Net::ARP::send_packet($self->phys_device,
            $self->my_ip,  $target_ip,
            $self->my_mac, 'ff:ff:ff:ff:ff:ff',
            'request'
        );
}

###############################################################################
# $sponge->gratuitous_arp($ip);
#
#   Send a (sponge) ARP WHO HAS $ip TELL $ip".
#
###############################################################################
sub gratuitous_arp {
    my ($self, $ip) = @_;

    $self->verbose(1, "Gratuitous ARP [dev=", $self->phys_device, "]: $ip\n");

    $self->set_state_atime($ip, time);

    return if $self->is_dummy;

    Net::ARP::send_packet($self->phys_device,
            $ip, $ip,
            $self->my_mac, 'ff:ff:ff:ff:ff:ff',
            'request'
        );
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

    # Figure out where to send the reply...
    my $dst_mac = hex2mac($arp_obj->{sha});
    my $dst_ip  = hex2ip($arp_obj->{spa});
    $self->verbose(1, "$src_ip: sponge reply to $dst_ip\@$dst_mac\n");
    return if $self->is_dummy;
    Net::ARP::send_packet($self->phys_device, $src_ip, $dst_ip,
                $self->my_mac, $dst_mac, 'reply'
            );
}

###############################################################################
# $sponge->set_dead($target_ip);
#
#    Set $target_ip's state to DEAD (i.e. "sponged").
#
###############################################################################
sub set_dead {
    my ($self, $ip) = @_;
    my $rate = $self->queue->rate($ip) // 0.0;

    $self->print_log("sponging: %s (%0.1f q/min)", $ip, $rate);
    $self->print_notify("action=sponge;ip=%s;mac=%s", $ip, $self->my_mac);

    $self->gratuitous_arp($ip) if $self->gratuitous;
    $self->set_state($ip, DEAD);
    # This is the place where we could send a gratuitous ARP for
    # the sponged address to shut up all other queriers.
}

###############################################################################
# set_alive($data, $target_ip, $target_mac);
#
#   Unsponge the $target_ip, which is now seen from $target_mac.
#   Update ARP cache and print appropriate notifications.
#
###############################################################################
sub set_alive {
    my ($self, $ip, $mac) = @_;

    return if ! $self->is_my_network($ip);

    if ($self->get_state($ip) == DEAD) {
        $self->print_log("unsponging: %s [found at %s]", $ip, $mac);
        $self->print_notify("action=unsponge;ip=%s;mac=%s", $ip, $mac);
    }
    elsif ($self->get_state($ip) >= PENDING(0)) {
        $self->print_log("clearing: %s [found at %s]", $ip, $mac);
        $self->print_notify("action=clear;ip=%s;mac=%s", $ip, $mac);
    }
    elsif ($self->queue->depth($ip) > 0) {
        $self->verbose(1, "Clearing: $ip [found at $mac]\n");
        $self->print_notify("action=clear;ip=%s;mac=%s", $ip, $mac);
    }

    $self->queue->clear($ip);
    $self->set_state($ip, ALIVE);

    my @arp = $self->arp_table($ip);

    if (!@arp) {
        $self->verbose(1, "Learned: $ip [found at $mac]\n");
        $self->print_notify("action=learn;ip=%s;mac=%s", $ip, $mac);
    }
    elsif ($arp[0] ne $mac) {
        $self->verbose(1, "Flip: $ip [found at $mac]\n");
        $self->print_notify("action=flip;ip=%s;mac=%s", $ip, $mac);
    }
    elsif (time - $arp[1] > $self->arp_age) {
        $self->print_notify("action=refresh;ip=%s;mac=%s",
                            $ip, $mac);
    }
    $self->arp_table($ip, $mac, time);
}

###############################################################################
# $sponge->verbose($level, $arg, ...);
# verbose($level, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#
###############################################################################
sub verbose {
    my ($self, $verbose);

    if (UNIVERSAL::isa($_[0], 'M6::ARP::Sponge')) {
        $self = shift;
        $verbose = $self->is_verbose;
    }
    $verbose = $::opt_verbose if ! $verbose;

    my $level = shift;

    if ($verbose >= $level) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time)), @_;
    }
}

###############################################################################
# $sponge->print_log_level($level, $format, ...);
# print_log_level($level, $format, ...);
###############################################################################
sub print_log_level {
    my ($self, $syslog);
    if ( eval { $_[0]->isa('M6::ARP::Sponge') } ) {
        $self = shift;
        $syslog = $self->syslog_ident;
    }
    $syslog = $0 if ! length $syslog;

    my ($level, $format, @args) = @_;
    if ($self->is_dummy || $self->is_verbose > 0) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time));
        print STDOUT $syslog, "[$$]: ";
        chomp(my $msg = sprintf($format, @args));
        print STDOUT $msg, "\n";
    }
    else {
        openlog($syslog, 'cons,pid', 'user');
        syslog($level, $format, @args);
        closelog;
    }
}

###############################################################################
# $sponge->print_log($format, ...);
#
#   Log $format, ... to syslog. Syntax is identical to that of printf().
#   Prints to STDOUT if verbose or dummy.
###############################################################################
sub print_log {
    my ($self, $format, @args) = @_;
    $self->print_log_level($self->loglevel, $format, @args);
}

###############################################################################
# $sponge->print_notify($format, ...);
# print_notify($fh, $format, ...);
#
#   Notify of sponge actions on the notify handle.
###############################################################################
sub print_notify {
    my ($self, $fh);
    if (UNIVERSAL::isa($_[0], 'M6::ARP::Sponge')) {
        $self = shift;
        $fh = $self->notify;
    }
    elsif (UNIVERSAL::isa($_[0], 'IO::Handle')) {
        $fh = shift;
    }
    return if ! defined $fh;

    my $format = shift @_;

    $fh->print(int(time), ";id=",
            $self->syslog_ident, ";", sprintf($format, @_), "\n");
}

1;
