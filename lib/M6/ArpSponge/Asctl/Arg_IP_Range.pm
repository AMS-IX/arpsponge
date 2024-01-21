package M6::ArpSponge::Asctl::Arg_IP_Range;

use 5.014;
use warnings;

use Moo;
extends 'Term::CLI::Argument';

use Carp qw( croak );
use M6::ArpSponge::Util qw( ip2int is_valid_ip );

use namespace::clean;

has network_prefix => (
    is => 'rw',
    required => 1,
    isa => sub {
        eval { $_[0]->isa('NetAddr::IP') }
            or croak "network_prefix must be a NetAddr::IP" 
    }
);

sub check_ip_address_arg {
    my ($self, $arg) = @_;

    my $err = '';
    my $ip = is_valid_ip(
        $arg,
        -network => $self->network_prefix->cidr,
        -err => \$err,
    ) or return $self->set_error($err);

    return $arg;
}

sub expand_ip_chunk {
    my ($self, $ip_s) = @_;

    my $net_prefix = $self->network_prefix;

    my ($lo_s, $hi_s);

    if ($ip_s !~ m{/\d+}) {
        ($lo_s, $hi_s) = split(/-/, $ip_s, 2);

        $self->check_ip_address_arg($lo_s) or return;

        my $lo = ip2int($lo_s);
        #::DEBUG "lo: <$lo_s> $lo";
        my $hi = $lo;
        if ($hi_s) {
            $self->check_ip_address_arg($hi_s) or return;
            $hi = ip2int($hi_s);
            #::DEBUG "hi: <$hi_s> $hi";
        }
        if ($hi < $lo) {
            return $self->set_error(
                qq{'$lo_s-$hi_s' is not a valid IP range} );
        }
        return {
            ip_int_lo => $lo,
            ip_int_hi => $hi,
            ip_str_lo => $lo_s,
            ip_str_hi => $hi_s // $lo_s
        };
    }

    my $cidr = NetAddr::IP->new($ip_s);
    if (!$cidr) {
        return $self->set_error(
                qq{'$ip_s' is not a valid IP range});
    }

    if (!$net_prefix->contains($cidr)) {
        return $self->set_error(
            qq{$ip_s is out of range } . $net_prefix->cidr
        );
        return;
    }

    my ($cidr_first, $cidr_last, $net_first, $net_last) = (
        $cidr->first->addr, $cidr->last->addr,
        $net_prefix->first->addr,
        $net_prefix->last->addr,
    );

    $lo_s = $cidr_first eq $net_first
        ? $cidr_first
        : $cidr->network->addr;

    $hi_s = $cidr_last eq $net_last
        ? $cidr_last
        : $cidr->broadcast->addr;

    return {
        ip_int_lo => ip2int($lo_s),
        ip_int_hi => ip2int($hi_s),
        ip_str_lo => $lo_s,
        ip_str_hi => $hi_s // $lo_s
    };
}

#########################################################################
# Expand the $arg_str as an IP address range:
#
#   192.168.0.4, 192.168.0.5 .. 192.168.0.8
#   192.168.0.4 - 192.168.0.8
#   192.168.0.4 .. 192.168.0.8
#   192.168.0.4/30, 192.168.0.8
#
#########################################################################
sub expand_ip_range {
    my ($self, $arg_str) = @_;

    $arg_str =~ s/\s*(?:-|\.\.|to)\s*/-/g;
    $arg_str =~ s/\s*,\s*/ /g;

    my @args = split(' ', $arg_str);

    #::DEBUG "range: <$arg_str>:", map {" <$_>"} @args;

    my @list;
    for my $ip_s (@args) {
        my $chunk = $self->expand_ip_chunk($ip_s) or return;
        push @list, $chunk;
    }
    return \@list;
}

sub complete {
    my ($self, $text, $state) = @_;

    if (!length $text) {
        return ('IP', 'IP1-IP2', 'IP/PREFIX');
    }
    return;
}

# Steal this bit from asctl...
sub validate {
    my ($self, $text, $state) = @_;

    #::DEBUG "validate: ", join(" ", map { "<$_>" } @_), "\n";

    return $self->expand_ip_range($text);

    my @addr = split(/-/, $text);
    if (@addr == 1) {
        my $ip = NetAddr::IP->new($text);
        return $ip if $ip;
    }
    if (@addr > 2) {
        return $self->set_error('bad IP address range');
    }
    $self->set_error('bad IP address or state');
}

1;
