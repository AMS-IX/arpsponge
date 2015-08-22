##############################################################################
#
# ARP Sponge Utility routines
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
# Description:  See the POD information at the end of this file.
# Author:       S.Bakker.
#
###############################################################################
package M6::ARPSponge::Util;

use Modern::Perl;

use POSIX qw( strftime strtod strtol );
use NetAddr::IP;

BEGIN {
    use parent qw( Exporter );

    our $VERSION = '1.00';

    our @EXPORT_OK = qw( 
        int2ip ip2int hex2ip ip2hex hex2mac mac2hex mac2mac
        format_time relative_time hex_addr_in_net
        is_valid_int is_valid_float is_valid_ip
        arpflags2int int2arpflags
    );

    our @EXPORT = ();

    our %EXPORT_TAGS = ( 
        'all'    => \@EXPORT_OK
    );
}


sub int2ip {
	hex2ip(sprintf("%08x", shift @_));
}


sub ip2int {
	hex(ip2hex(shift @_));
}


sub hex2ip {
	my $hex = shift;

	$hex =~ /(..)(..)(..)(..)/;
	my $ip = sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));
	return $ip;
}


sub ip2hex {
	return sprintf("%02x%02x%02x%02x", split(/\./, shift));
}


sub hex2mac {
	my $hex = substr("000000000000".(shift @_), -12);
	$hex =~ /(..)(..)(..)(..)(..)(..)/;
	return sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			hex($1), hex($2), hex($3), hex($4), hex($5), hex($6));
}


sub mac2hex {
    return if !@_ or !defined $_[0];
	my @mac = split(/[\s\.\-:\-]/, shift);
	return undef if 12 % int(@mac);
	my $digits = int(12 / int(@mac));
	my $hex;
	my $pref = "0" x $digits;
	foreach (@mac) { $hex .= substr($pref.$_, -$digits) }
	return lc $hex;
}


sub mac2mac {
	hex2mac(mac2hex($_[0]));
}


sub hex_addr_in_net {
    my ($addr, $net, $len) = @_;

    my $nibbles = $len >> 2;

    #print STDERR "$nibbles nibbles\n";

    if ($nibbles) {
        if (substr($addr, 0, $nibbles) ne substr($net, 0, $nibbles)) {
            return;
        }
    }

    $len = $len % 4;

    #print STDERR "$len bits leftover\n";
    return 1 if !$len;

    #my $mask = 0xf & ~( 1<<(4-$len) - 1 );
    my $mask = (0,8,12,14,15)[$len];
    my $addr_nibble = hex(substr($addr, $nibbles, 1));
    my $net_nibble  = hex(substr($net,  $nibbles, 1));
    #print STDERR "addr:$addr_nibble net:$net_nibble mask:$mask\n";
    return ($addr_nibble & $mask) == $net_nibble;
}


sub is_valid_int {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, -min => undef, -max => undef, -inclusive => 1, @_);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }

    my ($num, $unparsed) = strtol($arg);
    if ($unparsed) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }
    elsif ($opts{-inclusive}) {
        if (defined $opts{-min} && $num < $opts{-min}) {
            ${$opts{-err}} = 'number too small';
            return;
        }
        if (defined $opts{-max} && $num > $opts{-max}) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }
    else {
        if (defined $opts{-min} && $num <= $opts{-min}) {
            ${$opts{-err}} = 'number too small';
            return;
        }
        if (defined $opts{-max} && $num >= $opts{-max}) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }
    ${$opts{-err}} = '';
    return $num;
}


sub is_valid_float {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, -min => undef, -max => undef, -inclusive => 1, @_);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }

    my ($num, $unparsed) = strtod($arg);
    if ($unparsed) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }
    elsif ($opts{-inclusive}) {
        if (defined $opts{-min} && $num < $opts{-min}) {
            ${$opts{-err}} = 'number too small';
            return;
        }
        if (defined $opts{-max} && $num > $opts{-max}) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }
    else {
        if (defined $opts{-min} && $num <= $opts{-min}) {
            ${$opts{-err}} = 'number too small';
            return;
        }
        if (defined $opts{-max} && $num >= $opts{-max}) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }
    ${$opts{-err}} = '';
    return $num;
}


sub is_valid_ip {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, -network => undef, @_);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = q/"" is not a valid IPv4 address/;
        return;
    }

    my $ip = NetAddr::IP->new($arg);
    if (!$ip) {
        ${$opts{-err}} = qq/"$arg" is not a valid IPv4 address/;
        return;
    }
    
    return $ip->addr() if !$opts{-network};
   
    if (my $net = NetAddr::IP->new($opts{-network})) {
        return $ip->addr() if $net->contains($ip);
        ${$opts{-err}} = qq/$arg is out of range /.$net->cidr();
        return;
    }
    else {
        ${$opts{-err}} = qq/** INTERNAL ** is_valid_ip(): -network /
                       . qq/argument "$opts{-network}" is not valid/;
        warn ${$opts{-err}};
        return;
    }
}


sub format_time {
	my $time = shift;
    my $separator = @_ ? shift : '@';
    if (defined $time && $time > 0) {
        return strftime("%Y-%m-%d${separator}%H:%M:%S", localtime($time));
    }
    return 'never';
}

sub relative_time {
	my $time = shift;
    my $with_direction = @_ ? shift : 1;
    my $now  = time;

    return 'never' if !$time;

    my $direction = $time > $now ? 'from now' : 'ago';
    my $diff = abs(time - $time);

    my $day = int($diff / (24*3600));
    $diff %= 24*3600;

    my $str;
    if ($day) {
        $str = "$day day".($day==1?'':'s');
        $str .= ", ";
    }

    $str .= strftime("%H:%M:%S", gmtime($diff));
    
    if ($with_direction) {
        $str .= " $direction";
    }
    return $str;
}

1;

__END__

=pod

=head1 NAME

M6::ARPSponge::Util - IP, MAC, misc. utility routines

=head1 SYNOPSIS

 use M6::ARPSponge::Util qw( :all );

 $ip  = int2ip( $num );
 $num = ip2int( $ip  );
 $ip  = hex2ip( $hex  );
 $hex = ip2hex( $ip );
 $mac = hex2mac( $hex );
 $hex = mac2hex( $mac );
 $mac = mac2mac( $mac );

 $str = format_time($some_earlier_time);
 $str = relative_time($some_earlier_time);

 $in_net = hex_addr_in_net($hex, $hexnet, $prefixlen );

 $month = is_valid_int($some_string, -min=>1, -max=>12);
 $count = is_valid_int($some_string, -min=>0);

 $chance = is_valid_float($some_string, -min=>0, -max=>1, -inclusive=>1);

 $ip_string = is_valid_ip($some_string, -network=>'192.168.1.0/24');

=head1 DESCRIPTION

This module defines a number of routines to convert IP and MAC
representations to and from various formats and some miscellaneous
utility functions.

No functions are exported by default. Functions can be imported either
individually by name, or by using the C<:all> tag.

=head1 FUNCTIONS

=over

=item B<int2ip> ( I<num> )
X<int2ip>

Convert a (long) integer to a dotted decimal IP address. Return the
dotted decimal string.

Example:

  int2ip(3250751620)
  
Returns

  '193.194.136.132'

=item B<ip2int> ( I<IPSTRING> )
X<ip2int>

Dotted decimal IPv4 address to integer representation.

Example:

  ip2int("193.194.136.132")
  
Returns:

  3250751620

=item B<hex2ip> ( I<HEXSTRING> )
X<hex2ip>

Hexadecimal IPv4 address to dotted decimal representation.

Example:

  hex2ip("c1c28884")
  
Returns:

  '193.194.136.132'

=item B<ip2hex> ( I<IPSTRING> )
X<ip2hex>

Dotted decimal IPv4 address to hex representation.

Example:

  ip2hex("193.194.136.132")

Returns:

  'c1c28884'

=item B<hex2mac> ( I<HEXSTRING> )
X<hex2mac>

Hexadecimal MAC address to colon-separated hex representation.

Example:

  hex2mac("a1b20304e5f6")

Returns:

  'a1:b2:03:04:e5:f6'

=item B<mac2hex> ( I<macstring> )
X<mac2hex>

Any MAC address to hex representation.

Example:

  mac2hex("a1:b2:3:4:e5:f6")

Returns:

  'a1b20304e5f6'

=item X<mac2mac>B<mac2mac> ( I<MACSTRING> )
X<mac2mac>

Any MAC address to colon-separated hex representation (6 groups of 2 digits).

Example:

  mac2mac("a1b2.304.e5f6")

Returns:

  'a1:b2:03:04:e5:f6'

=item B<hex_addr_in_net> ( I<ADDR>, I<NET>, I<PREFIXLEN> )
X<hex_addr_in_net>

Check whether I<ADDR> is a part of I<NET>/I<PREFIXLEN>. The
I<ADDR> and I<NET> parameters are IP addresses in hexadecimal
notation.

Returns 1 if I<ADDR> is part of I<NET>/I<PREFIX>, C<undef> otherwise.

=item B<is_valid_int> ( I<ARG> [, I<OPTS> ] )
X<is_valid_int>

Check whether I<ARG> is defined and represents a valid integer. If I<MIN>
and/or I<MAX> are given and not C<undef>, it also checks the boundaries
(by default inclusive). Returns the integer value if the checks are successful,
C<undef> otherwise.

=item B<is_valid_int> ( I<ARG> [, I<OPTS> ] )
X<is_valid_int>

=over

=item I<OPTS>:

=over

=item B<-min> =E<gt> I<MIN>

=item B<-max> =E<gt> I<MAX>

=item B<-inclusive> =E<gt> I<BOOL>

=item B<-err> =E<gt> I<REF>

=back

=back

Check whether I<ARG> is defined and represents a valid integer. If I<MIN>
and/or I<MAX> are given and not C<undef>, it also checks the boundaries
(by default inclusive). Returns the integer value if the checks are successful,
C<undef> otherwise.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

Examples:

=over

=item Check for a positive integer:

 # check for >= 1
 if ($val = is_valid_int($arg, -min => 1)) {
    ...
 }

 # check for > 0
 if ($val = is_valid_int($arg, -min => 0, -inclusive => 0)) {
    ...
 }


=item Check for a negative integer:

 if ($val = is_valid_int($arg, -max => -1)) {
    ...
 }

=item Check for a valid month number:

 if ($val = is_valid_int($arg, -min => 1, -max => 12)) {
    ...
 }

=back

=item B<is_valid_float> ( I<ARG> [, I<OPTS> ] )
X<is_valid_float>

=over

=item I<OPTS>:

=over

=item B<-min> =E<gt> I<MIN>

=item B<-max> =E<gt> I<MAX>

=item B<-inclusive> =E<gt> I<BOOL>

=item B<-err> =E<gt> I<REF>

=back

=back

Check whether I<ARG> is defined and represents a valid floating point
number.  If I<MIN> and/or I<MAX> are given and not C<undef>, it also
checks the boundaries (by default inclusive). Returns the value of I<ARG>
if the checks are successful, C<undef> otherwise.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

Examples:

=over

=item Check for a positive float:

 # check for > 0
 if ($val = is_valid_float($arg, -min => 0, -inclusive => 0)) {
    ...
 }


=item Check for a negative float:

 if ($val = is_valid_float($arg, -max => 0, -inclusive => 0)) {
    ...
 }

=item Check for a valid stochastic value:

 if ($val = is_valid_float($arg, -min => 0, -max => 1)) {
    ...
 }

=back

=item B<is_valid_ip> ( I<ARG> [, I<OPTS> ] )
X<is_valid_ip>

=over

=item I<OPTS>:

=over

=item B<-network> =E<gt> I<CIDR>

=item B<-err> =E<gt> I<REF>

=back

=back

Check whether I<ARG> is defined and represents a valid IPv4 address.
If I<CIDR> is given, it also checks whether the address is part
of I<CIDR>.  Returns the value of I<ARG> if the checks are successful,
C<undef> otherwise.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=item B<format_time> ( I<TIME> [, I<SEPARATOR>] )
X<format_time>

Convert I<TIME> (seconds since epoch) to a "YYYY-mm-dd@HH:MM:SS"
string in the local timezone.
If I<TIME> is undefined or 0, it returns C<never>.

If I<SEPARATOR> is specified, it is used as the string that
separates the date part from the time part (by default an at-sign: "@").

Example:

  format_time(1300891278)

Returns:

  2011-03-23@15:41:18

=item B<relative_time> ( I<TIME> [, I<WITH_DIRECTION>] )
X<relative_time>

Compare I<TIME> (seconds since epoch) against the current time
and return a string that indicates the absolute difference.
If I<TIME> is undefined or 0, it returns C<never>.

If I<WITH_DIRECTION> is true, it will append C<ago> or C<from now>
to the string. If not given, it defaults to C<true>.

Example:

  relative_time(time-103745)

Returns:

  1 day 4h49m5s ago

=back

=head1 EXAMPLE

See the L</FUNCTIONS> and L</SYNOPSIS> sections.

=head1 SEE ALSO

L<M6::ARPSponge>(3).

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker AT ams-ix.net).

=head1 COPYRIGHT

Copyright 2005-2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
