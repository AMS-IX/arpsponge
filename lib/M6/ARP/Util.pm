##############################################################################
# @(#)$Id$
##############################################################################
#
# ARP Stuff Utility routines
#
# (c) Copyright AMS-IX B.V. 2004-2005;
#
# See the LICENSE file that came with this package.
#
# S.Bakker.
#
###############################################################################
package M6::ARP::Util;

use strict;
use POSIX qw( strftime strtod strtol );

BEGIN {
	use Exporter;

	our $VERSION = 1.04;
	our @ISA = qw( Exporter );

	our @EXPORT_OK = qw( 
            int2ip ip2int hex2ip ip2hex hex2mac mac2hex mac2mac
            format_time relative_time hex_addr_in_net
            is_valid_int is_valid_float
        );
	our @EXPORT    = ();

	our %EXPORT_TAGS = ( 
			'all'    => \@EXPORT_OK
		);
}

=pod

=head1 NAME

M6::ARP::Util - IP, MAC, misc. utility routines

=head1 SYNOPSIS

 use M6::ARP::Util qw( :all );

 $ip  = int2ip( $num );
 $num = ip2int( $ip  );
 $ip  = hex2ip( $hex  );
 $hex = ip2hex( $ip );
 $mac = hex2mac( $hex );
 $hex = mac2hex( $mac );
 $mac = mac2mac( $mac );

 $str = format_time($some_earlier_time);
 $str = relative_time($some_earlier_time);

 $month = is_valid_int($some_string, -min=>1, -max=>12);
 $count = is_valid_int($some_string, -min=>0);

 $chance = is_valid_float($some_string, -min=>0, -max=>1, -inclusive=>1);

=head1 DESCRIPTION

This module defines a number of routines to convert IP and MAC
representations to and from various formats and some miscellaneous
utility functions.

=head1 FUNCTIONS

=over

=cut

###############################################################################

=item X<int2ip>B<int2ip> ( I<num> )

Convert a (long) integer to a dotted decimal IP address. Return the
dotted decimal string.

Example: int2ip(3250751620) returns "193.194.136.132".

=cut

sub int2ip {
	hex2ip(sprintf("%08x", shift @_));
};

###############################################################################

=item X<ip2int>B<ip2int> ( I<IPSTRING> )

Dotted decimal IPv4 address to integer representation.

Example: ip2int("193.194.136.132") returns "3250751620".

=cut

sub ip2int {
	hex(ip2hex(shift @_));
};

###############################################################################

=item X<hex2ip>B<hex2ip> ( I<HEXSTRING> )

Hexadecimal IPv4 address to dotted decimal representation.

Example: hex2ip("c1c28884") returns "193.194.136.132".

=cut

sub hex2ip {
	my $hex = shift;

	$hex =~ /(..)(..)(..)(..)/;
	my $ip = sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));
	return $ip;
};

###############################################################################

=item X<ip2hex>B<ip2hex> ( I<IPSTRING> )

Dotted decimal IPv4 address to hex representation.

Example: ip2hex("193.194.136.132")
returns "c1c28884".

=cut

sub ip2hex {
	return sprintf("%02x%02x%02x%02x", split(/\./, shift));
};

###############################################################################

=item X<hex2mac>B<hex2mac> ( I<HEXSTRING> )

Hexadecimal MAC address to colon-separated hex representation.

Example: hex2mac("a1b20304e5f6")
returns "a1:b2:03:04:e5:f6"

=cut

sub hex2mac {
	my $hex = substr("000000000000".(shift @_), -12);
	$hex =~ /(..)(..)(..)(..)(..)(..)/;
	return sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			hex($1), hex($2), hex($3), hex($4), hex($5), hex($6));
};

###############################################################################

=item X<mac2hex>B<mac2hex> ( I<macstring> )

Any MAC address to hex representation.

Example:
mac2hex("a1:b2:3:4:e5:f6")
returns "a1b20304e5f6".

=cut

sub mac2hex {
	my @mac = split(/[\s\.\-:\-]/, shift);
	return undef if 12 % int(@mac);
	my $digits = int(12 / int(@mac));
	my $hex;
	my $pref = "0" x $digits;
	foreach (@mac) { $hex .= substr($pref.$_, -$digits) }
	return lc $hex;
};

###############################################################################

=item X<mac2mac>B<mac2mac> ( I<MACSTRING> )

Any MAC address to colon-separated hex representation (6 groups of 2 digits).

Example: mac2mac("a1b2.304.e5f6")
returns "a1:b2:03:04:e5:f6"

=cut

sub mac2mac {
	hex2mac(mac2hex($_[0]));
}

###############################################################################

=item X<hex_addr_in_net>B<hex_addr_in_net> ( I<ADDR>, I<NET>, I<PREFIXLEN> )

Check whether I<ADDR> is a part of I<NET>/I<PREFIXLEN>. The
I<ADDR> and I<NET> parameters are IP addresses in hexadecimal
notation.

Returns 1 if I<ADDR> is part of I<NET>/I<PREFIX>, C<undef> otherwise.

=cut 

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

###############################################################################

=item X<is_valid_int>B<is_valid_int> ( I<ARG>
[, B<-min> =E<gt> I<MIN>, B<-max> =E<gt> I<MAX>,
 B<-inclusive> =E<gt> I<BOOL>,
 B<-err> =E<gt> I<REF> ])

Check whether I<ARG> is defined and represents a valid integer. If I<MIN>
and/or I<MAX> are given and not C<undef>, it also checks the boundaries
(by default inclusive). Returns the integer value if the checks are successful,
C<undef> otherwise.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

Example:

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

=cut

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

###############################################################################

=item X<is_valid_float>B<is_valid_float> ( I<ARG>
[, B<-min> =E<gt> I<MIN>, B<-max> =E<gt> I<MAX>,
 B<-inclusive> =E<gt> I<BOOL>,
 B<-err> =E<gt> I<REF> ])

Check whether I<ARG> is defined and represents a valid floating point
number.  If I<MIN> and/or I<MAX> are given and not C<undef>, it also
checks the boundaries (by default inclusive). Returns the value of I<ARG>
if the checks are successful, C<undef> otherwise.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

Example:

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

=cut

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

###############################################################################

=item X<format_time>B<format_time> ( I<TIME> [, I<SEPARATOR>] )

Convert I<TIME> (seconds since epoch) to a "YYYY-mm-dd@HH:MM:SS"
string in the local timezone.
If I<TIME> is undefined or 0, it returns C<never>.

If I<SEPARATOR> is specified, it is used as the string that
separates the date part from the time part (by default an at-sign: "@").

Example: format_time(1300891278)
returns "2011-03-23@15:41:18"

=cut

sub format_time {
	my $time = shift;
    my $separator = @_ ? shift : '@';
    if (defined $time && $time > 0) {
        return strftime("%Y-%m-%d${separator}%H:%M:%S", localtime($time));
    }
    return 'never';
}

=item X<relative_time>B<relative_time> ( I<TIME> [, I<WITH_DIRECTION>] )

Compare I<TIME> (seconds since epoch) against the current time
and return a string that indicates the absolute difference.
If I<TIME> is undefined or 0, it returns C<never>.

If I<WITH_DIRECTION> is true, it will append "ago" or "from now" to the
string. If not given, it defaults to C<true>.

Example: relative_time(time-103745)
returns "1 day 4h49m5s ago"

=cut

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

=back

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<perl(1)|perl>, L<M6::ARP::Sponge(3)|M6::ARP::Sponge>.

=head1 AUTHORS

Steven Bakker at AMS-IX (steven.bakker@ams-ix.net).

=cut
