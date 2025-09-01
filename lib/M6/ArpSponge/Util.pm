##############################################################################
#
# ARP Stuff Utility routines
#
#   Copyright 2005-2016 AMS-IX B.V.; All rights reserved.
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
# S.Bakker.
#
###############################################################################
package M6::ArpSponge::Util;

use 5.014;
use warnings;

use POSIX qw( strtod strtol );
use Time::Piece;
use NetAddr::IP;

BEGIN {
    use Exporter;

    our $VERSION = 1.04;
    our @ISA = qw( Exporter );

    our @EXPORT_OK = qw(
            int2ip ip2int hex2ip ip2hex hex2mac mac2hex mac2mac
            format_time relative_time hex_addr_in_net
            is_valid_int is_valid_float is_valid_ip
            is_valid_bool
            read_from_pipe
        );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
            'all'    => \@EXPORT_OK
        );
}


sub int2ip {
    return hex2ip(sprintf("%08x", $_[0]));
}


sub ip2int {
    return hex(ip2hex($_[0]));
}


sub hex2ip {
    my ($hex) = @_;

    $hex =~ /(..)(..)(..)(..)/;
    my $ip = sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));
    return $ip;
}


sub ip2hex {
    return sprintf("%02x%02x%02x%02x", split(/\./, $_[0]));
}


sub hex2mac {
    my $hex = substr("000000000000$_[0]", -12);
    $hex =~ /(..)(..)(..)(..)(..)(..)/;
    return sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
            hex($1), hex($2), hex($3), hex($4), hex($5), hex($6));
}


sub mac2hex {
    return if !@_ or !defined $_[0];
    my @mac = split(/[\s\.\-:\-]/, $_[0]);
    return undef if 12 % int(@mac);
    my $digits = int(12 / int(@mac));
    my $hex;
    my $pref = '000000000000';
    foreach my $grp (@mac) { $hex .= substr($pref.$grp, -$digits) }
    $hex =~ m{^[[:xdigit:]]+$} or return undef;
    return lc $hex;
}


sub mac2mac {
    hex2mac(mac2hex($_[0]));
}


sub hex_addr_in_net {
    my ($addr, $net, $len) = @_;

    my $nibbles = $len >> 2;

    if ($nibbles) {
        if (substr($addr, 0, $nibbles) ne substr($net, 0, $nibbles)) {
            return;
        }
    }

    $len = $len % 4;

    return 1 if !$len;

    my $mask = (0,8,12,14)[$len];
    # my $mask = 0xf & (0xf << (4-$len));

    my $addr_nibble = hex(substr($addr, $nibbles, 1));
    my $net_nibble  = hex(substr($net,  $nibbles, 1));
    return ($addr_nibble & $mask) == $net_nibble;
}


sub is_valid_int {
    my ($arg, @opt) = @_;
    my $err_s;
    my %opts = (
        -err => \$err_s,
        -min => undef,
        -max => undef,
        -inclusive => 1,
        @opt,
    );

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = 'not a valid integer';
        return;
    }

    my ($num, $unparsed) = strtol($arg);
    if ($unparsed) {
        ${$opts{-err}} = 'not a valid integer';
        return;
    }

    if (defined(my $min = $opts{-min})) {
        my $min_ok = $opts{-inclusive} ? $num >= $min : $num > $min;
        if (!$min_ok) {
            ${$opts{-err}} = 'number too small';
            return;
        }
    }
    if (defined(my $max = $opts{-max})) {
        my $max_ok = $opts{-inclusive} ? $num <= $max : $num < $max;
        if (!$max_ok) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }

    ${$opts{-err}} = '';
    return $num;
}


sub is_valid_float {
    my ($arg, @opt) = @_;
    my $err_s;
    my %opts = (
        -err => \$err_s,
        -min => undef,
        -max => undef,
        -inclusive => 1,
        @opt,
    );

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }

    my ($num, $unparsed) = strtod($arg);
    if ($unparsed) {
        ${$opts{-err}} = 'not a valid number';
        return;
    }

    if (defined(my $min = $opts{-min})) {
        my $min_ok = $opts{-inclusive} ? $num >= $min : $num > $min;
        if (!$min_ok) {
            ${$opts{-err}} = 'number too small';
            return;
        }
    }
    if (defined(my $max = $opts{-max})) {
        my $max_ok = $opts{-inclusive} ? $num <= $max : $num < $max;
        if (!$max_ok) {
            ${$opts{-err}} = 'number too large';
            return;
        }
    }

    ${$opts{-err}} = '';
    return $num;
}


sub is_valid_bool {
    my ($arg, @opt) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, @opt);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = q/not a valid boolean/;
        return;
    }

    if ($arg =~ /^(?:[+-]?)\d+$/) {
        return int($arg)>0 ? 1 : 0;
    }

    return 1 if $arg =~ /^true|yes|on$/i;
    return 0 if $arg =~ /^false|no|off$/i;

    ${$opts{-err}} = qq/not a valid boolean/;
    return;
}


sub is_valid_ip {
    my ($arg, @opt) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, -network => undef, @opt);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{-err}} = q{not a valid IPv4 address};
        return;
    }

    my $ip = $arg =~ /^\d/ ? NetAddr::IP->new($arg) : undef;
    if (!$ip) {
        ${$opts{-err}} = q{not a valid IPv4 address};
        return;
    }

    return $ip->addr() if !$opts{-network};

    if (my $net = NetAddr::IP->new($opts{-network})) {
        return $ip->addr() if $net->contains($ip);
        ${$opts{-err}} = q{out of range }.$net->cidr();
        return;
    }
    ${$opts{-err}} = qq/** INTERNAL ** is_valid_ip(): -network /
                   . qq/argument "$opts{-network}" is not valid/;
    warn ${$opts{-err}};
    return;
}


sub format_time {
    my ($time, $separator) = @_;
    if (defined $time && $time > 0) {
        $separator //= '@';
        return localtime($time)->strftime("%F${separator}%T%z");
    }
    return 'never';
}


sub relative_time {
    my $time = $_[0];
    return 'never' if !$time;

    my $with_direction = @_ > 1 ? $_[1] : 1;
    my $now  = time;

    my $diff = abs(time - $time);
    my $day = int($diff / (24*3600));
    $diff %= 24*3600;

    my $str;
    if ($day) {
        $str = "$day day".($day==1?'':'s');
        $str .= ", ";
    }

    $str .= gmtime($diff)->strftime("%H:%M:%S");

    if ($with_direction) {
        my $direction = $time > $now ? 'from now' : 'ago';
        $str .= " $direction";
    }
    return $str;
}


sub read_from_pipe {
    my @cmd = @_;

    open my $save_err, '>&', \*STDERR;
    open STDERR, '>', '/dev/null';

    open my $fh, '-|', @cmd;

    my $stdout = do { local($/); <$fh> };
    close $fh;

    open STDERR, '>&', $save_err;

    return $stdout;
}

1;

__END__

=encoding utf8

=head1 NAME

M6::ArpSponge::Util - IP, MAC, misc. utility routines

=head1 SYNOPSIS

  use M6::ArpSponge::Util qw( :all );
 
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
 
  $bool = is_valid_bool($some_expr);

=head1 DESCRIPTION

This module defines a number of routines to convert IP and MAC
representations to and from various formats and some miscellaneous
utility functions.

=head1 FUNCTIONS

=head2 int2ip

  $IP_STR = int2ip($NUM);

Converts a (long) integer to a dotted decimal IPv4 address.
Returns the dotted decimal string.

Example:

  int2ip(3405803777) eq '203.0.113.1'

=head2 ip2int

  $NUM = ip2int($IP_STR);

Converts a dotted decimal IPv4 address to an integer and
returns the result.

Example:

  ip2int('203.0.113.1') == 3405803777

=head2 hex2ip

  $IP_STR = hex2ip($HEX_STRING)

Converts a hexadecimal IPv4 address string
to dotted decimal representation
and returns the result.

Example:

  hex2ip('cb007101') eq '203.0.113.1'

=head2 ip2hex

  $HEX_IP = ip2hex($IP_STR);

Converts a
dotted decimal IPv4 address
to a hexadecimal IPv4 address
and returns the result.

Example:

  ip2hex('203.0.113.1') eq 'cb007101'

=head2 hex2mac

  $MAC_STR = hex2mac($HEX_MAC);

Converts a hexadecimal MAC address string
to a colon-separated hex representation
and returns the result.

Example:

  hex2mac('1ab20304e5f6') eq '1a:b2:03:04:e5:f6'

=head2 mac2hex

  $HEX_MAC = mac2hex($MAC_STR);

Example:

  mac2hex('1a:b2:3:4:e5:f6') eq '1ab20304e5f6'
  mac2hex('1AB2-0304-e5f6')  eq '1ab20304e5f6'

=head2 mac2mac

  $MAC_STR_CANONICAL = mac2mac($MAC_STR);

Any MAC address to colon-separated hex representation (6 groups of 2 digits).

Example:

  mac2mac('1ab2.304.e5f6') eq '1a:b2:03:04:e5:f6'

=head2 hex_addr_in_net

  $BOOL = hex_addr_in_net($ADDR, $NET, $PREFIX_LEN)

Check whether I<$IP> is a part of I<$NET>/I<$PREFIXLEN>.

The I<$ADDR> and I<$NET> parameters are IP addresses in
hexadecimal notation.

Returns true if I<$ADDR> is part of I<$NET>/I<$PREFIX>, false otherwise.

=head2 is_valid_int

  $INT = is_valid_int(
      $ARG,
      [ -min       => $MIN,  ]
      [ -max       => $MAX,  ]
      [ -inclusive => $BOOL, ]
      [ -err       => \$ERR  ]
  );

Checks whether I<$ARG> is defined and represents a valid integer.
If C<-min> and/or I<-max> are given and not C<undef>,
it also checks the boundaries
(by default inclusive, but this can be changed by specifying
C<-inclusive> to be 0).

Returns the integer value if the checks are successful, C<undef> otherwise.

If an error occurs and C<-err> is specified,
the I<$ERR> scalar will contain a diagnostic message.

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

 if ($val = is_valid_int($arg, -min => 1, -max => 12, -err => \$err)) {
    ...
 }
 else {
    say STDERR "bad month number: $err";
 }

=back

=head2 is_valid_float

  $NUM = is_valid_float(
      $ARG,
      [ -min       => $MIN,  ]
      [ -max       => $MAX,  ]
      [ -inclusive => $BOOL, ]
      [ -err       => \$ERR  ]
  );

Checks whether I<$ARG> is defined and represents a valid floating point
number.
If C<-min> and/or I<-max> are given and not C<undef>,
it also checks the boundaries
(by default inclusive, but this can be changed by specifying
C<-inclusive> to be 0).

Returns the numerical value if the checks are successful,
C<undef> otherwise.

If an error occurs and C<-err> is specified,
the I<$ERR> scalar will contain a diagnostic message.

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

 if ($val = is_valid_float($arg, -min => 0, -max => 1, -err => \$err)) {
    ...
 }
 else {
    say STDERR "bad probability: $err";
 }

=back

=head2 is_valid_bool

    $BOOL = is_valid_bool($ARG> [, -err => \$ERR])

Checks whether I<$ARG> is defined and represents a valid boolean value.
Acceptable values are:

=over

=item I<true>:

C<true>, C<yes>, C<on>, I<$ARG E<gt> 0>.

=item I<false>:

C<false>, C<no>, C<off>, I<$ARG E<lt>= 0>.

=back

Returns C<1> for I<true>, C<0> for I<false>, or I<undef> on error.

If an error occurs and C<-err> is specified,
the I<$ERR> scalar will contain a diagnostic message.

=head2 is_valid_ip

  $IP_STR = is_valid_ip(
      $ARG, 
      [ -network => $CIDR, ]
      [ -err     => \$ERR  ]
  );

Check whether I<$ARG> is defined and represents a valid IPv4 address.
If C<-network> is given,
it also ensures that the address is part of I<$CIDR>.
Returns the value of I<$ARG> if the checks are successful,
C<undef> otherwise.

If an error occurs and C<-err> is specified,
the I<$ERR> scalar behind I<REF> will contain a diagnostic message.

=head2 format_time

  $TIME_STR = format_time($TIME);
  $TIME_STR = format_time($TIME, $SEPARATOR);

Converts I<$TIME> (seconds since epoch) to an ISO-8601
string in the local timezone.
If I<$TIME> is undefined or 0, it returns C<never>.

If I<$SEPARATOR> is specified, it is used as the string that
separates the date part from the time part (by default C<T>).

Example:

  say format_time(1300891278);

Will print:

  2011-03-23T15:41:18+0100

=head2 relative_time

  $REL_STR = relative_time($TIME);
  $REL_STR = relative_time($TIME, $WITH_DIRECTION);

Compares I<$TIME> (seconds since epoch) against the current time
and return a string that indicates the absolute difference.
If I<$TIME> is undefined or 0, it returns C<never>.

If I<$WITH_DIRECTION> is not specified, or evaluates to true,
the string C<ago> or C<from now> will be appended to the result.

Example:

  relative_time(time-103745)    eq '1 day, 04:49:05 ago'
  relative_time(time-103745, 0) eq '1 day, 04:49:05'

=head2 read_from_pipe

  $STDOUT = read_from_pipe($CMD, [$ARG, ...])

Executes I<$CMD> with any given I<$ARG>s and catch F<STDOUT>,
discarding F<STDERR>.

The I<$?> variable will contain the exit code of I<$CMD>.

=head1 EXAMPLE

See the L</SYNOPSIS> section.

=head1 SEE ALSO

L<B<arpsponge>(1)|arpsponge.1>,
L<B<M6::ArpSponge::Sponge>(3)|M6::ArpSponge::Sponge.3>.

=head1 AUTHORS

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>.

=head1 COPYRIGHT

Copyright E<copy> 2005-2025, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
