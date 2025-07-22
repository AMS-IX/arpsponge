##############################################################################
#
# ARP Sponge Flags
#
#   Copyright 2011-2016 AMS-IX B.V.; All rights reserved.
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
# S.Bakker, 2011;
#
###############################################################################
package M6::ArpSponge::Const;

use 5.014;
use warnings;

use M6::ArpSponge;

our $VERSION = $M6::ArpSponge::VERSION;

use Exporter 'import';

BEGIN {
    my @func = qw(
        parse_update_flags update_flags_to_str
    );

    my @update_flags = qw(
        ARP_UPDATE_REPLY
        ARP_UPDATE_REQUEST
        ARP_UPDATE_GRATUITOUS
        ARP_UPDATE_NONE
        ARP_UPDATE_ALL
    );

    our @EXPORT_OK = ( @func, @update_flags );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
        'func'   => \@func,
        'flags'  => \@update_flags,
        'all'    => [ @func, @update_flags ]
    );
}

use constant ARP_UPDATE_REPLY      => 0x01;
use constant ARP_UPDATE_REQUEST    => 0x02;
use constant ARP_UPDATE_GRATUITOUS => 0x04;
use constant ARP_UPDATE_NONE       => 0x00;
use constant ARP_UPDATE_ALL        => 0x07;

our $DEBUG = 0;

our %UPDATE_FLAG_TO_STR = (
    ARP_UPDATE_REPLY()      => 'reply',
    ARP_UPDATE_REQUEST()    => 'request',
    ARP_UPDATE_GRATUITOUS() => 'gratuitous',
);

our %STR_TO_UPDATE_FLAG = (
    'none' => ARP_UPDATE_NONE,
    'all'  => ARP_UPDATE_ALL,
        map { ($UPDATE_FLAG_TO_STR{$_} => $_) } keys %UPDATE_FLAG_TO_STR,
);

sub saydebug(@)   { say @_ if $DEBUG }
sub printdebug(@) { print @_ if $DEBUG }

sub parse_update_flags {
    my ($arg, @opts) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, @opts);

    my $flags = ARP_UPDATE_NONE;

    printdebug "[parse_update_flags] #BEGIN ",
        "[flags=$flags] ";

    if (! defined $arg) {
        saydebug "arg=UNDEF";
        saydebug "[parse_update_flags] #END flags=$flags";
        return $flags;
    }

    saydebug qq{arg="$arg"};

    my $iter = 0;
    for my $method (split(/\s*,\s*/, lc $arg)) {
        $iter++;
        printdebug "[parse_update_flags] #$iter [flags=$flags] ",
            "method=$method";

        my $negate = 0;
        if ($method =~ s/^\!//) {
            $negate = 1;
        }
        if ($method eq 'none') {
            $method = 'all';
            $negate = !$negate;
        }

        saydebug " => [method=$method; negate=$negate]";

        my $int_method = int($STR_TO_UPDATE_FLAG{$method});
        if (! defined $int_method ) {
            ${$opts{-err}} = qq/"$method" is not a valid ARP update flag/;
            return;
        }

        saydebug "[parse_update_flags] #$iter [flags=$flags] ",
            "$method => $int_method";

        if ($negate) {
            my $mask = ~$int_method & ARP_UPDATE_ALL;
            $flags &= $mask;

            saydebug "[parse_update_flags] #$iter [flags=$flags] ",
                "flags = flags & ~($int_method) = ",
                "flags & $mask = ",
                $flags;
            next;
        }
        $flags |= $int_method;
        saydebug "[parse_update_flags] #$iter [flags=$flags] ",
            "flags = flags | $int_method = $flags";
    }
    saydebug "[parse_update_flags] #END [flags=$flags]";
    return $flags;
}

sub update_flags_to_str {
    my ($arg) = @_;
    my @list;

    if ($arg == ARP_UPDATE_NONE) {
        return ('none');
    }
    for my $mask ( sort keys %UPDATE_FLAG_TO_STR ) {
        if ($arg & $mask) {
            push @list, $UPDATE_FLAG_TO_STR{$mask};
        }
    }
    return @list;
}

1;

__END__

=head1 FUNCTIONS

=head2 parse_update_flags

    FLAG_MASK = parse_update_flags(STR);
    FLAG_MASK = parse_update_flags(STR, -err => REF);

Check whether I<ARG> represents a valid list of ARP update flags. Returns an
integer representing the flags on success, C<undef> on error. Note that an
undefined I<ARG> is still valid, and represents C<ARP_UPDATE_NONE>.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=head2 update_flags_to_str

    FLAG_STR_LIST = update_flags_to_str(ARG);

Translate the bits in I<ARG> to ARP update flag names and return a list of
them.

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut

1;
