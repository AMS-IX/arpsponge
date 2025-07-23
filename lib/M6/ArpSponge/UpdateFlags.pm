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
package M6::ArpSponge::UpdateFlags;

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
        ARP_UPDATE_FLAG_NAMES
    );

    our @EXPORT_OK = ( @func, @update_flags );
    our @EXPORT    = ();

    our %EXPORT_TAGS = (
        'func'   => \@func,
        'const'  => \@update_flags,
        'all'    => [ @func, @update_flags ]
    );
}

use constant {
    ARP_UPDATE_REPLY      => 0x01,
    ARP_UPDATE_REQUEST    => 0x02,
    ARP_UPDATE_GRATUITOUS => 0x04,
    ARP_UPDATE_NONE       => 0x00,
    ARP_UPDATE_ALL        => 0x07,
};

my %FLAG_TO_STR = (
    ARP_UPDATE_REPLY()      => 'reply',
    ARP_UPDATE_REQUEST()    => 'request',
    ARP_UPDATE_GRATUITOUS() => 'gratuitous',
);

my %STR_TO_FLAG = (
    'none' => ARP_UPDATE_NONE,
    'all'  => ARP_UPDATE_ALL,
    (reverse %FLAG_TO_STR),
);

sub ARP_UPDATE_FLAG_NAMES {
    return keys %STR_TO_FLAG;
}

sub parse_update_flags {
    my ($arg, @opts) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, @opts);

    if (! defined $arg) {
        return ARP_UPDATE_NONE;
    }

    my $flags = ARP_UPDATE_NONE;

    my $iter = 0;
    for my $method (split(/\s*,\s*/, lc $arg)) {
        $iter++;

        my $negate = 0;
        if ($method =~ s/^\!//) {
            $negate = 1;
        }
        if ($method eq 'none') {
            $method = 'all';
            $negate = !$negate;
        }

        my $int_method = $STR_TO_FLAG{$method};
        if (! defined $int_method ) {
            ${$opts{-err}} = qq/"$method" is not a valid ARP update flag/;
            return;
        }

        if ($negate) {
            $flags &= ARP_UPDATE_ALL & ~int($int_method);
            next;
        }

        $flags |= $int_method;
    }
    return $flags;
}


sub update_flags_to_str {
    my ($arg) = @_;
    my @list;

    $arg //= ARP_UPDATE_NONE;
    for my $mask ( sort keys %FLAG_TO_STR ) {
        if ($arg & $mask) {
            push @list, $FLAG_TO_STR{$mask};
        }
    }
    return @list if @list;
    return ('none');
}

1;

__END__


=head1 NAME

M6::ArpSponge::UpdateFlags - define constants for arpsponge(1) update flags


=head1 SYNOPSIS

    use M6::ArpSponge::UpdateFlags qw( :const );

    say "ARP_UPDATE_REPLY = ", ARP_UPDATE_REPLY;

    use M6::ArpSponge::UpdateFlags qw( :func :const );

    say "Mask reply,gratuitous = ", parse_update_flags("reply,gratuitous");

    my $mask = ARP_UPDATE_ALL;

    printf("Mask 0x%2x = (%s)\n", join(',', update_flags_to_str($mask));

=head1 DESCRIPTION

B<M6::ArpSponge::UpdateFlags> defines constants and conversion functions
for the "ARP update flags" for the L<B<arpsponge>(1)|arpsponge>.

The update flags are stored as a bitmap, with each update method represented
by a distinctive bit position.

=head1 CONSTANTS

=over

=item B<ARP_UPDATE_FLAG_NAMES>

List of of all ARP update flag names (see the constants below).

=item B<ARP_UPDATE_REPLY> (name: C<reply>)

Send unsollicited unicast replies as a way to update ARP caches of peers.

=item B<ARP_UPDATE_REQUEST> (name: C<request>)

Send a (proxy) unicast ARP request.

=item B<ARP_UPDATE_GRATUITOUS> (name: C<gratuitous>)

Send a (proxy) gratuitous ARP request.

=item ARP_UPDATE_NONE (name: C<none>)

Mask with no bits set (in other words, 0).

=item ARP_UPDATE_ALL (name: C<all>)

Mask with all bits set (in other words, the disjunction of all methods).

=back

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

=head1 SEE ALSO

L<B<M6::ArpSponge::Sponge>(3)|M6::ArpSponge::Sponge>.
