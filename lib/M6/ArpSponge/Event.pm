###############################################################################
#
# Logging level/event definitions for the ARP Sponge.
#
#   Copyright 2014-2016 AMS-IX B.V.; All rights reserved.
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
# S.Bakker, 2014;
#
###############################################################################
package M6::ArpSponge::Event;

use 5.014;
use warnings;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Exporter 'import';

use M6::ArpSponge::Log qw( :standard :macros );

BEGIN {
    my @func = (qw(
            event_log
            event_mask
            event_mask_to_str
            is_event_mask
            parse_event_mask
        ),
        map { "event_$_" }
            qw( emerg alert crit err warning notice info debug )
    );

    my @const = qw(
        EVENT_NAMES
        EVENT_IO
        EVENT_ALIEN
        EVENT_SPOOF
        EVENT_STATIC
        EVENT_SPONGE
        EVENT_CTL
        EVENT_STATE
        EVENT_ALL
        EVENT_NONE
    );

    our @EXPORT      = ();
    our @EXPORT_OK   = (@func, @const);
    our %EXPORT_TAGS = (
        'const'    => \@const,
        'func'     => \@func,
        'all'      => \@EXPORT_OK,
    );
}

#############################################################################
use constant {
    EVENT_IO     => 0x01,
    EVENT_ALIEN  => 0x02,
    EVENT_SPOOF  => 0x04,
    EVENT_STATIC => 0x08,
    EVENT_SPONGE => 0x10,
    EVENT_CTL    => 0x20,
    EVENT_STATE  => 0x40,
    EVENT_ALL    => 0x7f,
    EVENT_NONE   => 0x00,
};

my %EVENT_MASK_TO_STR = (
    EVENT_IO()     => 'io',
    EVENT_ALIEN()  => 'alien',
    EVENT_SPOOF()  => 'spoof',
    EVENT_STATIC() => 'static',
    EVENT_SPONGE() => 'sponge',
    EVENT_CTL()    => 'ctl',
    EVENT_STATE()  => 'state',
);

my %STR_TO_EVENT_MASK = (
    reverse(%EVENT_MASK_TO_STR),
    'all'  => EVENT_ALL(),
    'none' => EVENT_NONE(),
);

my $Event_Mask   = EVENT_ALL();

#############################################################################

sub __event_getset {
    my $ref = $_[0];
    if (@_ > 1) {
        my $old = $$ref;
        $$ref = $_[1];
        return $old;
    }
    return $$ref;
}

sub EVENT_NAMES     { return sort keys %STR_TO_EVENT_MASK }

sub event_mask      { return __event_getset(\$Event_Mask, @_) }
sub is_event_mask   { return ($_[0] & $Event_Mask) != 0 }

sub event_emerg   { event_log(LOG_EMERG,    $_[0], @_[1..$#_]) }
sub event_alert   { event_log(LOG_ALERT,    $_[0], @_[1..$#_]) }
sub event_crit    { event_log(LOG_CRIT,     $_[0], @_[1..$#_]) }
sub event_err     { event_log(LOG_ERR,      $_[0], @_[1..$#_]) }
sub event_warning { event_log(LOG_WARNING,  $_[0], @_[1..$#_]) }
sub event_notice  { event_log(LOG_NOTICE,   $_[0], @_[1..$#_]) }
sub event_info    { event_log(LOG_INFO,     $_[0], @_[1..$#_]) }
sub event_debug   { event_log(LOG_DEBUG,    $_[0], @_[1..$#_]) }

sub event_log($$@) {
    my ($priority, $event, @args) = @_;

    if ($event & $Event_Mask) {
        print_log_level($priority, @args);
    }
}


sub parse_event_mask {
    my $arg = $_[0];
    my $err_s;
    my %opts = (-err => \$err_s, @_[1..$#_]);

    return event_mask() if ! defined $arg;

    my $mask;
    for my $event (split(/\s*,\s*/, lc $arg)) {
        my $negate = 0;

        if ($event =~ s/^\!//) {
            $negate = 1;
            $mask //= event_mask();
        }
        elsif ($event =~ s/^\+//) {
            $mask //= event_mask();
        }
        else {
            $mask //= EVENT_NONE;
        }

        if ($event eq 'none') {
            $event = 'all';
            $negate = !$negate;
        }

        my $int_event = $STR_TO_EVENT_MASK{$event};
        if (!defined $int_event) {
            ${$opts{-err}} = qq/"$event" is not a valid event name/;
            return;
        }

        if ($negate) {
            $mask &= EVENT_ALL & ~int($int_event);
            next;
        }
        $mask |= $int_event;
    }
    return $mask;
}


sub event_mask_to_str {
    my ($arg) = @_;
    my @list;

    $arg //= EVENT_NONE;
    for my $mask (sort keys %EVENT_MASK_TO_STR) {
        if ($arg & $mask) {
            push @list, $EVENT_MASK_TO_STR{$mask};
        }
    }
    return int(@list) ? @list : ('none');
}

1;
__END__

=encoding utf8

=over

=item B<event_log>
X<event_log>

    event_log(PRIORITY, EVENT, FMT [, ARG, ... ] )

Log an I<EVENT> at level I<PRIORITY>, with the message specified by
the I<FMT> format string and any additional arguments.

If I<EVENT> matches the current event mask the message is logged
with L<B<print_log_level>()|M6::ArpSponge::Log/print_log_level>,
(see L<B<M6::ArpSponge::Log>|M6::ArpSponge::Log>),
otherwise it is discarded.

=item B<parse_event_mask>
( I<ARG> [, B<-err> =E<gt> I<REF>] )
X<parse_event_mask>

Check whether I<ARG> represents a valid list of event masks. Returns an
integer representing the mask on success, C<undef> on error. Note that an
undefined I<ARG> is still valid, and represents the current mask.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=item B<event_mask_to_str> ( I<ARG> )
X<event_mask_to_str>

Translate the bits in I<ARG> to event mask names and return a list of
them.

=back

=head1 COPYRIGHT

Copyright E<copy> 2014-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
