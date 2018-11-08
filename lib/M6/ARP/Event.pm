###############################################################################
###############################################################################
#
# Logging for the ARP Sponge.
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
package M6::ARP::Event;

use strict;

use parent qw( Exporter );

use M6::ARP::Log        qw( :standard :macros );

BEGIN {
    our $VERSION   = 1.00;

    our @func = (qw(
            event_log
            event_mask
            event_mask_split
            event_mask_to_str
            event_names event_values
            is_event_mask
            is_valid_event_mask
            parse_event_mask
        ),
        map { "event_$_" }
            qw( emerg alert crit err warning notice info debug )
    );

    our @macros = qw(
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

    our %EXPORT_TAGS = (
        'standard' => [ @func, @macros ],
        'macros'   => \@macros,
        'func'     => \@func,
        'all'      => [ @func, @macros ],
    );
    our @EXPORT_OK = @{ $EXPORT_TAGS{'all'} };
    our @EXPORT    = @{ $EXPORT_TAGS{'standard'} };
}

#############################################################################
use constant {
    EVENT_IO     => 0x0001,
    EVENT_ALIEN  => 0x0002,
    EVENT_SPOOF  => 0x0004,
    EVENT_STATIC => 0x0008,
    EVENT_SPONGE => 0x0010,
    EVENT_CTL    => 0x0020,
    EVENT_STATE  => 0x0040,
    EVENT_ALL    => 0xffff,
    EVENT_NONE   => 0x0000,
};

our %EVENT_MASK_TO_STR = (
    EVENT_IO()     => 'io',
    EVENT_ALIEN()  => 'alien',
    EVENT_SPOOF()  => 'spoof',
    EVENT_STATIC() => 'static',
    EVENT_SPONGE() => 'sponge',
    EVENT_CTL()    => 'ctl',
    EVENT_STATE()  => 'state',
);

our %STR_TO_EVENT_MASK = (
    reverse(%EVENT_MASK_TO_STR),
    'all'  => EVENT_ALL(),
    'none' => EVENT_NONE(),
);

our $Default_Mask = EVENT_ALL();

#############################################################################

my $Event_Mask    = EVENT_ALL();

sub __event_getset {
    my $ref = $_[0];
    if (@_ > 1) {
        my $old = $$ref;
        $$ref = $_[1];
        return $old;
    }
    return $$ref;
}

sub event_names     { return sort keys %STR_TO_EVENT_MASK }
sub event_values    { return sort keys %EVENT_MASK_TO_STR }

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

=item B<event_log> ( I<LOGLEVEL>, I<EVENT>, I<FMT> [, I<ARG>, ... ] )
X<event_log>

Log an I<EVENT> at level I<LOGLEVEL>, with the message specified by
the I<FMT> format string and any additional arguments.

If I<EVENT> matches the current event mask and I<LOGLEVEL> passes
the current log level threshold, the message is logged (L<M6::ARP::Log>),
otherwise it is discarded.

=cut

sub event_log($$@) {
    my ($level, $event, @args) = @_;

    if ( ($event & $Event_Mask) and ($level <= log_level()) ) {
        print_log_level($level, @args);
    }
}

=item B<is_valid_event_mask> ( I<STRING> [, B<-err> =E<gt> I<REF>] )
X<is_valid_event_mask>

Check whether the I<STRING> represents a valid log event.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=cut

sub is_valid_event_mask {
    my ($arg) = @_;
    my $err_s;
    my %opts = (-err => \$err_s, @_[1..$#_]);

    if (defined (my $level = $STR_TO_EVENT_MASK{lc $arg}) ) {
        return $level;
    }

    ${$opts{-err}} = q/"$arg" is not a valid event mask/;
    return;
}

=item X<event_mask_split>B<event_mask_split> ( I<MASK> )

Return an array of the individual event mask values that make
up the compound I<MASK>.

    @list = event_mask_split($mask);
    print map { event_mask_to_str($_)."\n" } @list;

=cut

sub event_mask_split {
    my $mask = int($_[0]);
    return sort grep { $_ & $mask } keys %EVENT_MASK_TO_STR;
}

=item B<parse_event_mask>
( I<ARG> [, B<-err> =E<gt> I<REF>] )
X<parse_event_mask>

Check whether I<ARG> represents a valid list of event masks. Returns an
integer representing the mask on success, C<undef> on error. Note that an
undefined I<ARG> is still valid, and represents the current mask.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=cut

sub parse_event_mask {
    my $arg = $_[0];
    my $err_s;
    my %opts = (-err => \$err_s, @_[1..$#_]);

    return event_mask() if ! defined $arg;
    my $mask;
    for my $event (split(/\s*,\s*/, lc $arg)) {
        my $negate = 0;
        my $cumulative = 0;

        if ($event =~ s/^([\!\+])//) {
            $mask //= event_mask();
            $negate = 1 if $1 eq '!';
        }
        else {
            $mask //= EVENT_NONE;
        }

        if ($event eq 'none') {
            $event = 'all';
            $negate = !$negate;
        }

        if (!exists $STR_TO_EVENT_MASK{$event}) {
            ${$opts{-err}} = qq/"$event" is not a valid event name/;
            return;
        }

        if ($negate) {
            $mask &= ~ int($STR_TO_EVENT_MASK{$event});
            next;
        }
        $mask |= $STR_TO_EVENT_MASK{$event};
    }
    return $mask;
}

=item B<event_mask_to_str> ( I<ARG> )
X<event_mask_to_str>

Translate the bits in I<ARG> to event mask names and return a list of
them.

=cut

sub event_mask_to_str {
    my ($mask) = @_;

    return if !$mask;

    return map { $EVENT_MASK_TO_STR{$_} } event_mask_split($mask);
}

=head1 COPYRIGHT

Copyright 2014-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut

1;
