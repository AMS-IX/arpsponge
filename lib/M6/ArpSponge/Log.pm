###############################################################################
#
# Logging for the ARP Sponge.
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
package M6::ArpSponge::Log;

use 5.014;
use warnings;
use FindBin;

use M6::ArpSponge;
our $VERSION = $M6::ArpSponge::VERSION;

use Exporter qw( import );
use Time::Piece qw( localtime );
use IO::Select;
use List::Util qw( min max );

use Sys::Syslog qw(
    :macros
    openlog closelog syslog setlogmask
);

BEGIN {
    our @func = qw(
        init_log
        end_log
        print_log
        print_log_level
        log_emerg
        log_alert
        log_crit
        log_err
        log_warning
        log_notice
        log_info
        log_fatal
        log_debug
        log_is_verbose log_verbose log_sverbose
        log_level is_log_level
        is_valid_log_level log_level_to_string
        add_notify remove_notify
        get_log_buffer clear_log_buffer log_buffer_size
    );

    our @macros = qw(
        LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR
        LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
        LOG_MIN_LEVEL LOG_MAX_LEVEL
        LOG_IDENT
    );

    our %EXPORT_TAGS = (
        'standard' => \@func,
        'macros'   => \@macros,
        'func'     => \@func,
        'all'      => [ @func, @macros ],
    );

    our @EXPORT_OK = @{ $EXPORT_TAGS{'all'} };
    our @EXPORT    = @{ $EXPORT_TAGS{'standard'} };
}

my $FACILITY     = 'user';
my $LOGOPT       = 'pid';
my $SYSLOG_IDENT = $FindBin::Script;

#############################################################################
my $Verbose        = 0;
#############################################################################

my $DEFAULT_PRIO   = LOG_NOTICE;

my %STR_TO_LOG_PRIO = (
    'emerg'   => LOG_EMERG,
    'alert'   => LOG_ALERT,
    'crit'    => LOG_CRIT,
    'err'     => LOG_ERR,
    'warning' => LOG_WARNING,
    'notice'  => LOG_NOTICE,
    'info'    => LOG_INFO,
    'debug'   => LOG_DEBUG,
);

my %LOG_PRIO_TO_STR = reverse %STR_TO_LOG_PRIO;

my $MIN_PRIO       = min(keys %LOG_PRIO_TO_STR);
my $MAX_PRIO       = max(keys %LOG_PRIO_TO_STR);

#############################################################################

my $Log_Level       = LOG_NOTICE;
my @Log_Buffer      = ();
my $Log_Buffer_Size = 256;
my $Notify;

sub __log_getset {
    my $ref = $_[0];
    return $$ref if @_ == 1;
    my $old = $$ref;
    $$ref = $_[1];
    return $old;
}

sub end_log {
    $Notify = undef;
    closelog();
}

sub init_log {
    $SYSLOG_IDENT = @_ ? $_[0] : $FindBin::Script;
    $SYSLOG_IDENT =~ s{.*/}{};

    if (defined $Notify) {
        end_log();
    }
    openlog($SYSLOG_IDENT, $LOGOPT, $FACILITY);
    $Notify = IO::Select->new();
    return 1;
}

END {
    end_log();
}

sub LOG_MIN_LEVEL    { return $MIN_PRIO }
sub LOG_MAX_LEVEL    { return $MAX_PRIO }
sub LOG_IDENT        { return $SYSLOG_IDENT }

sub log_buffer_size  {
    my $old = $Log_Buffer_Size;
    if (@_) {
        $Log_Buffer_Size = shift @_;
        my $kill_count = int(@Log_Buffer) - $Log_Buffer_Size;
        if ($kill_count > 0) {
            splice @Log_Buffer, 0, $kill_count;
        }
    }
    return $old;
}

sub log_is_verbose   { return __log_getset(\$Verbose, @_) }
sub is_log_level     { return $_[0] <= $Log_Level }
sub get_log_buffer   { return \@Log_Buffer }
sub clear_log_buffer { @Log_Buffer = () }

sub log_level {
    my $old = $Log_Level;
    if (@_) {
        $Log_Level = shift @_;
        setlogmask(LOG_UPTO($Log_Level));
    }
    return $old;
}

sub log_emerg        { print_log_level(LOG_EMERG,    @_) }
sub log_alert        { print_log_level(LOG_ALERT,    @_) }
sub log_crit         { print_log_level(LOG_CRIT,     @_) }
sub log_err          { print_log_level(LOG_ERR,      @_) }
sub log_warning      { print_log_level(LOG_WARNING,  @_) }
sub log_notice       { print_log_level(LOG_NOTICE,   @_) }
sub log_info         { print_log_level(LOG_INFO,     @_) }
sub log_debug        { print_log_level(LOG_DEBUG,    @_) }

# Return a timestamp string for logging to STDOUT.
sub _log_tstamp {
    return localtime->strftime("%FT%T%z");
}

sub add_notify {
    my ($fh) = @_;
    $Notify->add($fh);
    return $fh;
}

sub remove_notify {
    my ($fh) = @_;
    $Notify->remove($fh);
    return $fh;
}

###############################################################################
# _print_notify($format, ...);
#
#   Print message on the notify handles.
###############################################################################
sub _print_notify($@) {
    my $msg = sprintf(@_);
    for my $fh ($Notify->can_write(0)) {
        $fh->send_log($msg);
    }
}

###############################################################################
# print_log_level($level, $format, ...);
###############################################################################
sub print_log_level {
    my ($level, $format, @args) = @_;

    return if !is_log_level($level);

    # Add message to circular log buffer.
    my $msg = @args ?  sprintf($format, @args) : $format;
    my $is_verbose = log_is_verbose() > 0;
    my $tstamp = _log_tstamp();

    foreach my $line (split(/\n/, $msg)) {
        if (int(@Log_Buffer) >= $Log_Buffer_Size) {
            shift @Log_Buffer;
        }
        push @Log_Buffer, [ time, $line ];

        _print_notify($line);

        if ($is_verbose) {
            printf STDOUT "%s %s[%d]: %s\n", $tstamp, $SYSLOG_IDENT, $$, $line;
        }
        else {
            syslog($level, $line);
        }
    }
    return;
}

###############################################################################
# print_log($format, ...);
#
#   Log $format, ... to syslog. Syntax is identical to that of printf().
#   Prints to STDOUT if verbose or dummy.
###############################################################################
sub print_log {
    my ($format, @args) = @_;
    print_log_level($DEFAULT_PRIO, $format, @args);
}

###############################################################################
# log_fatal($format, ...);
#
#   Log $format, ... to with CRIT priority and die with the same message.
#   Syntax is identical to that of printf().  Prints to STDOUT if verbose
#   or dummy, so you may see duplicate messages in that case.
###############################################################################
sub log_fatal {
    my ($format, @args) = @_;
    if (@args == 0) {
        @args = ($format);
        $format = '%s';
    }
    log_crit($format, @args);
    chomp(my $msg = sprintf($format, @args));
    die "$msg\n";
}

###############################################################################
# log_verbose($level, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#
###############################################################################
sub log_verbose {
    my ($level, @args)  = @_;

    if (log_is_verbose >= $level) {
        print STDOUT _log_tstamp(), ' ', @args;
    }
}

###############################################################################
# log_sverbose($level, $fmt, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#   Functions like sprintf();
#
###############################################################################
sub log_sverbose {
    my ($level, $fmt, @args) = @_;
    if (log_is_verbose >= $level) {
        print STDOUT _log_tstamp(), ' ', sprintf($fmt, @args);
    }
}

sub is_valid_log_level {
    my ($arg, %opts) = @_;
    my $err_s;
    $opts{-err} //= \$err_s;

    if (defined (my $level = $STR_TO_LOG_PRIO{lc $arg}) ) {
        return $level;
    }

    ${$opts{-err}} = q/"$arg" is not a valid syslog level/;
    return;
}

sub log_level_to_string {
    my $level = int($_[0]);

    if ($level > LOG_MAX_LEVEL) {
        return $LOG_PRIO_TO_STR{LOG_MAX_LEVEL()};
    }
    if ($level < LOG_MIN_LEVEL) {
        return $LOG_PRIO_TO_STR{LOG_MIN_LEVEL()};
    }
    return $LOG_PRIO_TO_STR{$level};
}

1;

__END__

=encoding utf8

=head1 NAME

M6::ArpSponge::Log - logging functions for the arpsponge(1)

=head1 SYNOPSIS

    use M6::ArpSponge::Log qw( :macros :func );

    init_log();

    log_level(LOG_NOTICE);

    log_notice("my PID is %d", $$);
    print_log("my PID is %d", $$);
    print_log_level(LOG_NOTICE, "my PID is %d", $$);

    log_is_verbose(1);

    log_verbose("my PID is $$\n");
    log_sverbose("my PID is %d\n", $$");

    end_log();

=head1 DESCRIPTION

The B<M6::ArpSponge::Log> module provides a convenience layer
on top of
L<B<Sys::Syslog>(3)|Sys::Syslog.3>.

It normally logs messages to L<B<syslog>(3)|syslog.3> using
L<B<Sys::Syslog>(3)|Sys::Syslog.3>. It can also send log notifications
to
L<B<M6::ArpSponge::Control::Server>(3)|M6::ArpSponge::Control::Server>
sockets and print messages to F<STDOUT>.

Due to the confusing "lower number is higher priority" semantics,
this module foregoes the term "priority" in favour of "level".

For more elaborate logging of specific event categories, see
L<B<M6::ArpSponge::Event>(3)|M6::ArpSponge::Event.3>
(which uses this module).

=head1 MACROS

Macros can be imported by name or by the C<:macros> or C<:all> tag.

The list of exported macros include the log priority macros from
L<B<Sys::Syslog>(3)|Sys::Syslog>:
B<LOG_EMERG>, B<LOG_ALERT>, B<LOG_CRIT>, B<LOG_ERR>,
<LOG_WARNING>, B<LOG_NOTICE>, B<LOG_INFO>,
and B<LOG_DEBUG>.

In addition to those, the following are defined:

=over

=item B<LOG_MIN_LEVEL>

The lowest numbered log priority
(corresponds to the highest priority, B<LOG_EMERG>).

=item B<LOG_MAX_LEVEL>

The highest numbered log priority
(corresponds to the lowest priority B<LOG_DEBUG>).

=item B<LOG_IDENT>

The "ident" field that is used in L<B<syslog>(3)|syslog> messages.

=back

=head1 FUNCTIONS

Functions can be imported by name or by the C<:func> or C<:all> tag.

=head2 init_log

    init_log();
    init_log($IDENT);

Initialises the logging module. This function should be called before
any other function in this module.

It the module is already initialised, the L<B<end_log>()|/end_log>
function is called first.

If I<$IDENT> is given, then it will be used as the identifier tag
on log messages. Any leading directory path will be stripped.

If I<$IDENT> is not given (or is C<undef>),
L<B<$FindBin::Script>|FindBin/$Script> will be used.

=head2 end_log

    end_log();

Close the logging interface and clear the list of notification handles.

=head2 log_buffer_size

    $NLINES = log_buffer_size();
    $OLD_NLINES = log_buffer_size($NEW_NLINES);

Get or set the number of lines to keep in the internal log buffer.
The internal log buffer is a ring buffer where newer entries will
overwrite the oldest.

If necessary, older entries in the buffer will be purged so that the
number of lines is no more than I<$NEW_NLINES>.

=head2 get_log_buffer

    $BUF_REF = get_log_buffer();

Returns a reference to an array holding the internal log buffer.
The order of elements is oldest to newest.
Each element in the array is a log entry that consists of a time stamp
and a log message:

    $BUF_REF = [
        [ $T0, $STR_0 ],
        [ $T1, $STR_1 ],
        ...
        [ $Tn, $STR_n ],
    ];

The time stamps are expressed as seconds since epoch.

=head2 clear_log_buffer

    clear_log_buffer();

Clear the internal log buffer.

=head2 log_is_verbose

    $LEVEL = log_is_verbose();
    $OLD_LEVEL = log_is_verbose($NEW_LEVEL);

Get or set the verbosity level. Default is 0.
If verbosity is set to any level greater than 0,
then the various logging functions will print
to F<STDOUT> rather than
L<B<syslog>(3)|syslog>.

=head2 log_level

    $LEVEL = log_level();
    $OLD_LEVEL = log_level($NEW_LEVEL);

Get or set the current cut-off level for logging.

If set to I<$LEVEL>, the logging functions will
log messages with a level of I<$LEVEL> or lower
(lower levels corresponding to higher priorities).

The default level is B<LOG_NOTICE>.

=head2 is_log_level

    $BOOL = is_log_level($LEVEL);

Return a true value if a message with priority I<$LEVEL>
would be logged according to the current
L<B<log_level>()|/log_level>.

For instance, if the
L<B<log_level>()|/log_level> is B<LOG_NOTICE>,
then C<log_is_level(LOG_WARNING)> would return true,
but C<log_is_level(LOG_INFO)> would return false.

=head2 log_fatal

    log_fatal($STR);
    log_fatal($FMT, ...);

Calls L<B<log_crit>()|/log_crit> with the given arguments
and then L<B<die>()|perlfunc/die>s with the same message.

=head2 log_emerg

    log_emerg($STR);
    log_emerg($FMT, ...);

Synonymous with C<print_log_level(LOG_EMERG, ...)>.

=head2 log_alert

    log_alert($STR);
    log_alert($FMT, ...);

Synonymous with C<print_log_level(LOG_ALERT, ...)>.

=head2 log_crit

    log_crit($STR);
    log_crit($FMT, ...);

Synonymous with C<print_log_level(LOG_CRIT, ...)>.

=head2 log_err

    log_err($STR);
    log_err($FMT, ...);

Synonymous with C<print_log_level(LOG_ERR, ...)>.

=head2 log_warning

    log_warning($STR);
    log_warning($FMT, ...);

Synonymous with C<print_log_level(LOG_WARNING, ...)>.

=head2 log_notice

    log_notice($STR);
    log_notice($FMT, ...);

Synonymous with C<print_log_level(LOG_NOTICE, ...)>.

=head2 log_info

    log_info($STR);
    log_info($FMT, ...);

Synonymous with C<print_log_level(LOG_INFO, ...)>.

=head2 log_debug

    log_debug($STR);
    log_debug($FMT, ...);

Synonymous with C<print_log_level(LOG_DEBUG, ...)>.

=head2 add_notify

    add_notify($HANDLE);

Adds I<$HANDLE> to the list of notification handles.
<$HANDLE> is assumed
to be a M6::ArpSponge::Control::Server reference.
L<B<M6::ArpSponge::Control::Server>(3)|M6::ArpSponge::Control::Server>
reference.
More specifically, the I<$HANDLE> reference is expected to act like an
IO handle and provide a C<send_log> method.

=head2 remove_notify

    $HANDLE = remove_notify($HANDLE);

Removes I<$HANDLE> from the list of notification handles.
<$HANDLE> is assumed
to be a M6::ArpSponge::Control::Server reference.
L<B<M6::ArpSponge::Control::Server>(3)|M6::ArpSponge::Control::Server>
reference.

Returns I<$HANDLE>.

=head2 print_log_level

    print_log_level($LEVEL, $STR);
    print_log_level($LEVEL, $FMT, ...);

Log a message at priority I<$LEVEL>.
If more multiple message parameters are given, they will be
treated as
L<B<printf>()|perlfunc/printf>
arguments.

=head2 print_log

    print_log($STR);
    print_log($FMT, ...);

Calls L<B<print_log_level>()|/print_log_level>
with the default log level (B<LOG_NOTICE>).

=head2 log_verbose

    log_verbose($LEVEL, $STR, ...);

Prints I<$STR>, ... to F<STDOUT> if verbosity level
(see L<B<log_is_verbose>|/log_is_verbose>) is
at least I<$LEVEL>.

Does not add any timestamp, identifier, or newline.

=head2 log_sverbose

    log_sverbose($LEVEL, $FMT, ...);

Similar to L<B<log_verbose>|/log_verbose>, but the
arguments are treated as L<B<printf>()|perlfunc/printf>
arguments.

=head2 log_level_to_string

    $STR = log_level_to_string( $LEVEL );

Returns the string representation of the numerical I<$LEVEL>.
If I<$LEVEL> is outside the pre-defined bounds, the value
returned is either C<emerg> (I<$LEVEL> is too low), or
C<debug> (if I<$LEVEL> is too high).

=head2 is_valid_log_level

    $LEVEL = is_valid_log_level($STR);
    $LEVEL = is_valid_log_level($STR, -err => \$ERR_STR);

Checks whether I<$STR> represents a valid syslog level.

If an error occurs, and B<-err> is specified, the I<$ERR_STR> scalar will
contain a diagnostic message.

=head1 SEE ALSO

L<B<arpsponge>(1)|arpsponge.1>,
L<B<FindBin>(3p)|FindBin.3>,
L<B<M6::ArpSponge::Control::Server>(3)|M6::ArpSponge::Control::Server.3>,
L<B<M6::ArpSponge::Event>(3)|M6::ArpSponge::Event.3>,
L<B<syslog>(3)|syslog.3>,
L<B<Sys::Syslog>(3p)|Sys::Syslog.3>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>.

=head1 COPYRIGHT

Copyright 2011-2025, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
