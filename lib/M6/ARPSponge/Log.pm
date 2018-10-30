###############################################################################
#
# Logging for the ARP Sponge.
#
#   Copyright (c) 2011 AMS-IX B.V.; All rights reserved.
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
package M6::ARPSponge::Log;

use Modern::Perl;

use parent qw( Exporter );

use FindBin;
use POSIX               qw( strftime );
use Sys::Syslog         qw( :standard :macros );

BEGIN {
    our $VERSION   = 1.00;

    our @func = qw(
        init_log
        log_print
        log_print_prio
        log_emerg
        log_alert
        log_crit
        log_err
        log_warning
        log_notice
        log_info
        log_fatal
        log_debug
        log_verbosity log_verbose log_sverbose
        log_threshold pass_log_threshold
        is_valid_log_prio log_prio_to_string
        add_notify remove_notify print_notify
        get_log_buffer clear_log_buffer log_buffer_size
    );

    our @macros = qw(
        LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR
        LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
    );

    our %EXPORT_TAGS = (
        'standard' => \@func,
        'macros'   => \@macros,
        'vars'     => \@vars,
        'func'     => \@func,
        'all'      => [ @func, @macros, @vars ],
    );
    our @EXPORT_OK = @{ $EXPORT_TAGS{'all'} };
    our @EXPORT    = @{ $EXPORT_TAGS{'standard'} };
}

#############################################################################
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

#############################################################################
my $Verbose           = 0;
my $Default_Priority  = LOG_NOTICE;
my $Syslog_Ident      = $FindBin::Script;
my $Syslog_Facility   = 'user';
my $Syslog_Options    = 'pid';

#############################################################################

my $Log_Threshold   = LOG_NOTICE;
my @Log_Buffer      = ();
my $Log_Buffer_Size = 256;
my $Notify;

END {
    closelog;
}

sub __log_getset {
    my $ref = shift;
    if (@_) {
        my $old = $$ref;
        $$ref = shift;
        return $old;
    }
    return $$ref;
}

sub __log_getset_reopen {
    my $ref = shift;
    my $old = __log_getset($ref, @_);
    
    if ($$ref ne $old) {
        closelog;
        openlog(syslog_ident, syslog_options, syslog_facility);
    }
    return $old;
}

sub init_log {
    syslog_ident(shift @_) if @_;
    openlog(syslog_ident, syslog_options, syslog_facility);
    $Notify = IO::Select->new();
    clear_log_buffer();
    return 1;
}

sub log_buffer_size {
    my $r = __log_getset(\$Log_Buffer_Size, @_);

    if ($Log_Buffer_Size < $r) {
        splice @Log_Buffer, 0, -$Log_Buffer_Size;
    }
    return $r;
}

sub syslog_facility { return __log_getset_reopen(\$Syslog_Facility, @_) }
sub syslog_ident    { return __log_getset_reopen(\$Syslog_Ident, @_) }
sub syslog_options  { return __log_getset_reopen(\$Syslog_Options, @_) }

sub log_verbosity       { return __log_getset(\$Verbose, @_) }
sub log_threshold       { return __log_getset(\$Log_Threshold, @_) }
sub pass_log_threshold  { return $_[0] <= $Log_Threshold }

sub get_log_buffer      { return \@Log_Buffer }
sub clear_log_buffer    { @Log_Buffer = () }

sub log_emerg           { log_print_prio(LOG_EMERG,    @_) }
sub log_alert           { log_print_prio(LOG_ALERT,    @_) }
sub log_crit            { log_print_prio(LOG_CRIT,     @_) }
sub log_err             { log_print_prio(LOG_ERR,      @_) }
sub log_warning         { log_print_prio(LOG_WARNING,  @_) }
sub log_notice          { log_print_prio(LOG_NOTICE,   @_) }
sub log_info            { log_print_prio(LOG_INFO,     @_) }
sub log_debug           { log_print_prio(LOG_DEBUG,    @_) }

###############################################################################
# add_notify($fh);
#
#   Add $fh to the list of notification handles. $fh is assumed
#   to be a M6::ARPSponge::Control::Server reference.
#
#   Returns the $fh argument.
#
###############################################################################
sub add_notify {
    my $fh = shift;
    $Notify->add($fh);
    return $fh;
}

###############################################################################
# remove_notify($fh);
#
#   Remove $fh from the list of notification handles. $fh is assumed
#   to be a M6::ARPSponge::Control::Server reference.
#
#   Returns the $fh argument.
#
###############################################################################
sub remove_notify {
    my $fh = shift;
    $Notify->remove($fh);
    return $fh;
}

###############################################################################
# print_notify($format, ...);
#
#   Print message on the notify handles.
###############################################################################
sub print_notify($@) {
    $Notify || return;

    my $format = shift;
    my $msg = sprintf($format, @_);
    for my $fh ($Notify->can_write(0)) {
        $fh->send_log($msg);
    }
}

###############################################################################
# log_print_prio($prio, $format, ...);
###############################################################################
sub log_print_prio($$@) {
    my ($prio, $format, @args) = @_;

    return if $prio > $Log_Threshold;

    # Add message to circular log buffer.
    foreach (split(/\n/, sprintf($format, @args))) {
        push @Log_Buffer, [ time, $_ ];
    }

    if (int(@Log_Buffer) > $Log_Buffer_Size) {
        splice @Log_Buffer, 0, -$Log_Buffer_Size;
    }

    if ($Verbose > 0) {
        my $head = strftime("%Y-%m-%d %H:%M:%S ", localtime(time))
                 . $Syslog_Ident . "[$$]:";
        print STDOUT map { "$head $_\n" } split(/\n/, sprintf($format, @args));
    }
    else {
        syslog($prio, $format, @args);
    }
    print_notify($format, @args);
}

###############################################################################
# log_print($format, ...);
#
#   Log $format, ... to syslog. Syntax is identical to that of printf().
#   Prints to STDOUT if verbose or dummy.
###############################################################################
sub log_print {
    my ($format, @args) = @_;
    log_print_prio($Default_Priority, $format, @args);
}

###############################################################################
# log_fatal($format, ...);
#
#   Log $format, ... to syslog and dies() with the same message. Syntax is
#   identical to that of printf().  Prints to STDOUT if verbose or dummy,
#   so you may see duplicate messages in that case.
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
sub log_verbose($@) {
    my ($level, @args)  = @_;

    if (log_verbosity >= $level) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time)), @args;
    }
}

###############################################################################
# log_sverbose($level, $fmt, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#   Functions like sprintf();
#
###############################################################################
sub log_sverbose($@) {
    my ($level, $fmt, @args) = @_;
    if (log_verbosity >= $level) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time)),
                     sprintf($fmt, @args);
    }
}

sub is_valid_log_prio {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, @_);

    if (defined (my $prio = $STR_TO_LOG_PRIO{lc $arg}) ) {
        return $prio;
    }

    ${$opts{-err}} = q/"$arg" is not a valid syslog priority/;
    return;
}

sub log_prio_to_string {
    my $prio = int(shift);

    if ($prio > LOG_DEBUG()) {
        $prio = LOG_DEBUG();
    }
    elsif ($prio < LOG_EMERG()) {
        $prio = LOG_EMERG();
    }
    return $LOG_PRIO_TO_STR{$prio};
}

1;

__END__

=head1 NAME

M6::ARPSponge::Log - log buffer and notification for M6::ARPSponge

=head1 SYNOPSIS

 use M6::ARPSponge::Log qw( :all );

 init_log( $ident ); # Default to $FindBin::Script;

 # Add clients to be notified of log messages.
 add_notify( $fh_1 );
 add_notify( $fh_2 );

 # Log at default prio (LOG_NOTICE)
 log_print('going to read %s', $filename);

 # Log an error (LOG_ERR)
 log_err('cannot read %s: %s', $filename, $!);

 log_info('INFO: entering phase %d', $phase);
    # Default log threshold is LOG_NOTICE, so won't do anything.

 # Change the log threshold
 log_threshold(LOG_DEBUG);
 log_info('INFO: entering phase %d', $phase);
    # Log threshold is now LOG_DEBUG, so this will log something.

 say "LOG_DEBUG is ", log_prio_to_string(LOG_DEBUG);
    # -> LOG_DEBUG is 7

 # Print verbose messages to STDOUT.

 log_verbosity(1); # Set verbosity level.

 # print() syntax
 log_verbose(1, "Verbose message for FOO\n");
    # -> Verbose message for FOO

 # printf() syntax
 log_sverbose(1, "Verbose message for %s\n", 'FOO');
    # -> Verbose message for FOO

 log_sverbose(2, "More messages\n");
    # -> (nothing)
    # Module's verbosity level (1) is lower than required (2).

=head1 DESCRIPTION

Provide convenient logging functions for the L<arpsponge>(8)
that send information to F<STDOUT>, L<syslog>(8), and the
L<M6::ARPSponge::Socket::Server>(3p) socket connections.

=head2 Basic Logging

Basic logging is as easy as:

    use M6::ARPSponge::Log;

    init_log('program');
    log_print("A simple message");
    log_debug("A debug message for pid %d", $$);
    log_err("an error message: %s", $!);

    if ($> != 0) {
        log_fatal("must run as root"); # Will die() as well.
    }

    exit 0; # Syslog connection is automatically closed.

=head2 Notifying Clients

In addition to sending log messages to L<syslog>(8), the logging
functions can also print log messages to arbitrary file handles.

To enable this, the file handles need to be registered with
L<add_notify()|/add_notify>.

    init_log();
    add_notify($fh_1);
    add_notify($fh_2);
    log_print("A log message");

The log message above will be sent to I<$fh_1> and I<$fh_2> (provided
the file handles don't currently block), each prefixed with C<LOG|>, so
a client process listening on e.g. the I<$fh_1> socket will receive
C<LOG|A log message\n>.

=head2 Log History Buffer

=head1 LOG PRIORITY MACROS

The symbolic log priority macros can be imported with the C<:macros> or
C<:all> tag, and are as follows:

=over

=item *

B<LOG_EMERG> (0)

=item *

B<LOG_ALERT> (1)

=item *

B<LOG_CRIT> (2)

=item *

B<LOG_ERR> (3)

=item *

B<LOG_WARNING> (4)

=item *

B<LOG_NOTICE> (5)

=item *

B<LOG_INFO> (6)

=item *

B<LOG_DEBUG> (7)

=back

These are symbolic representations of (syslog) logging priorities and
identical to those of L<Sys::Syslog>(3p).

=head1 FUNCTIONS

=head2 Basic Logging

=over

=item B<init_log> ( [ I<Str> ] )

Initialise the logging module. If I<Str> is given, it will act
as the "identifier" string that log messages get prefixed with.
The default is C<$FindBin::Script>.

The function initialises the L<Sys::Syslog> module, the circular
log message buffer, and the notification handles.

=item B<is_valid_log_prio> ( I<ARG> [, B<-err> =E<gt> I<REF>] )
X<is_valid_log_prio>

Check whether I<ARG> represents a valid syslog priority and return
its numerical value, or return I<undef>.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=item B<log_prio_to_string> ( I<PRIO> )
X<log_prio_to_string>

Return the string representation of the numerical I<PRIO>.

=item B<log_threshold> ( [ I<NUM> ] )
X<log_threshold>

Get or set the logging threshold. Default is C<LOG_NOTICE>.
Messages of that priority or higher will get logged. Note that
a I<higher priority> is represented by a I<lower priority number>.
That is, C<LOG_EMERG> is the highest priority, represented by the
number 0, while C<LOG_DEBUG> is the lowest priority, represented by
the number 7.

=item B<pass_log_threshold> ( [ I<NUM> ] )
X<pass_log_threshold>

To get around the confusing logic of priority/numeric ordering, this
boolean function tells whether I<NUM> passes the logging threshold,
i.e., if C<pass_log_threshold(LOG_NOTICE)> is true, then C<log_notice()>
will log a message.

=item B<log_emerg> I<FMT>, I<ARG>, ...
X<log_emerg>

=item B<log_alert> I<FMT>, I<ARG>, ...
X<log_alert>

=item B<log_crit> I<FMT>, I<ARG>, ...
X<log_crit>

=item B<log_err> I<FMT>, I<ARG>, ...
X<log_err>

=item B<log_warning> I<FMT>, I<ARG>, ...
X<log_warning>

=item B<log_notice> I<FMT>, I<ARG>, ...
X<log_notice>

=item B<log_info> I<FMT>, I<ARG>, ...
X<log_info>

=item B<log_debug> I<FMT>, I<ARG>, ...
X<log_debug>

Using C<sprintf()>-like formatting, send log messages
with the given priority. These are fairly simple wrappers
around L<log_print_prio()|/log_print_prio>:

    log_err 'read error: %s', $!;
    log_print_prio LOG_ERR, 'read error: %s', $!;

=item B<log_print_prio> I<PRIO>, I<FMT>, I<ARG>, ...
X<log_print_prio>

The function used by the L<log_print()|/log_print>,
L<log_info()|/log_info>, etc. functions to
do any actual logging and client notification.

=item B<log_print> I<FMT>, I<ARG>, ...
X<log_print>

Log a message at the default priority (I<LOG_NOTICE>).

=item B<log_fatal> I<FMT>, I<ARG>, ...
X<log_fatal>

Log a critical error and call C<die()> with that message.

=back

=head2 Verbosity Functions

The "verbosity" functions can be used to print (timestamped) information
to F<STDOUT> without adding it to any logs. Typical use is by increasing
the L<log_verbosity()|/log_verbosity> for every C<--verbose> CLI option,
and use L<log_verbose()|/log_verbose> and L<log_sverbose()|/log_sverbose>
to print verbose messages to F<STDOUT>.

=over

=item B<log_verbosity> ( [ I<NUM> ] )
X<log_verbosity>

Get or set verbosity level. This affects the operation of
L<log_verbose|/log_verbose> and L<log_sverbose|/log_sverbose>.

=item B<log_verbose> I<LEVEL>, I<ARG>, ...
X<log_verbose>

Print I<ARG>, ... to F<STDOUT> (prefixed with a timestamp) if
the L<log_verbosity|/log_verbosity> is at least I<LEVEL>.

=item B<log_sverbose> I<LEVEL>, I<FMT>, I<ARG>, ...
X<log_sverbose>

Same as L<log_verbose|/log_verbose>, but with a C<printf>-like syntax.

Equivalent to:
    
    log_verbose LEVEL, sprintf( FMT, ARG, ... );

=back

=head2 Client Notifications

Clients (see L<asctl>(1)) connecting over the control socket can receive
log events as well. This is done by adding 
L<M6::ARPSponge::Socket::Server>(3p) handles for client connections
with L<add_notify()|/add_notify>. When the program calls one of the
logging functions above, the message is also sent to all registered
client connections.

=over

=item B<add_notify> ( I<FH> )
X<add_notify>

Add I<FH> to the list of clients to be notified of log messages.
I<FH> should be a valid
L<M6::ARPSponge::Socket::Server>(3p) handle.

=item B<remove_notify> ( I<FH> )
X<remove_notify>

Remove I<FH> from the list of clients to be notified of log messages.
I<FH> should be a valid
L<M6::ARPSponge::Socket::Server>(3p) handle.

=item B<print_notify> I<FMT>, I<ARG>, ...
X<print_notify>

Send a log message to all registered clients, but only if they are
writeable (this means that clients could miss log messages). This is
done by formatting the I<FMT> and I<ARG> arguments using C<sprintf()>,
and calling L<send_log()|M6::ARPSponge::Control::Server/send_log> on
each notify handle.

=back

=head2 Circular Log Buffer

In addition to sending messages to L<syslog>(8) and client sockets, the
logging functions add these messages to a circular history buffer, so
clients can query them.

=over

=item B<log_buffer_size> ( [ I<NUM> ] )
X<log_buffer_size>

Get or set the size of the circular log buffer. If the buffer
size is reduced from its original size, then the buffer will
be immediately truncated to the correct size.

=item B<get_log_buffer>
X<get_log_buffer>

Return an ARRAY reference pointing to the circular log buffer. The log events
are ordered from oldest to most recent.

=item B<clear_log_buffer>
X<clear_log_buffer>

Clear the circular log buffer.

=back

=head2 Miscellaneous

=over

=item B<syslog_facility> ( [ I<FACILITY> ] )
X<syslog_facility>

Get or set the facility for syslog messages. Default is C<user>.
Can be set to a string (C<user>, C<auth>) or a number (8, 32).
If changed from the current value, the L<syslog>(8) connection will
be re-opened.

If the value is changed, the old value is returned.

=item B<syslog_ident> ( [ I<IDENT> ] )
X<syslog_ident>

Get or set the "ident" tag for syslog messages. Default is the
value of L<FindBin::Script|FindBin>.

If changed from the current value, the L<syslog>(8) connection will
be re-opened.

If the value is changed, the old value is returned.

=item B<syslog_options> ( [ I<OPTIONS> ] )
X<syslog_options>

Get or set the syslog options for the syslog connection. Default
value is C<pid>. See also L<Sys::Syslog>(3p) for valid options.

If changed from the current value, the L<syslog>(8) connection will
be re-opened.

If the value is changed, the old value is returned.

=back

=head1 SEE ALSO

L<asctl>(1),
L<arpsponge>(8),
L<FindBin>(3p),
L<M6::ARPSponge>(3p),
L<M6::ARPSponge::Socket::Server>(3p),
L<Sys::Syslog>(3p).

=head1 COPYRIGHT

Copyright 2011, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.
