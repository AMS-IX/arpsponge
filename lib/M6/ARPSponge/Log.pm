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
        log_verbosity log_verbose log_sverbose
        log_threshold pass_log_threshold
        is_valid_log_level log_level_to_string
        add_notify remove_notify print_notify
        get_log_buffer clear_log_buffer log_buffer_size
    );

    our @macros = qw(
        LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR
        LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
    );

    our @vars = qw(
        $FACILITY
        $LOGOPT
        $Debug
        $Verbose
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

our $FACILITY  = 'user';
our $LOGOPT    = 'pid';

#############################################################################
our $Debug          = 0;
our $Verbose        = 0;
our $Syslog_Ident   = $FindBin::Script;

#############################################################################
our $Default_Level  = LOG_NOTICE;

our %STR_TO_LOGLEVEL = (
    'emerg'   => LOG_EMERG,
    'alert'   => LOG_ALERT,
    'crit'    => LOG_CRIT,
    'err'     => LOG_ERR,
    'warning' => LOG_WARNING,
    'notice'  => LOG_NOTICE,
    'info'    => LOG_INFO,
    'debug'   => LOG_DEBUG,
);

our %LOGLEVEL_TO_STR = reverse %STR_TO_LOGLEVEL;

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

sub init_log {
    $Syslog_Ident = shift @_ if @_;
    openlog($Syslog_Ident, $LOGOPT, $FACILITY);
    $Notify = IO::Select->new();
    @Log_Buffer = ();
    return 1;
}

sub log_buffer_size {
    my $r = __log_getset(\$Log_Buffer_Size, @_);

    if ($Log_Buffer_Size < $r) {
        splice @Log_Buffer, 0, -$Log_Buffer_Size;
    }
    return $r;
}

sub log_verbosity  { return __log_getset(\$Verbose, @_) }
sub log_threshold   { return __log_getset(\$Log_Threshold, @_) }
sub pass_log_threshold    { return $_[0] <= $Log_Threshold }

sub get_log_buffer {
    return \@Log_Buffer;
}

sub clear_log_buffer {
    @Log_Buffer = ();
}

sub log_emerg   { print_log_level(LOG_EMERG,    @_) }
sub log_alert   { print_log_level(LOG_ALERT,    @_) }
sub log_crit    { print_log_level(LOG_CRIT,     @_) }
sub log_err     { print_log_level(LOG_ERR,      @_) }
sub log_warning { print_log_level(LOG_WARNING,  @_) }
sub log_notice  { print_log_level(LOG_NOTICE,   @_) }
sub log_info    { print_log_level(LOG_INFO,     @_) }
sub log_debug   { print_log_level(LOG_DEBUG,    @_) }

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
# print_log_level($level, $format, ...);
###############################################################################
sub print_log_level($$@) {
    my ($level, $format, @args) = @_;

    return if $level > $Log_Threshold;

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
        syslog($level, $format, @args);
    }
    print_notify($format, @args);
}

###############################################################################
# print_log($format, ...);
#
#   Log $format, ... to syslog. Syntax is identical to that of printf().
#   Prints to STDOUT if verbose or dummy.
###############################################################################
sub print_log {
    my ($format, @args) = @_;
    print_log_level($Default_Level, $format, @args);
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

sub is_valid_log_level {
    my $arg = shift;
    my $err_s;
    my %opts = (-err => \$err_s, @_);

    if (defined (my $level = $STR_TO_LOGLEVEL{lc $arg}) ) {
        return $level;
    }

    ${$opts{-err}} = q/"$arg" is not a valid syslog level/;
    return;
}

sub log_level_to_string {
    my $level = int(shift);

    if ($level > LOG_DEBUG()) {
        $level = LOG_DEBUG();
    }
    elsif ($level < LOG_EMERG()) {
        $level = LOG_EMERG();
    }
    return $LOGLEVEL_TO_STR{$level};
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

 # Log at default level (LOG_NOTICE)
 print_log('going to read %s', $filename);

 # Log an error (LOG_ERR)
 log_err('cannot read %s: %s', $filename, $!);

 log_info('INFO: entering phase %d', $phase);
    # Default log threshold is LOG_NOTICE, so won't do anything.

 # Change the log threshold
 log_threshold(LOG_DEBUG);
 log_info('INFO: entering phase %d', $phase);
    # Log threshold is now LOG_DEBUG, so this will log something.

 say "LOG_DEBUG is ", log_level_to_string(LOG_DEBUG);
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

=head2 Basic Logging

=head2 Notifying Clients

=head2 Log History Buffer

=head1 LOG LEVEL MACROS

The symbolic log level macros can be imported with the C<:macros> or
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

These are symbolic representations of (syslog) logging levels and identical
to those of L<Sys::Syslog>(3p).

=head1 FUNCTIONS

=head2 Basic Logging

=over

=item B<init_log> ( [ I<Str> ] )

Initialise the logging module. If I<Str> is given, it will act
as the "identifier" string that log messages get prefixed with.
The default is C<$FindBin::Script>.

The function initialises the L<Sys::Syslog> module, the circular
log message buffer, and the notification handles.

=item X<is_valid_log_level>B<is_valid_log_level> ( I<ARG>
[, B<-err> =E<gt> I<REF>] )
X<is_valid_log_level>

Check whether I<ARG> represents a valid syslog level.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=item B<log_level_to_string> ( I<LOGLEVEL> )
X<log_level_to_string>

Return the string representation of the numerical I<LOGLEVEL>.

=item B<log_threshold> ( [ I<NUM> ] )
X<log_threshold>

Get or set the logging threshold. Default is C<LOG_NOTICE>.
Messages of that priority or higher will get logged. Note that
a I<higher priority> is represented by a L<lower level>. That is,
C<LOG_EMERG> is the highest priority, represented by the number 0,
while C<LOG_DEBUG> is the lowest priority, represented by the number 7.

=item B<pass_log_threshold> ( [ I<NUM> ] )
X<pass_log_threshold>

To get around the confusing logic of priority/log level, this
boolean function tells whether I<NUM> passes the logging threshold,
i.e., if C<pass_log_threshold(LOG_NOTICE)> is true, then C<log_notice()>
will log a message.

=item B<log_emerg>
X<log_emerg>

...

=item B<log_alert>
X<log_alert>

...

=item B<log_crit>
X<log_crit>

...

=item B<log_err>
X<log_err>

...

=item B<log_warning>
X<log_warning>

...

=item B<log_notice>
X<log_notice>

...

=item B<log_info>
X<log_info>

...

=item B<log_debug>
X<log_debug>

...

=item B<print_log_level> I<LEVEL>, I<FMT>, I<ARG>, ...
X<print_log_level>

The function used by the L<print_log()|/print_log>,
L<log_info()|/log_info>, etc. functions to check
do any actual logging and client notification.

=item B<print_log>
X<print_log>

...

=item B<log_fatal>
X<log_fatal>

...

=item B<is_valid_log_level>
X<is_valid_log_level>

...

=item B<log_level_to_string>
X<log_level_to_string>

...

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

=over

=item B<add_notify> ( I<FH> )
X<add_notify>

...

=item B<remove_notify> ( I<FH> )
X<remove_notify>

...

=item B<print_notify> I<FMT>, I<ARG>, ...
X<print_notify>

...

=back

=head2 Circular Log Buffer

=over

=item B<log_buffer_size> ( [ I<NUM> ] )
X<log_buffer_size>

Get or set the size of the circular log buffer.

=item B<get_log_buffer>
X<get_log_buffer>

...

=item B<clear_log_buffer>
X<clear_log_buffer>

...

=back

=head1 SEE ALSO

L<FindBin>(3p),
L<M6::ARPSponge>(3p),
L<Sys::Syslog>(3p).

=head1 COPYRIGHT

Copyright 2011, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut

1;
