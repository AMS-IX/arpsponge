###############################################################################
# @(#)$Id$
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
package M6::ARP::Log;

use strict;

use base qw( Exporter );

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
        log_is_verbose log_verbose log_sverbose
        log_level is_log_level
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
our $Syslog_Ident   = $0;

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

my $Log_Level      = LOG_NOTICE;
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
    $Syslog_Ident = @_ ? shift : $0;
    $Syslog_Ident =~ s|.*/||;
    openlog($Syslog_Ident, $LOGOPT, $FACILITY);
    $Notify = IO::Select->new();
    return 1;
}

sub log_buffer_size { return __log_getset(\$Log_Buffer_Size, @_) }
sub log_is_verbose  { return __log_getset(\$Verbose, @_) }
sub log_level       { return __log_getset(\$Log_Level, @_) }
sub is_log_level    { return $_[0] <= $Log_Level }

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
#   to be a M6::ARP::Control::Server reference.
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
#   to be a M6::ARP::Control::Server reference.
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
sub print_log_level {
    my ($level, $format, @args) = @_;

    return if $level > $Log_Level;

    # Add message to circular log buffer.
    foreach (split(/\n/, sprintf($format, @args))) {
        push @Log_Buffer, [ time, $_ ];
        if (int(@Log_Buffer) > $Log_Buffer_Size) {
            shift @Log_Buffer;
        }
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

    if (log_is_verbose >= $level) {
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
    if (log_is_verbose >= $level) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time)),
                     sprintf($fmt, @args);
    }
}

=item X<is_valid_log_level>B<is_valid_log_level> ( I<ARG>
[, B<-err> =E<gt> I<REF>]
)

Check whether I<ARG> represents a valid syslog level.

If an error occurs, and C<-err> is specified, the scalar behind I<REF> will
contain a diagnostic.

=cut

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

=item X<log_level_to_string>B<log_level_to_string> ( I<LOGLEVEL> )

Return the string representation of the numerical I<LOGLEVEL>.

=cut

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

=head1 COPYRIGHT

Copyright 2011, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut

1;
