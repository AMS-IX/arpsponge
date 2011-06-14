###############################################################################
# @(#)$Id$
###############################################################################
#
# Logging for the ARP Sponge.
#
# (c) Copyright AMS-IX B.V. 2004-2011;
#
# See the LICENSE file that came with this package.
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
        log_emerg
        log_alert
        log_crit
        log_err
        log_warning
        log_notice
        log_info
        log_fatal
        log_is_verbose verbose sverbose
        add_notify remove_notify print_notify
    );

    our @macros = qw(
        LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR
        LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
    );

    our @vars = qw(
        $FACILITY
        $LOGOPT
        $Min_Level
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

our $Min_Level      = LOG_NOTICE;
our $Default_Level  = LOG_NOTICE;
our $Debug          = 0;
our $Verbose        = 0;
our $Syslog_Ident   = $0;

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

my @Log_Buffer      = ();
my $Log_Buffer_Size = 100;
my $Notify;

END {
    closelog;
}

sub init_log {
    $Syslog_Ident = @_ ? shift : $0;
    $Syslog_Ident =~ s|.*/||;
    openlog($Syslog_Ident, $LOGOPT, $FACILITY);
    $Notify = IO::Select->new();
    return 1;
}

sub log_buffer_size {
    if (@_) {
        my $old = $Log_Buffer_Size;
        $Log_Buffer_Size = int(shift);
        return $old;
    }
    return $Log_Buffer_Size;
}

sub get_log_buffer {
    my $num = @_ ? shift : int @Log_Buffer;
    return @Log_Buffer[0..$num-1];
}

sub log_is_verbose { 
    if (@_) {
        my $old = $Verbose;
        $Verbose = int(shift);
        return $old;
    }
    return $Verbose;
}

sub log_emerg($@)   { print_log_level(LOG_EMERG,    @_) }
sub log_alert($@)   { print_log_level(LOG_ALERT,    @_) }
sub log_crit($@)    { print_log_level(LOG_CRIT,     @_) }
sub log_err($@)     { print_log_level(LOG_ERR,      @_) }
sub log_warning($@) { print_log_level(LOG_WARNING,  @_) }
sub log_notice($@)  { print_log_level(LOG_NOTICE,   @_) }
sub log_info($@)    { print_log_level(LOG_INFO,     @_) }
sub log_debug($@)   { print_log_level(LOG_DEBUG,    @_) }

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
sub print_log_level($$@) {
    my ($level, $format, @args) = @_;

    return if $level < $Min_Level;

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
sub print_log($@) {
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
sub log_fatal($;@) {
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
# verbose($level, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#
###############################################################################
sub verbose($$@) {
    my ($level, @args)  = @_;

    if (log_is_verbose >= $level) {
        print STDOUT strftime("%Y-%m-%d %H:%M:%S ", localtime(time)), @args;
    }
}

###############################################################################
# sverbose($level, $fmt, $arg, ...);
#
#   Print the arguments to STDOUT if verbosity is at least $level.
#   Functions like sprintf();
#
###############################################################################
sub sverbose($$@) {
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

1;
